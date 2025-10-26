<?php

namespace Drupal\bot_guard\EventSubscriber;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Response;
use Drupal\Component\Utility\Crypt;

/**
 * Event subscriber to check and block requests.
 */
class BotGuardSubscriber implements EventSubscriberInterface {

  protected $configFactory;

  protected $currentUser;

  /**
   * The module handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * The cache backend.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cacheBackend;

  /**
   * The time service.
   *
   * @var \Drupal\Component\Datetime\TimeInterface
   */
  protected $time;

  // Cache decision states
  private const ALLOW = 1;

  private const BLOCK = -1;

  private const CHALLENGE_PENDING = 2;

  /**
   * Constructs a BotGuardSubscriber object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory service.
   * @param \Drupal\Core\Session\AccountProxyInterface $current_user
   *   The current user service.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler service.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache_backend
   *   The cache backend.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    AccountProxyInterface $current_user,
    ModuleHandlerInterface $module_handler,
    CacheBackendInterface $cache_backend,
    TimeInterface $time
  ) {
    $this->configFactory = $config_factory;
    $this->currentUser = $current_user;
    $this->moduleHandler = $module_handler;
    $this->cacheBackend = $cache_backend;
    $this->time = $time;
  }

  public static function getSubscribedEvents(): array {
    // Very early.
    return [
      KernelEvents::REQUEST => ['onRequest', 999],
    ];
  }

  public function onRequest(RequestEvent $event): void {
    // Only act on the main request (Drupal 9/10 => isMainRequest()).
    if (!$event->isMainRequest()) {
      return;
    }

    if ($this->currentUser->hasPermission('bypass bot guard')) {
      return;
    }

    // Retrieve module settings.
    $config = $this->configFactory->get('bot_guard.settings');

    if (!$config->get('enabled')) {
      return;
    }

    $request = $event->getRequest();
    $ua = $request->headers->get('User-Agent', '');
    $al = $request->headers->get('Accept-Language', '');
    $path = $request->getPathInfo();
    $ip = $request->getClientIp() ?? '0.0.0.0';
    $method = $request->getMethod();

    // ---- Decision cache (APCu) --------------------------------------------
    $decision = NULL;
    $cacheEnabled = (bool) $config->get('cache_enabled');
    $cacheTtl = (int) ($config->get('cache_ttl') ?? 300);
    $cacheKey = $this->cacheKey($ip, $ua, $path);

    if ($cacheEnabled && function_exists('apcu_fetch')) {
      $decision = apcu_fetch($cacheKey);
      if (is_int($decision)) {
        if ($decision === self::ALLOW) {
          // Count cached allowed requests
          if ($this->usePersistentCache()) {
            $cached = $this->cacheBackend->get('bg.allowed.count');
            $count = $cached ? $cached->data : 0;
            $this->cacheBackend->set('bg.allowed.count', $count + 1);
          }
          elseif (function_exists('apcu_fetch')) {
            $allowed = apcu_fetch('bg.allowed.count');
            apcu_store('bg.allowed.count', ($allowed === FALSE ? 1 : ((int) $allowed) + 1), 0);
          }
          return;
        }
        if ($decision === self::BLOCK) {
          $this->deny($event, $config, $ip, $ua, $path, 'cached-block');
          return;
        }
        if ($decision === self::CHALLENGE_PENDING) {
          // fall-through to verify cookie again (cheap)
        }
      }
    }

    // ---- Initialize metrics start time (once) -----------------------------
    if ($this->isCacheAvailable()) {
      if ($this->usePersistentCache()) {
        if (!$this->cacheBackend->get('bg.metrics.start')) {
          $this->cacheBackend->set('bg.metrics.start', $this->time->getRequestTime());
        }
      }
      elseif (function_exists('apcu_store') && !apcu_exists('bg.metrics.start')) {
        apcu_store('bg.metrics.start', time(), 0);
      }
    }

    // ---- Allow-list quick path --------------------------------------------
    if ($this->matchesAny($ua, (string) $config->get('allow_bots'))) {
      // Metrics: allowed counter
      if ($this->usePersistentCache()) {
        $cached = $this->cacheBackend->get('bg.allowed.count');
        $count = $cached ? $cached->data : 0;
        $this->cacheBackend->set('bg.allowed.count', $count + 1);
      }
      elseif (function_exists('apcu_fetch')) {
        $allowed = apcu_fetch('bg.allowed.count');
        apcu_store('bg.allowed.count', ($allowed === FALSE ? 1 : ((int) $allowed) + 1), 0);
      }

      $this->storeDecision($cacheEnabled, $cacheKey, self::ALLOW, $cacheTtl);
      return;
    }

    // ---- Block-list UA patterns -------------------------------------------
    if ($ua !== '' && $this->matchesAny($ua, (string) $config->get('block_bots'))) {
      $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
      $this->deny($event, $config, $ip, $ua, $path, 'ua-block');
      return;
    }

    // ---- Heuristics: empty/short UA, missing Accept-Language --------------
    if ($ua === '' || strlen($ua) < 10) {
      $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
      $this->deny($event, $config, $ip, $ua, $path, 'ua-short');
      return;
    }
    if ($request->headers->get('Accept-Language') === NULL || $request->headers->get('Accept-Language') === '') {
      $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
      $this->deny($event, $config, $ip, $ua, $path, 'no-accept-language');
      return;
    }

    // ---- Facet Bot Blocking (independent of language) -----------------------
    // Only apply facet protection if the facets module is installed.
    if ($this->moduleHandler->moduleExists('facets')) {
      $facetEnabled = (bool) ($config->get('facet_enabled') ?? TRUE);
      if ($facetEnabled && isset($_GET['f']) && is_array($_GET['f'])) {
        $limit = (int) ($config->get('facet_limit') ?? 2);

        // Metrics (allowed/blocked + start time) using default cache bin.
        $cache = \Drupal::cache();
        if (!$cache->get('facet_bot.metrics_start')) {
          $cache->set('facet_bot.metrics_start', time());
        }

        if (count($_GET['f']) > $limit) {
          // Count blocked.
          $blocked = $cache->get('facet_bot.blocked');
          $blocked_count = $blocked ? (int) $blocked->data : 0;
          $cache->set('facet_bot.blocked', $blocked_count + 1);

          // Save last blocked info.
          $cache->set('facet_bot.last', [
            'ip' => $ip,
            'path' => $request->getUri(),
            'ua' => $ua,
            'params' => $_GET['f'],
          ]);

          // Use centralized error response configuration.
          $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
          $this->deny($event, $config, $ip, $ua, $path, 'facet-limit');
          return;
        }
        else {
          // Count allowed when f[] present and within limit.
          $allowed = $cache->get('facet_bot.allowed');
          $allowed_count = $allowed ? (int) $allowed->data : 0;
          $cache->set('facet_bot.allowed', $allowed_count + 1);
        }

        // ---- Facet Flood Pattern Detection (APCu-based, very cheap) -----------
        $facetFloodEnabled = (bool) ($config->get('facet_flood_enabled') ?? TRUE);
        $facetThreshold = (int) ($config->get('facet_flood_threshold') ?? 20);
        $facetWindow    = (int) ($config->get('facet_flood_window') ?? 600);
        $facetBan       = (int) ($config->get('facet_flood_ban') ?? 1800);

        if ($facetFloodEnabled && $facetThreshold > 0 && $facetWindow > 0 && function_exists('apcu_fetch')) {
          // If already banned, deny immediately.
          $banKey = 'bg_ffp_ban_' . sha1($ip);
          if (apcu_exists($banKey)) {
            $this->deny($event, $config, $ip, $ua, $path, 'facet-flood-ban');
            return;
          }

          // Compute fingerprint for current facet combination.
          $sig = $this->facetFingerprint($_GET['f']);

          // Load or initialize rolling window for this IP.
          $key = 'bg_ffp_' . sha1($ip);
          $now = time();
          $data = apcu_fetch($key);
          if (!is_array($data) || !isset($data['first_ts']) || ($now - (int) $data['first_ts']) > $facetWindow) {
            $data = [
              'unique'   => [$sig => TRUE],
              'count'    => 1,
              'first_ts' => $now,
            ];
          }
          else {
            if (empty($data['unique'][$sig])) {
              $data['unique'][$sig] = TRUE;
              $data['count'] = (int) ($data['count'] ?? 0) + 1;
            }
          }
          apcu_store($key, $data, $facetWindow);

          if ((int) $data['count'] > $facetThreshold) {
            // Put IP on temporary ban list.
            apcu_store($banKey, 1, $facetBan);

            // Use centralized error response configuration.
            $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
            $this->deny($event, $config, $ip, $ua, $path, 'facet-flood-ban');
            return;
          }
        }
      }
    }

    // ---- Rate limit (APCu only; skip if not available) --------------------
    $max = (int) ($config->get('rate_limit') ?? 20);
    $win = (int) ($config->get('rate_window') ?? 10);
    if ($max > 0 && function_exists('apcu_fetch')) {
      if (!$this->rateCheck($ip, $max, $win)) {
        // 429 not cached (small window anyway)
        $this->deny429($event, $config, $ip, $ua, $path, 'ratelimit');
      }
    }

    // ---- Cookie challenge --------------------------------------------------
    $challengeEnabled = (bool) ($config->get('challenge_enabled') ?? TRUE);
    if ($challengeEnabled) {
      // Only challenge for GET/HEAD; let POST/PUT be blocked (404) if not allowed bot.
      if (in_array($method, ['GET', 'HEAD'], TRUE)) {
        $cookieName = (string) ($config->get('cookie_name') ?? 'bg_chal');
        $cookieTtl = (int) ($config->get('cookie_ttl') ?? 86400);

        if (!$this->hasValidChallengeCookie($request->cookies->get($cookieName), $ip, $ua)) {
          $this->storeDecision($cacheEnabled, $cacheKey, self::CHALLENGE_PENDING, $cacheTtl);
          $this->serveChallenge($event, $cookieName, $cookieTtl, $ip, $ua);
          return;
        }
      }
      else {
        // Non-GET without valid challenge → deny 404 (cheap protection)
        $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
        $this->deny($event, $config, $ip, $ua, $path, 'method-block');
        return;
      }
    }

    // Passed all checks - count as allowed request
    if ($this->usePersistentCache()) {
      $cached = $this->cacheBackend->get('bg.allowed.count');
      $count = $cached ? $cached->data : 0;
      $this->cacheBackend->set('bg.allowed.count', $count + 1);
    }
    elseif (function_exists('apcu_fetch')) {
      $allowed = apcu_fetch('bg.allowed.count');
      apcu_store('bg.allowed.count', ($allowed === FALSE ? 1 : ((int) $allowed) + 1), 0);
    }
    
    $this->storeDecision($cacheEnabled, $cacheKey, self::ALLOW, $cacheTtl);
  }

  private function cacheKey(string $ip, string $ua, string $path): string {
    // Path bucket to avoid huge key cardinality (first segment only)
    $seg = explode('/', trim($path, '/'))[0] ?? '';
    return 'bg:' . sha1($ip . "\n" . $ua . "\n" . $seg);
  }

  private function storeDecision(bool $enabled, string $key, int $value, int $ttl): void {
    if ($enabled && function_exists('apcu_store')) {
      apcu_store($key, $value, $ttl);
    }
  }

  private function matchesAny(string $subject, string $patterns): bool {
    foreach (preg_split('/\R+/', $patterns) as $p) {
      $p = trim($p);
      if ($p !== '' && @preg_match("~$p~i", '') !== FALSE && preg_match("~$p~i", $subject)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  private function deny(RequestEvent $event, $config, string $ip, string $ua, string $path, string $reason): void {
    $this->log($config, $ip, $ua, $path, $reason);

    // Use centralized error response configuration.
    $statusCode = (int) ($config->get('block_status_code') ?? 404);
    $message = (string) ($config->get('block_message') ?? '<h1>Access Denied</h1><p>Your request was blocked.</p>');

    $event->setResponse(new Response($message, $statusCode, [
      'Content-Type' => 'text/html; charset=utf-8',
    ]));
    $event->stopPropagation();
  }

  private function deny429(RequestEvent $event, $config, string $ip, string $ua, string $path, string $reason): void {
    $this->log($config, $ip, $ua, $path, $reason);

    // Use centralized rate limit error response configuration.
    $statusCode = (int) ($config->get('ratelimit_status_code') ?? 429);
    $message = (string) ($config->get('ratelimit_message') ?? '<h1>Too Many Requests</h1><p>Please slow down.</p>');
    $retryAfter = (int) ($config->get('ratelimit_retry_after') ?? 30);

    $event->setResponse(new Response($message, $statusCode, [
      'Content-Type' => 'text/html; charset=utf-8',
      'Retry-After' => (string) $retryAfter,
    ]));
    $event->stopPropagation();
  }

  private function log($config, string $ip, string $ua, string $path, string $reason): void {
    if (!$this->isCacheAvailable()) {
      return;
    }

    if ($this->usePersistentCache()) {
      // Use Drupal cache backend (Memcache/Redis)
      if (!$this->cacheBackend->get('bg.metrics.start')) {
        $this->cacheBackend->set('bg.metrics.start', $this->time->getRequestTime());
      }

      // Global blocked counter
      $blocked_cache = $this->cacheBackend->get('bg.blocked.count');
      $blocked = $blocked_cache ? $blocked_cache->data : 0;
      $this->cacheBackend->set('bg.blocked.count', $blocked + 1);

      // Count by reason
      $reasonKey = 'bg.reason.' . $reason;
      $reason_cache = $this->cacheBackend->get($reasonKey);
      $reasonCount = $reason_cache ? $reason_cache->data : 0;
      $this->cacheBackend->set($reasonKey, $reasonCount + 1);

      // Track last block
      $this->cacheBackend->set('bg.blocked.last', [
        'time' => $this->time->getRequestTime(),
        'ip' => $ip,
        'ua' => $ua,
        'path' => $path,
        'reason' => $reason,
      ]);

      // Keep small rolling history (last 20 blocks)
      $hist_cache = $this->cacheBackend->get('bg.history');
      $hist = $hist_cache ? $hist_cache->data : [];
      array_unshift($hist, [
        'time' => $this->time->getRequestTime(),
        'ip' => $ip,
        'path' => $path,
        'ua' => $ua,
        'reason' => $reason,
      ]);
      $hist = array_slice($hist, 0, 20);
      $this->cacheBackend->set('bg.history', $hist);
    }
    elseif (function_exists('apcu_fetch')) {
      // APCu fallback
      if (!apcu_exists('bg.metrics.start')) {
        apcu_store('bg.metrics.start', time(), 0);
      }

      $blocked = apcu_fetch('bg.blocked.count');
      apcu_store('bg.blocked.count', ($blocked === FALSE ? 1 : ((int) $blocked) + 1), 0);

      $reasonKey = 'bg.reason.' . $reason;
      $reasonCount = apcu_fetch($reasonKey);
      apcu_store($reasonKey, ($reasonCount === FALSE ? 1 : ((int) $reasonCount) + 1), 0);

      apcu_store('bg.blocked.last', [
        'time' => time(),
        'ip' => $ip,
        'ua' => $ua,
        'path' => $path,
        'reason' => $reason,
      ]);

      $hist = apcu_fetch('bg.history') ?: [];
      array_unshift($hist, [
        'time' => time(),
        'ip' => $ip,
        'path' => $path,
        'ua' => $ua,
        'reason' => $reason,
      ]);
      $hist = array_slice($hist, 0, 20);
      apcu_store('bg.history', $hist);
    }
  }

  // ---- APCu rate limiter (cheap) ------------------------------------------
  private function rateCheck(string $ip, int $max, int $window): bool {
    $now = time();
    $key = 'bg_rl_' . sha1($ip);
    $data = apcu_fetch($key);
    if (!is_array($data) || $now - $data['t'] > $window) {
      $data = ['t' => $now, 'c' => 0];
    }
    $data['c']++;
    apcu_store($key, $data, $window);
    return $data['c'] <= $max;
  }

  // ---- Cookie challenge: stateless signed cookie --------------------------
  private function serveChallenge(RequestEvent $event, string $cookieName, int $ttl, string $ip, string $ua): void {
    // Metrics
    if ($this->usePersistentCache()) {
      $cached = $this->cacheBackend->get('bg.challenge.count');
      $count = $cached ? $cached->data : 0;
      $this->cacheBackend->set('bg.challenge.count', $count + 1);
    }
    elseif (function_exists('apcu_fetch')) {
      $c = apcu_fetch('bg.challenge.count');
      apcu_store('bg.challenge.count', ($c === FALSE ? 1 : ((int) $c) + 1), 0);
    }

    $exp = time() + $ttl;
    $sig = $this->sign($ip, $ua, $exp);
    $val = $exp . ':' . $sig;

    // Minimal HTML/JS (no assets, ~0.8 KB). Also meta refresh for no-JS.
    $html = '<!doctype html><html><head><meta charset="utf-8">' .
      '<meta http-equiv="refresh" content="1">' .
      '<title>Verifying…</title></head><body>' .
      '<noscript>JavaScript required.</noscript>' .
      '<script>(function(){try{' .
      'var d=new Date(' . ($exp * 1000) . ');' .
      'document.cookie=' . json_encode($cookieName) . '+\'=' . $val . ';path=/;expires=\'+d.toUTCString()+' .
      '\';SameSite=Lax\';location.reload();}catch(e){}})();</script>' .
      '</body></html>';

    $response = new Response($html, 200, [
      'Content-Type' => 'text/html; charset=utf-8',
      // Also set cookie via header for first-party contexts:
      'Set-Cookie' => $cookieName . '=' . $val . '; Path=/; Expires=' . gmdate('D, d M Y H:i:s', $exp) . ' GMT; SameSite=Lax',
      'Cache-Control' => 'no-cache, no-store, must-revalidate',
      'Pragma' => 'no-cache',
    ]);

    $event->setResponse($response);
  }

  private function hasValidChallengeCookie(?string $cookie, string $ip, string $ua): bool {
    if (!$cookie || strpos($cookie, ':') === FALSE) {
      return FALSE;
    }
    [$exp, $sig] = explode(':', $cookie, 2);
    if (!ctype_digit($exp)) {
      return FALSE;
    }
    if ((int) $exp < time()) {
      return FALSE;
    }
    // Constant-time compare
    $expected = $this->sign($ip, $ua, (int) $exp);
    return hash_equals($expected, $sig);
  }

  private function sign(string $ip, string $ua, int $exp): string {
    // Use Drupal hash salt; fallback to Crypt::randomBytesBase64()
    $salt = (string) \Drupal::service('settings')->get('hash_salt');
    if ($salt === '') {
      $salt = Crypt::randomBytesBase64();
    }
    return base64_encode(hash_hmac('sha256', $ip . "\n" . $ua . "\n" . $exp, $salt, TRUE));
  }

  /**
   * Create an order-independent fingerprint of facet parameters.
   *
   * @param array $facets
   *   The $_GET['f'] array.
   *
   * @return string
   *   A stable hash representing the combination of facet keys and values.
   */
  private function facetFingerprint(array $facets): string {
    $keys = array_keys($facets);
    sort($keys);

    $values = [];
    foreach ($facets as $k => $v) {
      if (is_array($v)) {
        $vv = $v;
        sort($vv);
        $values[$k] = $vv;
      }
      else {
        $values[$k] = (string) $v;
      }
    }

    return sha1(json_encode([$keys, $values]));
  }

  /**
   * Check if cache is available (Memcache/Redis or APCu fallback).
   *
   * @return bool
   *   TRUE if cache is available.
   */
  private function isCacheAvailable(): bool {
    return (
      $this->moduleHandler->moduleExists('memcache') ||
      $this->moduleHandler->moduleExists('redis') ||
      function_exists('apcu_fetch')
    );
  }

  /**
   * Get cache backend name for debugging.
   *
   * @return string
   *   The cache backend name.
   */
  private function getCacheBackendName(): string {
    if ($this->moduleHandler->moduleExists('memcache')) {
      return 'Memcache';
    }
    if ($this->moduleHandler->moduleExists('redis')) {
      return 'Redis';
    }
    if (function_exists('apcu_fetch')) {
      return 'APCu (fallback)';
    }
    return 'None';
  }

  /**
   * Check if we should use persistent cache (Memcache/Redis).
   *
   * @return bool
   *   TRUE if persistent cache is available.
   */
  private function usePersistentCache(): bool {
    return (
      $this->moduleHandler->moduleExists('memcache') ||
      $this->moduleHandler->moduleExists('redis')
    );
  }
}

