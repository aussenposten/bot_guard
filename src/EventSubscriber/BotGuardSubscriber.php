<?php

namespace Drupal\bot_guard\EventSubscriber;

use Drupal\bot_guard\Service\BotGuardMetricsService;
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

  /**
   * The config factory service.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The current user service.
   *
   * @var \Drupal\Core\Session\AccountProxyInterface
   */
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

  /**
   * The metrics service.
   *
   * @var \Drupal\bot_guard\Service\BotGuardMetricsService
   */
  protected $metricsService;

  /**
   * The screen resolution from the client.
   *
   * @var string
   */
  protected $screenResolution = '';

  /**
   * Cache decision state: Allow the request.
   *
   * @var int
   */
  private const ALLOW = 1;

  /**
   * Cache decision state: Block the request.
   *
   * @var int
   */
  private const BLOCK = -1;

  /**
   * Cache decision state: A challenge is pending verification.
   *
   * @var int
   */
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
   * @param \Drupal\bot_guard\Service\BotGuardMetricsService $metrics_service
   *   The metrics service.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    AccountProxyInterface $current_user,
    ModuleHandlerInterface $module_handler,
    CacheBackendInterface $cache_backend,
    TimeInterface $time,
    BotGuardMetricsService $metrics_service
  ) {
    $this->configFactory = $config_factory;
    $this->currentUser = $current_user;
    $this->moduleHandler = $module_handler;
    $this->cacheBackend = $cache_backend;
    $this->time = $time;
    $this->metricsService = $metrics_service;
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    // Very early.
    return [
      KernelEvents::REQUEST => ['onRequest', 299],
    ];
  }

  /**
   * Main request handler to check and block bots.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The request event.
   */
  public function onRequest(RequestEvent $event): void {
    // Only act on the main request (Drupal 9/10 => isMainRequest()).
    if (!$event->isMainRequest()) {
      return;
    }

    // Initialize metrics early, regardless of subsequent checks.
    // This ensures the start time is set even if the request is bypassed.
    $this->metricsService->ensureMetricsInitialized();

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
    $path = $request->getPathInfo();
    $ip = $this->getTrustedClientIp($request, $config);
    $method = $request->getMethod();

    // IP Allow-list (bypass all checks).
    $allowIps = (string) $config->get('allow_ips');
    if ($allowIps && $this->ipInAllowlist($ip, $allowIps)) {
      return;
    }

    // Path Allow-list (bypass all checks).
    $allowPaths = (string) $config->get('allow_paths');
    if ($allowPaths && $this->matchesAny($path, $allowPaths)) {
      return;
    }

    // Decision cache.
    $cacheEnabled = (bool) $config->get('cache_enabled');
    $cacheTtl = (int) ($config->get('cache_ttl') ?? 300);
    $cacheKey = $this->cacheKey($ip, $ua, $path);

    if ($cacheEnabled && function_exists('apcu_fetch')) {
      $decision = apcu_fetch($cacheKey);
      if (is_int($decision)) {
        if ($decision === self::ALLOW) {
          // Count cached allowed requests.
          $this->incrementAllowedCounter();
          return;
        }
        if ($decision === self::BLOCK) {
          $this->deny($event, $config, $ip, $ua, $path, 'cached-block');
          return;
        }
      }
    }

    // Allow-list quick path.
    if ($this->matchesAny($ua, (string) $config->get('allow_bots'))) {
      $this->incrementAllowedCounter();
      $this->storeDecision($cacheEnabled, $cacheKey, self::ALLOW, $cacheTtl);
      return;
    }

    // Heuristics: empty/short UA, missing Accept-Language.
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

    // Block-list UA patterns.
    if ($this->matchesAny($ua, (string) $config->get('block_bots'))) {
      $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
      $this->deny($event, $config, $ip, $ua, $path, 'ua-block');
      return;
    }

    // Rate limit.
    $max = (int) ($config->get('rate_limit') ?? 20);
    $win = (int) ($config->get('rate_window') ?? 10);
    if ($max > 0 && function_exists('apcu_fetch')) {
      if (!$this->rateCheck($ip, $max, $win)) {
        // 429 not cached (small window anyway)
        $this->deny429($event, $config, $ip, $ua, $path, 'ratelimit');
      }
    }

    // Cookie challenge.
    $challengeEnabled = (bool) ($config->get('challenge_enabled') ?? TRUE);
    $cookieName = (string) ($config->get('cookie_name') ?? 'bg_chal');
    $cookieTtl = (int) ($config->get('cookie_ttl') ?? 86400);
    $hasValidChallengeCookie = FALSE;

    if ($challengeEnabled) {
      // If no valid challenge cookie is present, take action.
      if (!$this->hasValidChallengeCookie($request->cookies->get($cookieName), $ip, $ua)) {
        // For GET/HEAD requests, serve the JS challenge to the browser.
        if (in_array($method, ['GET', 'HEAD'], TRUE)) {
          $this->storeDecision($cacheEnabled, $cacheKey, self::CHALLENGE_PENDING, $cacheTtl);
          $this->serveChallenge($event, $cookieName, $cookieTtl, $ip, $ua);
        }
        // For other methods like POST, block if no valid cookie is present.
        else {
          $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
          $this->deny($event, $config, $ip, $ua, $path, 'method-block');
        }
        return;
      }
      // If a valid cookie exists, the request proceeds.
      $hasValidChallengeCookie = TRUE;
    }

    // Suspicious screen resolution.
    // Only check if a valid challenge cookie exists (which contains screen resolution).
    // The resolution is automatically extracted from the cookie in hasValidChallengeCookie().
    $resolutionCheckEnabled = (bool) ($config->get('resolution_check_enabled') ?? TRUE);
    if ($hasValidChallengeCookie && $resolutionCheckEnabled && !empty($this->screenResolution)) {
      if ($this->isSuspiciousScreenResolution($ua, $this->screenResolution)) {
        $this->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
        $this->deny($event, $config, $ip, $ua, $path, 'suspicious-resolution', [
          'screen_resolution' => $this->screenResolution,
        ]);
        return;
      }
    }

    // Facet Bot Blocking.
    if ($this->moduleHandler->moduleExists('facets')) {
      $facetEnabled = (bool) ($config->get('facet_enabled') ?? TRUE);
      $facet_params = $this->getFacetParams($request);

      if ($facetEnabled && !empty($facet_params)) {
        $limit = (int) ($config->get('facet_limit') ?? 2);

        // Metrics (allowed/blocked + start time) using default cache bin.
        $cache = $this->cacheBackend;
        if (!$cache->get('facet_bot.metrics_start')) {
          $cache->set('facet_bot.metrics_start', time());
        }

        if (count($facet_params) > $limit) {
          // Count blocked.
          $blocked = $cache->get('facet_bot.blocked');
          $blocked_count = $blocked ? (int) $blocked->data : 0;
          $cache->set('facet_bot.blocked', $blocked_count + 1);

          // Save last blocked info.
          $cache->set('facet_bot.last', [
            'ip' => $ip,
            'path' => $request->getUri(),
            'ua' => $ua,
            'params' => $facet_params,
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

        // Facet Flood Pattern Detection.
        $facetFloodEnabled = (bool) ($config->get('facet_flood_enabled') ?? TRUE);
        $facetThreshold = (int) ($config->get('facet_flood_threshold') ?? 20);
        $facetWindow = (int) ($config->get('facet_flood_window') ?? 600);
        $facetBan = (int) ($config->get('facet_flood_ban') ?? 1800);

        if ($facetFloodEnabled && $facetThreshold > 0 && $facetWindow > 0 && function_exists('apcu_fetch')) {
          // If already banned, deny immediately.
          $banKey = 'bg_ffp_ban_' . sha1($ip);
          if (apcu_exists($banKey)) {
            $this->deny($event, $config, $ip, $ua, $path, 'facet-flood-ban');
            return;
          }

          // Compute fingerprint for current facet combination.
          $sig = $this->facetFingerprint($facet_params);

          // Load or initialize rolling window for this IP.
          $key = 'bg_ffp_' . sha1($ip);
          $now = time();
          $data = apcu_fetch($key);
          if (!is_array($data) || !isset($data['first_ts']) || ($now - (int) $data['first_ts']) > $facetWindow) {
            $data = [
              'unique' => [$sig => TRUE],
              'count' => 1,
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

    // Passed all checks - count as allowed request.
    $this->incrementAllowedCounter();
    $this->storeDecision($cacheEnabled, $cacheKey, self::ALLOW, $cacheTtl);
  }

  /**
   * Generate a cache key for a decision.
   *
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   * @param string $path
   *   The request path.
   *
   * @return string
   *   A hashed cache key.
   */
  private function cacheKey(string $ip, string $ua, string $path): string {
    // Path bucket to avoid huge key cardinality (first segment only)
    $seg = explode('/', trim($path, '/'))[0] ?? '';
    return 'bg:' . sha1($ip . "\n" . $ua . "\n" . $seg);
  }

  /**
   * Store a decision in the APCu cache.
   *
   * @param bool $enabled
   *   Whether caching is enabled.
   * @param string $key
   *   The cache key.
   * @param int $value
   *   The decision value to store (ALLOW, BLOCK, etc.).
   * @param int $ttl
   *   The cache lifetime in seconds.
   */
  private function storeDecision(bool $enabled, string $key, int $value, int $ttl): void {
    if ($enabled && function_exists('apcu_store')) {
      apcu_store($key, $value, $ttl);
    }
  }

  /**
   * Check if a string matches any regex pattern from a newline-separated list.
   *
   * @param string $subject
   *   The string to check.
   * @param string $patterns
   *   A newline-separated string of regex patterns.
   *
   * @return bool
   *   TRUE if any pattern matches, FALSE otherwise.
   */
  private function matchesAny(string $subject, string $patterns): bool {
    foreach (preg_split('/\R+/', $patterns) as $p) {
      $p = trim($p);
      if ($p !== '' && @preg_match("~$p~i", '') !== FALSE && preg_match("~$p~i", $subject)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Deny a request with a standard block response.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The request event.
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The module configuration.
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   * @param string $path
   *   The request path.
   * @param string $reason
   *   The reason for blocking the request.
   * @param array $details
   *   Optional additional details for logging.
   */
  private function deny(RequestEvent $event, $config, string $ip, string $ua, string $path, string $reason, array $details = []): void {
    $this->log($ip, $ua, $path, $reason, $details);

    // Use centralized error response configuration.
    $statusCode = (int) ($config->get('block_status_code') ?? 404);
    $message = (string) ($config->get('block_message') ?? '<h1>Access Denied</h1><p>Your request was blocked.</p>');

    $event->setResponse(new Response($message, $statusCode, [
      'Content-Type' => 'text/html; charset=utf-8',
    ]));
    $event->stopPropagation();
  }

  /**
   * Deny a request with a 429 Too Many Requests response.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The request event.
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The module configuration.
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   * @param string $path
   *   The request path.
   * @param string $reason
   *   The reason for blocking the request.
   * @param array $details
   *   Optional additional details for logging.
   */
  private function deny429(RequestEvent $event, $config, string $ip, string $ua, string $path, string $reason, array $details = []): void {
    $this->log($ip, $ua, $path, $reason, $details);

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

  /**
   * Log a blocked request to the cache for metrics.
   *
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   * @param string $path
   *   The request path.
   * @param string $reason
   *   The reason for blocking the request.
   * @param array $details
   *   Optional additional details (e.g., screen resolution, facet params).
   */
  private function log(string $ip, string $ua, string $path, string $reason, array $details = []): void {
    if (!$this->isCacheAvailable()) {
      return;
    }

    if ($this->usePersistentCache()) {
      // Use Drupal cache backend (Memcache/Redis)
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
      $this->cacheBackend->set('bg.blocked.last', array_merge([
        'time' => $this->time->getRequestTime(),
        'ip' => $ip,
        'ua' => $ua,
        'path' => $path,
        'reason' => $reason,
      ], $details));

      // Keep small rolling history (last 20 blocks)
      $hist_cache = $this->cacheBackend->get('bg.history');
      $hist = $hist_cache ? $hist_cache->data : [];
      array_unshift($hist, array_merge([
        'time' => $this->time->getRequestTime(),
        'ip' => $ip,
        'path' => $path,
        'ua' => $ua,
        'reason' => $reason,
      ], $details));
      $hist = array_slice($hist, 0, 20);
      $this->cacheBackend->set('bg.history', $hist);
    }
    elseif (function_exists('apcu_fetch')) {
      // APCu fallback.
      $blocked = apcu_fetch('bg.blocked.count');
      apcu_store('bg.blocked.count', ($blocked === FALSE ? 1 : ((int) $blocked) + 1), 0);

      $reasonKey = 'bg.reason.' . $reason;
      $reasonCount = apcu_fetch($reasonKey);
      apcu_store($reasonKey, ($reasonCount === FALSE ? 1 : ((int) $reasonCount) + 1), 0);

      apcu_store('bg.blocked.last', array_merge([
        'time' => time(),
        'ip' => $ip,
        'ua' => $ua,
        'path' => $path,
        'reason' => $reason,
      ], $details));

      $hist = apcu_fetch('bg.history') ?: [];
      array_unshift($hist, array_merge([
        'time' => time(),
        'ip' => $ip,
        'path' => $path,
        'ua' => $ua,
        'reason' => $reason,
      ], $details));
      $hist = array_slice($hist, 0, 20);
      apcu_store('bg.history', $hist);
    }
  }

  /**
   * Perform rate limiting check using APCu.
   *
   * @param string $ip
   *   The client IP address.
   * @param int $max
   *   Maximum number of requests allowed.
   * @param int $window
   *   The time window in seconds.
   *
   * @return bool
   *   TRUE if the request is within the limit, FALSE otherwise.
   */
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

  /**
   * Serve a JavaScript-based cookie challenge.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The request event.
   * @param string $cookieName
   *   The name of the challenge cookie.
   * @param int $ttl
   *   The cookie lifetime in seconds.
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   */
  private function serveChallenge(RequestEvent $event, string $cookieName, int $ttl, string $ip, string $ua): void {
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
    // Generate signature based on IP, UA, and timestamp
    $sig = $this->sign($ip, $ua, $exp);

    // Minimal HTML/JS (no assets, ~0.8 KB). Also meta refresh for no-JS.
    $html = '<!doctype html><html><head><meta charset="utf-8">' .
      '<meta http-equiv="refresh" content="1">' .
      '<title>Verifying…</title></head><body>' .
      '<noscript>JavaScript required.</noscript>' .
      '<script>(function(){try{' .
      'var exp=' . ($exp * 1000) . ';' .
      'var d=new Date(exp);' .
      'var scr=screen.width+"x"+screen.height;' .
      'var payload=btoa(JSON.stringify({ts:exp,scr:scr}));' .
      'var sig=' . json_encode($sig) . ';' .
      'var val=payload+"."+sig;' .
      'document.cookie=' . json_encode($cookieName) . '+"="+val+";path=/;expires="+d.toUTCString()+";SameSite=Lax";' .
      'location.reload();}catch(e){}})();</script>' .
      '</body></html>';

    $response = new Response($html, 200, [
      'Content-Type' => 'text/html; charset=utf-8',
      'Cache-Control' => 'no-cache, no-store, must-revalidate',
      'Pragma' => 'no-cache',
    ]);

    $event->setResponse($response);
  }

  /**
   * Validate the challenge cookie.
   *
   * @param string|null $cookie
   *   The cookie value from the request.
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   *
   * @return bool
   *   TRUE if the cookie is present and valid, FALSE otherwise.
   */
  private function hasValidChallengeCookie(?string $cookie, string $ip, string $ua): bool {
    if (!$cookie) {
      return FALSE;
    }

    // New format: payload.signature (JSON payload with ts + scr)
    if (str_contains($cookie, '.')) {
      $parts = explode('.', $cookie, 2);
      if (count($parts) !== 2) {
        return FALSE;
      }
      [$payload, $sig] = $parts;

      // Decode payload first to get timestamp
      $decoded = base64_decode($payload, TRUE);
      if ($decoded === FALSE) {
        return FALSE;
      }
      $data = json_decode($decoded, TRUE);
      if (!is_array($data) || !isset($data['ts'])) {
        return FALSE;
      }

      // Check expiration (ts is in milliseconds)
      $exp = (int) ($data['ts'] / 1000);
      if ($exp < time()) {
        return FALSE;
      }

      // Verify signature based on IP, UA, and timestamp (not payload)
      $expected = $this->sign($ip, $ua, $exp);
      if (!hash_equals($expected, $sig)) {
        return FALSE;
      }

      // Store screen resolution for later use
      $this->screenResolution = $data['scr'] ?? '';

      return TRUE;
    }

    // Legacy format: exp:signature (for backwards compatibility)
    if (str_contains($cookie, ':')) {
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

    return FALSE;
  }

  /**
   * Generate a signature for the challenge cookie.
   *
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   * @param int $exp
   *   The expiration timestamp.
   *
   * @return string
   *   A base64-encoded HMAC-SHA256 signature.
   */
  private function sign(string $ip, string $ua, int $exp): string {
    $salt = $this->getHashSalt();
    return base64_encode(hash_hmac('sha256', $ip . "\n" . $ua . "\n" . $exp, $salt, TRUE));
  }

  /**
   * Get the hash salt for signing cookies.
   *
   * @return string
   *   The hash salt.
   */
  private function getHashSalt(): string {
    $salt = (string) \Drupal::service('settings')->get('hash_salt');
    if ($salt === '') {
      $salt = Crypt::randomBytesBase64();
    }
    return $salt;
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
   * Get facet parameters from the query string.
   *
   * Detects both `f[...]=...` and `1=...` style parameters.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   *
   * @return array
   *   An array of facet parameters found in the query string.
   */
  private function getFacetParams($request): array {
    $query_params = $request->query->all();
    $facet_params = [];

    // The `f` parameter is the standard way facets are passed.
    if (isset($query_params['f']) && is_array($query_params['f'])) {
      $facet_params = $query_params['f'];
    }

    // Some bots use numeric keys instead of the `f` parameter.
    foreach ($query_params as $key => $value) {
      if (is_numeric($key)) {
        $facet_params[] = $value;
      }
    }

    return $facet_params;
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

  /**
   * Check if IP is in allowlist.
   *
   * @param string $ip
   *   IP address to check.
   * @param string $allowlist
   *   Newline-separated list of IPs/CIDR ranges.
   *
   * @return bool
   *   TRUE if IP is in allowlist.
   */
  private function ipInAllowlist(string $ip, string $allowlist): bool {
    foreach (preg_split('/\R+/', $allowlist) as $entry) {
      $entry = trim($entry);
      if ($entry === '') {
        continue;
      }

      // Check if entry contains CIDR notation.
      if (str_contains($entry, '/')) {
        if ($this->ipInCidr($ip, $entry)) {
          return TRUE;
        }
      }
      // Exact IP match.
      elseif ($ip === $entry) {
        return TRUE;
      }
    }

    return FALSE;
  }

  /**
   * Check if IP is in CIDR range.
   *
   * @param string $ip
   *   IP address to check.
   * @param string $cidr
   *   CIDR notation (e.g., 192.168.0.0/16).
   *
   * @return bool
   *   TRUE if IP is in CIDR range.
   */
  /**
   * Increment the allowed requests counter in the cache.
   */
  private function incrementAllowedCounter(): void {
    if ($this->usePersistentCache()) {
      $cached = $this->cacheBackend->get('bg.allowed.count');
      $count = $cached ? $cached->data : 0;
      $this->cacheBackend->set('bg.allowed.count', $count + 1);
    }
    elseif (function_exists('apcu_fetch')) {
      $allowed = apcu_fetch('bg.allowed.count');
      apcu_store('bg.allowed.count', ($allowed === FALSE ? 1 : ((int) $allowed) + 1), 0);
    }
  }

  /**
   * Check for suspicious screen resolution / user agent combinations.
   *
   * @param string $ua
   *   The client User-Agent string.
   * @param string $resolution
   *   The client screen resolution (e.g., "1920x1080").
   *
   * @return bool
   *   TRUE if the combination is suspicious, FALSE otherwise.
   */
  private function isSuspiciousScreenResolution(string $ua, string $resolution): bool {
    // An empty resolution is highly suspicious, as it indicates that the JS
    // challenge was likely not executed. This is a strong signal for a bot.
    if (empty($resolution) || !str_contains($resolution, 'x')) {
      return TRUE;
    }

    [$width, $height] = explode('x', $resolution, 2);
    $width = (int) $width;
    $height = (int) $height;

    // Invalid or zero resolutions are also a strong indicator of a non-browser client.
    if ($width <= 100 || $height <= 100) {
      return TRUE;
    }

    // Distinguish between device types based on User-Agent.
    $isTablet = preg_match('/(iPad|Tablet|Android(?!.*Mobi))/i', $ua);
    $isPhone = preg_match('/(Mobi|Android.*Mobi|iPhone|iPod)/i', $ua);
    $isDesktop = !$isTablet && !$isPhone;

    // --- Define suspicious scenarios ---

    // 1. Desktop UA with a very small, phone-like resolution.
    if ($isDesktop && ($width < 1024 || $height < 768)) {
      return TRUE;
    }

    // 2. Phone UA with a very large, desktop-like resolution.
    // Modern phones have high pixel density, but their logical width in JS is usually < 980px.
    if ($isPhone && $width > 980) {
      return TRUE;
    }

    // 3. Tablet UA with an unlikely resolution (either too small or excessively large).
    if ($isTablet && (($width < 768 && $height < 1024) || $width > 2048)) {
      return TRUE;
    }

    // All other combinations are considered valid.
    return FALSE;
  }

  private function ipInCidr(string $ip, string $cidr): bool {
    [$subnet, $mask] = explode('/', $cidr);

    // Convert IP and subnet to long integers.
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);

    if ($ip_long === FALSE || $subnet_long === FALSE) {
      return FALSE;
    }

    // Calculate network mask.
    $mask_long = -1 << (32 - (int) $mask);

    // Check if IP is in subnet.
    return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
  }

  /**
   * Get the trusted client IP address from request.
   *
   * Handles various reverse proxy scenarios (Traefik, Nginx, Cloudflare, etc.).
   * Checks multiple headers in order of preference and validates against
   * trusted proxy ranges.
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The current request.
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The module configuration.
   *
   * @return string
   *   The client IP address.
   */
  private function getTrustedClientIp($request, $config): string {
    // Get the immediate client IP (might be proxy).
    $immediateIp = $request->getClientIp() ?? '0.0.0.0';

    // Get trusted proxy IPs/ranges from config.
    $trustedProxies = (string) $config->get('trusted_proxies');

    // If no trusted proxies configured, use immediate IP.
    if (empty($trustedProxies)) {
      return $immediateIp;
    }

    // Check if immediate IP is a trusted proxy.
    $isTrustedProxy = $this->ipInAllowlist($immediateIp, $trustedProxies);

    // If not from trusted proxy, return immediate IP.
    if (!$isTrustedProxy) {
      return $immediateIp;
    }

    // Priority order of headers to check (most reliable first).
    $headers = [
      'HTTP_CF_CONNECTING_IP',     // Cloudflare
      'HTTP_X_REAL_IP',            // Nginx, Traefik
      'HTTP_X_FORWARDED_FOR',      // Standard proxy header
      'HTTP_X_FORWARDED',          // Alternative
      'HTTP_FORWARDED_FOR',        // RFC 7239
      'HTTP_FORWARDED',            // RFC 7239
      'HTTP_CLIENT_IP',            // Some proxies
    ];

    foreach ($headers as $header) {
      if (!empty($_SERVER[$header])) {
        $ip = $_SERVER[$header];

        // X-Forwarded-For can contain multiple IPs (client, proxy1, proxy2).
        // Take the first (leftmost) IP as it's the original client.
        if (str_contains($ip, ',')) {
          $ips = array_map('trim', explode(',', $ip));
          $ip = $ips[0];
        }

        // Validate IP format.
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
          return $ip;
        }
      }
    }

    // Fallback to immediate IP if no valid header found.
    return $immediateIp;
  }

}
