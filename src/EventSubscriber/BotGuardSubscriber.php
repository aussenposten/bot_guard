<?php

namespace Drupal\bot_guard\EventSubscriber;

use Drupal\bot_guard\Service\BotGuardBlockTokenService;
use Drupal\bot_guard\Service\BotGuardChallengeService;
use Drupal\bot_guard\Service\BotGuardDetectionHelper;
use Drupal\bot_guard\Service\BotGuardFacetService;
use Drupal\bot_guard\Service\BotGuardIpHelper;
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
   * The challenge service.
   *
   * @var \Drupal\bot_guard\Service\BotGuardChallengeService
   */
  protected $challengeService;

  /**
   * The facet service.
   *
   * @var \Drupal\bot_guard\Service\BotGuardFacetService
   */
  protected $facetService;

  /**
   * The IP helper.
   *
   * @var \Drupal\bot_guard\Service\BotGuardIpHelper
   */
  protected $ipHelper;

  /**
   * The detection helper.
   *
   * @var \Drupal\bot_guard\Service\BotGuardDetectionHelper
   */
  protected $detectionHelper;

  /**
   * The block token service.
   *
   * @var \Drupal\bot_guard\Service\BotGuardBlockTokenService
   */
  protected $blockTokenService;

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
   * @param \Drupal\bot_guard\Service\BotGuardChallengeService $challenge_service
   *   The challenge service.
   * @param \Drupal\bot_guard\Service\BotGuardFacetService $facet_service
   *   The facet service.
   * @param \Drupal\bot_guard\Service\BotGuardIpHelper $ip_helper
   *   The IP helper.
   * @param \Drupal\bot_guard\Service\BotGuardDetectionHelper $detection_helper
   *   The detection helper.
   * @param \Drupal\bot_guard\Service\BotGuardBlockTokenService $block_token_service
   *   The block token service.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    AccountProxyInterface $current_user,
    ModuleHandlerInterface $module_handler,
    CacheBackendInterface $cache_backend,
    TimeInterface $time,
    BotGuardMetricsService $metrics_service,
    BotGuardChallengeService $challenge_service,
    BotGuardFacetService $facet_service,
    BotGuardIpHelper $ip_helper,
    BotGuardDetectionHelper $detection_helper,
    BotGuardBlockTokenService $block_token_service
  ) {
    $this->configFactory = $config_factory;
    $this->currentUser = $current_user;
    $this->moduleHandler = $module_handler;
    $this->cacheBackend = $cache_backend;
    $this->time = $time;
    $this->metricsService = $metrics_service;
    $this->challengeService = $challenge_service;
    $this->facetService = $facet_service;
    $this->ipHelper = $ip_helper;
    $this->detectionHelper = $detection_helper;
    $this->blockTokenService = $block_token_service;
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
    $trustedProxies = (string) $config->get('trusted_proxies');
    $ipData = $this->ipHelper->getTrustedClientIp($request, $trustedProxies);
    $ip = $ipData['ip'];
    $isProxyIp = $ipData['is_proxy'];
    $method = $request->getMethod();

    // IP Allow-list (bypass all checks).
    $allowIps = (string) $config->get('allow_ips');
    if ($allowIps && $this->ipHelper->ipInAllowlist($ip, $allowIps)) {
      return;
    }

    // Path Allow-list (bypass all checks).
    $allowPaths = (string) $config->get('allow_paths');
    if ($allowPaths && $this->detectionHelper->matchesAny($path, $allowPaths)) {
      return;
    }

    // Decision cache.
    // Disable caching for proxy IPs (multiple users may share the same proxy IP).
    $cacheEnabled = (bool) $config->get('cache_enabled') && !$isProxyIp;
    $cacheTtl = (int) ($config->get('cache_ttl') ?? 300);
    $cacheKey = $this->detectionHelper->cacheKey($ip, $ua, $path);

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
    if ($this->detectionHelper->matchesAny($ua, (string) $config->get('allow_bots'))) {
      $this->incrementAllowedCounter();
      $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::ALLOW, $cacheTtl);
      return;
    }

    // Heuristics: empty/short UA, missing Accept-Language.
    if ($ua === '' || strlen($ua) < 10) {
      $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
      $this->deny($event, $config, $ip, $ua, $path, 'ua-short');
      return;
    }
    if ($request->headers->get('Accept-Language') === NULL || $request->headers->get('Accept-Language') === '') {
      $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
      $this->deny($event, $config, $ip, $ua, $path, 'no-accept-language');
      return;
    }

    // Block-list UA patterns.
    if ($this->detectionHelper->matchesAny($ua, (string) $config->get('block_bots'))) {
      $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
      $this->deny($event, $config, $ip, $ua, $path, 'ua-block');
      return;
    }

    // Rate limit.
    // Skip rate limiting for proxy IPs (multiple users may share the same proxy IP).
    if (!$isProxyIp) {
      $max = (int) ($config->get('rate_limit') ?? 20);
      $win = (int) ($config->get('rate_window') ?? 10);
      if ($max > 0) {
        if (!$this->detectionHelper->rateCheck($ip, $max, $win)) {
          // 429 not cached (small window anyway)
          $this->deny429($event, $config, $ip, $ua, $path, 'ratelimit');
        }
      }
    }

    // Cookie challenge.
    $challengeEnabled = (bool) ($config->get('challenge_enabled') ?? TRUE);
    $cookieName = (string) ($config->get('cookie_name') ?? 'bg_chal');
    $cookieTtl = (int) ($config->get('cookie_ttl') ?? 86400);
    $hasValidChallengeCookie = FALSE;

    if ($challengeEnabled) {
      // If no valid challenge cookie is present, take action.
      $cookieValue = $request->cookies->get($cookieName);
      if (!$this->challengeService->hasValidChallengeCookie($cookieValue, $ip, $ua)) {
        // Determine if this is a failed challenge attempt or first visit
        $isChallengeFailure = !empty($cookieValue);

        // For GET/HEAD requests, serve the JS challenge to the browser.
        if (in_array($method, ['GET', 'HEAD'], TRUE)) {
          $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::CHALLENGE_PENDING, $cacheTtl);

          // Log failed challenge attempts (invalid/expired cookie)
          if ($isChallengeFailure) {
            $this->log($ip, $ua, $path, 'challenge-failed', [
              'cookie_present' => TRUE,
            ]);
          }

          $this->challengeService->serveChallenge($event, $cookieName, $cookieTtl, $ip, $ua);
        }
        // For other methods like POST, block if no valid cookie is present.
        else {
          $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
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
    $screenResolution = $this->challengeService->getScreenResolution();
    if ($hasValidChallengeCookie && $resolutionCheckEnabled && !empty($screenResolution)) {
      if ($this->detectionHelper->isSuspiciousScreenResolution($ua, $screenResolution)) {
        $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
        $this->deny($event, $config, $ip, $ua, $path, 'suspicious-resolution', [
          'screen_resolution' => $screenResolution,
        ]);
        return;
      }
    }

    // Facet Bot Blocking.
    if ($this->moduleHandler->moduleExists('facets')) {
      $facetEnabled = (bool) ($config->get('facet_enabled') ?? TRUE);
      $facet_params = $this->facetService->getFacetParams($request);

      if ($facetEnabled && !empty($facet_params)) {
        // Check if facet limit is exceeded
        if ($this->facetService->checkFacetLimit($facet_params, $ip, $ua, $request->getUri())) {
          $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
          $this->deny($event, $config, $ip, $ua, $path, 'facet-limit');
          return;
        }

        // Check for facet flood pattern
        if ($this->facetService->checkFacetFlood($facet_params, $ip, $isProxyIp)) {
          $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::BLOCK, $cacheTtl);
          $this->deny($event, $config, $ip, $ua, $path, 'facet-flood-ban');
          return;
        }
      }
    }

    // Passed all checks - count as allowed request.
    $this->incrementAllowedCounter();
    $this->detectionHelper->storeDecision($cacheEnabled, $cacheKey, self::ALLOW, $cacheTtl);
  }


  /**
   * Deny a request with a custom error response.
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

    $statusCode = (int) ($config->get('block_status_code') ?? 200);
    $message = (string) ($config->get('block_message') ?? '<h1>Access Denied</h1><p>Your request was blocked.</p>');

    $this->buildDenyResponse($event, $ip, $ua, $path, $reason, $details, $statusCode, $message);
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

    $statusCode = (int) ($config->get('ratelimit_status_code') ?? 429);
    $message = (string) ($config->get('ratelimit_message') ?? '<h1>Too Many Requests</h1><p>Please slow down.</p>');
    $retryAfter = (int) ($config->get('ratelimit_retry_after') ?? 30);

    $this->buildDenyResponse($event, $ip, $ua, $path, $reason, $details, $statusCode, $message, $retryAfter);
  }

  /**
   * Build and set a deny response with token injection.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   The request event.
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
   * @param int $statusCode
   *   The HTTP status code.
   * @param string $message
   *   The response message.
   * @param int|null $retryAfter
   *   Optional Retry-After header value in seconds.
   */
  private function buildDenyResponse(
    RequestEvent $event,
    string $ip,
    string $ua,
    string $path,
    string $reason,
    array $details,
    int $statusCode,
    string $message,
    ?int $retryAfter = NULL
  ): void {
    // Generate debug token for troubleshooting.
    $token = $this->blockTokenService->generateBlockToken($ip, $ua, $path, $reason, $details);

    // Add token to message if not already present.
    if (!str_contains($message, '{token}')) {
      $message .= '<strong>Reference:</strong> ' . htmlspecialchars($token);
    }
    else {
      // Replace placeholder if present in custom message.
      $message = str_replace('{token}', htmlspecialchars($token), $message);
    }

    $headers = ['Content-Type' => 'text/html; charset=utf-8'];
    if ($retryAfter !== NULL) {
      $headers['Retry-After'] = (string) $retryAfter;
    }

    $event->setResponse(new Response($message, $statusCode, $headers));
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

      // Track UA-specific blocks separately for aggregation
      if (in_array($reason, ['ua-block', 'ua-short'], TRUE)) {
        $ua_stats_cache = $this->cacheBackend->get('bg.ua.stats');
        $ua_stats = $ua_stats_cache ? $ua_stats_cache->data : [];

        $ua_key = md5($ua); // Use hash as key to avoid issues with special chars
        if (!isset($ua_stats[$ua_key])) {
          $ua_stats[$ua_key] = [
            'ua' => $ua,
            'count' => 0,
            'reasons' => [],
            'last_seen' => $this->time->getRequestTime(),
          ];
        }

        $ua_stats[$ua_key]['count']++;
        if (!isset($ua_stats[$ua_key]['reasons'][$reason])) {
          $ua_stats[$ua_key]['reasons'][$reason] = 0;
        }
        $ua_stats[$ua_key]['reasons'][$reason]++;
        $ua_stats[$ua_key]['last_seen'] = $this->time->getRequestTime();

        $this->cacheBackend->set('bg.ua.stats', $ua_stats);
      }

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

      // Track UA-specific blocks separately for aggregation
      if (in_array($reason, ['ua-block', 'ua-short'], TRUE)) {
        $ua_stats = apcu_fetch('bg.ua.stats') ?: [];

        $ua_key = md5($ua); // Use hash as key to avoid issues with special chars
        if (!isset($ua_stats[$ua_key])) {
          $ua_stats[$ua_key] = [
            'ua' => $ua,
            'count' => 0,
            'reasons' => [],
            'last_seen' => time(),
          ];
        }

        $ua_stats[$ua_key]['count']++;
        if (!isset($ua_stats[$ua_key]['reasons'][$reason])) {
          $ua_stats[$ua_key]['reasons'][$reason] = 0;
        }
        $ua_stats[$ua_key]['reasons'][$reason]++;
        $ua_stats[$ua_key]['last_seen'] = time();

        apcu_store('bg.ua.stats', $ua_stats, 0);
      }

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
   * Decode a block token for debugging.
   *
   * @param string $token
   *   The encoded block token.
   *
   * @return array|null
   *   The decoded token data, or NULL if invalid.
   */
  public static function decodeBlockToken(string $token): ?array {
    // Delegate to service
    $service = \Drupal::service('bot_guard.block_token');
    return $service->decodeBlockToken($token);
  }

}
