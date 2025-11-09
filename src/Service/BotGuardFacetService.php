<?php

namespace Drupal\bot_guard\Service;

use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Service for handling facet bot detection and flood protection.
 */
class BotGuardFacetService {

  /**
   * The config factory service.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The cache backend.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cacheBackend;

  /**
   * Constructs a BotGuardFacetService object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory service.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache_backend
   *   The cache backend.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    CacheBackendInterface $cache_backend
  ) {
    $this->configFactory = $config_factory;
    $this->cacheBackend = $cache_backend;
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
  public function getFacetParams(Request $request): array {
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
   * Check if facet parameters exceed the configured limit.
   *
   * @param array $facet_params
   *   The facet parameters.
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   * @param string $path
   *   The request path (full URI).
   *
   * @return bool
   *   TRUE if the limit is exceeded, FALSE otherwise.
   */
  public function checkFacetLimit(array $facet_params, string $ip, string $ua, string $path): bool {
    $config = $this->configFactory->get('bot_guard.settings');
    $limit = (int) ($config->get('facet_limit') ?? 2);

    // Initialize metrics if not present.
    if (!$this->cacheBackend->get('facet_bot.metrics_start')) {
      $this->cacheBackend->set('facet_bot.metrics_start', time());
    }

    if (count($facet_params) > $limit) {
      // Count blocked.
      $blocked = $this->cacheBackend->get('facet_bot.blocked');
      $blocked_count = $blocked ? (int) $blocked->data : 0;
      $this->cacheBackend->set('facet_bot.blocked', $blocked_count + 1);

      // Save last blocked info.
      $this->cacheBackend->set('facet_bot.last', [
        'ip' => $ip,
        'path' => $path,
        'ua' => $ua,
        'params' => $facet_params,
      ]);

      return TRUE;
    }

    // Count allowed when f[] present and within limit.
    $allowed = $this->cacheBackend->get('facet_bot.allowed');
    $allowed_count = $allowed ? (int) $allowed->data : 0;
    $this->cacheBackend->set('facet_bot.allowed', $allowed_count + 1);

    return FALSE;
  }

  /**
   * Check for facet flood pattern (too many unique facet combinations).
   *
   * @param array $facet_params
   *   The facet parameters.
   * @param string $ip
   *   The client IP address.
   *
   * @return bool
   *   TRUE if the IP should be banned, FALSE otherwise.
   */
  public function checkFacetFlood(array $facet_params, string $ip): bool {
    $config = $this->configFactory->get('bot_guard.settings');
    $facetFloodEnabled = (bool) ($config->get('facet_flood_enabled') ?? TRUE);
    $facetThreshold = (int) ($config->get('facet_flood_threshold') ?? 20);
    $facetWindow = (int) ($config->get('facet_flood_window') ?? 600);
    $facetBan = (int) ($config->get('facet_flood_ban') ?? 1800);

    if (!$facetFloodEnabled || $facetThreshold <= 0 || $facetWindow <= 0 || !function_exists('apcu_fetch')) {
      return FALSE;
    }

    // If already banned, deny immediately.
    $banKey = 'bg_ffp_ban_' . sha1($ip);
    if (apcu_exists($banKey)) {
      return TRUE;
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
      return TRUE;
    }

    return FALSE;
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
  protected function facetFingerprint(array $facets): string {
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

}
