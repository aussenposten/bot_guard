<?php

namespace Drupal\bot_guard\Service;

/**
 * Helper service for bot detection heuristics.
 */
class BotGuardDetectionHelper {

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
  public function matchesAny(string $subject, string $patterns): bool {
    foreach (preg_split('/\R+/', $patterns) as $p) {
      $p = trim($p);
      if ($p !== '' && @preg_match("~$p~i", '') !== FALSE && preg_match("~$p~i", $subject)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Check for suspicious screen resolution / user agent combinations.
   *
   * This method focuses on detecting obviously fake resolutions and headless
   * browsers, while being permissive enough to allow legitimate devices.
   *
   * Known limitations:
   * - iPads with Safari report as "Macintosh" (desktop UA) with tablet
   * resolutions
   * - Modern tablets can have various resolutions overlapping with small
   * laptops
   *
   * @param string $ua
   *   The client User-Agent string.
   * @param string $resolution
   *   The client screen resolution (e.g., "1920x1080").
   *
   * @return bool
   *   TRUE if the combination is suspicious, FALSE otherwise.
   */
  public function isSuspiciousScreenResolution(string $ua, string $resolution): bool {
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

    // Common headless browser and automation tool resolutions that are suspicious.
    // These are default values commonly used by Puppeteer, Selenium, etc.
    $headlessResolutions = [
      '800x600',   // Common Puppeteer/Selenium default
      '1280x720',  // Another common automation default
      '1280x800',  // Headless Chrome default on some systems
    ];
    if (in_array($resolution, $headlessResolutions, TRUE)) {
      // Additional check: if it's a headless resolution but has webkit/safari,
      // it might be a real device (like an old iPad). Be more lenient.
      if (!preg_match('/WebKit|Safari/i', $ua)) {
        return TRUE;
      }
    }

    // Distinguish between device types based on User-Agent.
    // Note: iPads with Safari report as "Macintosh" (desktop UA), so we can't
    // reliably detect them here. We need to be permissive with tablet-sized resolutions.
    $isPhone = preg_match('/(Mobi|Android.*Mobi|iPhone|iPod)/i', $ua);
    $isTablet = preg_match('/(iPad|Tablet|Android(?!.*Mobi))/i', $ua);

    // --- Define suspicious scenarios ---

    // 1. Phone UA with desktop/tablet resolution.
    // Modern phones rarely exceed 430px logical width (even with high DPI).
    // iPhone 15 Pro Max = 430x932, Samsung S24 Ultra = 412x915.
    if ($isPhone && $width > 600) {
      return TRUE;
    }

    // 2. Tablet UA with phone resolution.
    // Tablets are typically 600px+ width. iPads start at 768px.
    if ($isTablet && $width < 600) {
      return TRUE;
    }

    // 3. Very unusual resolutions that don't match any real device.
    // Excessively narrow (< 320px) or extremely wide (> 4000px) are suspicious.
    if ($width < 320 || $width > 4000 || $height < 320 || $height > 4000) {
      return TRUE;
    }

    // 4. Aspect ratios that don't exist in the real world.
    // Most screens have aspect ratios between 4:3 (1.33) and 21:9 (2.33).
    $aspectRatio = max($width, $height) / min($width, $height);
    if ($aspectRatio > 3.0 || $aspectRatio < 1.0) {
      return TRUE;
    }

    // All other combinations are considered valid.
    // This includes:
    // - iPads with Safari (Macintosh UA + 768x1024 or similar)
    // - Small laptops (1366x768, 1280x720)
    // - Large monitors (3840x2160, 2560x1440)
    // - Modern tablets with various resolutions
    return FALSE;
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
  public function rateCheck(string $ip, int $max, int $window): bool {
    if (!function_exists('apcu_fetch')) {
      return TRUE;
    }

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
  public function cacheKey(string $ip, string $ua, string $path): string {
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
  public function storeDecision(bool $enabled, string $key, int $value, int $ttl): void {
    if ($enabled && function_exists('apcu_store')) {
      apcu_store($key, $value, $ttl);
    }
  }

}
