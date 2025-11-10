<?php

namespace Drupal\bot_guard\Service;

use Symfony\Component\HttpFoundation\Request;

/**
 * Helper service for IP address validation and CIDR checks.
 */
class BotGuardIpHelper {

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
  public function ipInAllowlist(string $ip, string $allowlist): bool {
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
  public function ipInCidr(string $ip, string $cidr): bool {
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
   * @param string $trustedProxies
   *   Newline-separated list of trusted proxy IPs/CIDR ranges.
   *
   * @return array
   *   An array with keys:
   *   - 'ip': The client IP address.
   *   - 'is_proxy': TRUE if the returned IP is a proxy IP (original IP could
   *     not be extracted), FALSE if it's a real client IP.
   */
  public function getTrustedClientIp(Request $request, string $trustedProxies): array {
    // Get the immediate client IP (might be proxy).
    $immediateIp = $request->getClientIp() ?? '0.0.0.0';

    // If no trusted proxies configured, use immediate IP.
    if (empty($trustedProxies)) {
      return ['ip' => $immediateIp, 'is_proxy' => FALSE];
    }

    // Check if immediate IP is a trusted proxy.
    $isTrustedProxy = $this->ipInAllowlist($immediateIp, $trustedProxies);

    // If not from trusted proxy, return immediate IP.
    if (!$isTrustedProxy) {
      return ['ip' => $immediateIp, 'is_proxy' => FALSE];
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
          return ['ip' => $ip, 'is_proxy' => FALSE];
        }
      }
    }

    // Fallback to immediate IP if no valid header found.
    // Mark as proxy IP since we couldn't extract the real client IP.
    return ['ip' => $immediateIp, 'is_proxy' => TRUE];
  }

}
