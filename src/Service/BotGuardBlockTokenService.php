<?php

namespace Drupal\bot_guard\Service;

/**
 * Service for generating and decoding block tokens for debugging.
 */
class BotGuardBlockTokenService {

  /**
   * Generate an encoded block token for debugging.
   *
   * Creates a compact token containing block information that can be decoded
   * in the dashboard for troubleshooting false positives.
   *
   * Format: BG + base64url(gzcompress(json({...})))
   * Uses gzip compression and URL-safe base64 to minimize token length.
   * The token is not cryptographically signed - it's just for debugging.
   * Contains full IP address and User-Agent for admin troubleshooting.
   *
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   * @param string $path
   *   The request path.
   * @param string $reason
   *   The block reason.
   * @param array $details
   *   Additional details (resolution, cookie info, etc.).
   *
   * @return string
   *   The encoded block token (typically 40-60% smaller than uncompressed).
   */
  public function generateBlockToken(string $ip, string $ua, string $path, string $reason, array $details): string {
    // Pack data efficiently: reason|ip|ua|path|timestamp|details
    // Use pipe separator for easy parsing
    $detailsJson = empty($details) ? '' : json_encode($details, JSON_UNESCAPED_SLASHES);
    $data = implode('|', [$reason, $ip, $ua, $path, time(), $detailsJson]);

    // Compress with gzcompress (level 9 = maximum compression)
    $compressed = gzcompress($data, 9);

    // Base64 encode (URL-safe variant, no padding)
    $token = rtrim(strtr(base64_encode($compressed), '+/', '-_'), '=');

    // Add prefix (no checksum to save 3 chars)
    return 'BG' . $token;
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
  public function decodeBlockToken(string $token): ?array {
    // Remove prefix (BG)
    if (!str_starts_with($token, 'BG') || strlen($token) < 4) {
      return NULL;
    }

    $encodedData = substr($token, 2);

    // Restore padding if needed
    $padding = strlen($encodedData) % 4;
    if ($padding > 0) {
      $encodedData .= str_repeat('=', 4 - $padding);
    }

    // Convert URL-safe base64 back to standard base64
    $encodedData = strtr($encodedData, '-_', '+/');

    // Base64 decode
    $compressed = base64_decode($encodedData, TRUE);
    if ($compressed === FALSE) {
      return NULL;
    }

    // Decompress
    $data = @gzuncompress($compressed);
    if ($data === FALSE) {
      return NULL;
    }

    // Parse pipe-separated values: reason|ip|ua|path|timestamp|details
    $parts = explode('|', $data, 6);
    if (count($parts) < 5) {
      return NULL;
    }

    return [
      'r' => $parts[0],
      'i' => $parts[1],
      'u' => $parts[2],
      'p' => $parts[3],
      't' => (int) $parts[4],
      'd' => isset($parts[5]) && $parts[5] !== '' ? json_decode($parts[5], TRUE) : [],
    ];
  }

}
