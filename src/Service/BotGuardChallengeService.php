<?php

namespace Drupal\bot_guard\Service;

use Drupal\Component\Utility\Crypt;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\StringTranslation\StringTranslationTrait;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Service for handling bot guard challenge, cookie validation and proof-of-work.
 */
class BotGuardChallengeService {

  use StringTranslationTrait;

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
   * The module handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * The screen resolution from the client.
   *
   * @var string
   */
  protected $screenResolution = '';

  /**
   * Constructs a BotGuardChallengeService object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory service.
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache_backend
   *   The cache backend.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler service.
   */
  public function __construct(
    ConfigFactoryInterface $config_factory,
    CacheBackendInterface $cache_backend,
    ModuleHandlerInterface $module_handler
  ) {
    $this->configFactory = $config_factory;
    $this->cacheBackend = $cache_backend;
    $this->moduleHandler = $module_handler;
  }

  /**
   * Get the screen resolution extracted from the challenge cookie.
   *
   * @return string
   *   The screen resolution (e.g., "1920x1080").
   */
  public function getScreenResolution(): string {
    return $this->screenResolution;
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
  public function hasValidChallengeCookie(?string $cookie, string $ip, string $ua): bool {
    if (!$cookie) {
      return FALSE;
    }

    // New format: payload.signature (JSON payload with ts + scr + optional pow)
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

      // Validate proof-of-work if enabled and present
      $config = $this->configFactory->get('bot_guard.settings');
      $powEnabled = (bool) ($config->get('pow_enabled') ?? TRUE);
      if ($powEnabled && isset($data['pow'])) {
        $powData = $data['pow'];
        if (!is_array($powData) || !isset($powData['challenge'], $powData['nonce'], $powData['hash'])) {
          return FALSE;
        }
        if (!$this->validateProofOfWork($powData['challenge'], $powData['nonce'], $powData['hash'])) {
          return FALSE;
        }
      }
      elseif ($powEnabled) {
        // PoW is enabled but not present in cookie - invalid
        return FALSE;
      }

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
   * Serve a JavaScript-based cookie challenge with optional proof-of-work.
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
  public function serveChallenge(RequestEvent $event, string $cookieName, int $ttl, string $ip, string $ua): void {
    $this->incrementChallengeCounter();

    $config = $this->configFactory->get('bot_guard.settings');
    $exp = time() + $ttl;
    $sig = $this->sign($ip, $ua, $exp);

    // Check if proof-of-work is enabled
    $powEnabled = (bool) ($config->get('pow_enabled') ?? TRUE);

    if ($powEnabled) {
      // Generate proof-of-work challenge
      $powChallenge = $this->generatePowChallenge($ip, $ua, $exp);
      $powDifficulty = (int) ($config->get('pow_difficulty') ?? 3);
      $powMaxIterations = (int) ($config->get('pow_max_iterations') ?? 10000000);
      $powTimeout = (int) ($config->get('pow_timeout') ?? 30);

      // Serve challenge page with proof-of-work
      $html = $this->buildPowChallengePage(
        $cookieName,
        $exp,
        $sig,
        $powChallenge,
        $powDifficulty,
        $powMaxIterations,
        $powTimeout
      );
    }
    else {
      // Serve simple challenge page without proof-of-work
      $html = $this->buildSimpleChallengePage($cookieName, $exp, $sig);
    }

    $response = new Response($html, 200, [
      'Content-Type' => 'text/html; charset=utf-8',
      'Cache-Control' => 'no-cache, no-store, must-revalidate',
      'Pragma' => 'no-cache',
    ]);

    $event->setResponse($response);
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
  protected function sign(string $ip, string $ua, int $exp): string {
    $salt = $this->getHashSalt();
    return base64_encode(hash_hmac('sha256', $ip . "\n" . $ua . "\n" . $exp, $salt, TRUE));
  }

  /**
   * Get the hash salt for signing cookies.
   *
   * @return string
   *   The hash salt.
   */
  protected function getHashSalt(): string {
    $salt = (string) \Drupal::service('settings')->get('hash_salt');
    if ($salt === '') {
      $salt = Crypt::randomBytesBase64();
    }
    return $salt;
  }

  /**
   * Build the HTML page for simple challenge (without proof-of-work).
   *
   * @param string $cookieName
   *   The name of the challenge cookie.
   * @param int $exp
   *   The expiration timestamp.
   * @param string $sig
   *   The signature for the cookie.
   *
   * @return string
   *   The HTML page content.
   */
  protected function buildSimpleChallengePage(string $cookieName, int $exp, string $sig): string {
    return '<!doctype html><html><head><meta charset="utf-8">' .
      '<meta http-equiv="refresh" content="1">' .
      '<title>' . $this->t('Verifying…') . '</title></head><body>' .
      '<noscript>' . $this->t('JavaScript required.') . '</noscript>' .
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
  }

  /**
   * Build the HTML page for proof-of-work challenge.
   *
   * @param string $cookieName
   *   The name of the challenge cookie.
   * @param int $exp
   *   The expiration timestamp.
   * @param string $sig
   *   The signature for the cookie.
   * @param string $challenge
   *   The proof-of-work challenge string.
   * @param int $difficulty
   *   The number of leading zeros required.
   * @param int $maxIterations
   *   Maximum number of iterations.
   * @param int $timeout
   *   Timeout in seconds.
   *
   * @return string
   *   The HTML page content.
   */
  protected function buildPowChallengePage(string $cookieName, int $exp, string $sig, string $challenge, int $difficulty, int $maxIterations, int $timeout): string {
    $expMs = $exp * 1000;

    // Inline Web Worker code for proof-of-work computation
    $workerCode = <<<'WORKER'
self.onmessage = async function(e) {
  const { challenge, difficulty, maxIterations } = e.data;
  const target = '0'.repeat(difficulty);

  // Use SubtleCrypto for SHA-256 hashing
  async function sha256(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  let nonce = 0;
  let hash = '';

  try {
    while (nonce < maxIterations) {
      hash = await sha256(challenge + nonce);

      if (hash.startsWith(target)) {
        self.postMessage({ success: true, nonce, hash });
        return;
      }

      nonce++;

      // Report progress every 10000 iterations
      if (nonce % 10000 === 0) {
        self.postMessage({ progress: nonce });
      }
    }

    self.postMessage({ success: false, error: 'Max iterations reached' });
  } catch (error) {
    self.postMessage({ success: false, error: error.message });
  }
};
WORKER;

    $workerBlob = base64_encode($workerCode);

    // Properly escape values for JavaScript
    $challengeJson = json_encode($challenge);
    $sigJson = json_encode($sig);
    $cookieNameJson = json_encode($cookieName);

    $html = '<!doctype html><html><head><meta charset="utf-8">' .
      '<meta name="viewport" content="width=device-width, initial-scale=1">' .
      '<title>' . $this->t('Verifying Your Browser') . '</title><style>' .
      'body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f5f5}' .
      '.container{text-align:center;padding:2rem;background:white;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,0.1);max-width:400px}' .
      '.spinner{border:3px solid #f3f3f3;border-top:3px solid #3498db;border-radius:50%;width:40px;height:40px;animation:spin 1s linear infinite;margin:0 auto 1rem}' .
      '@keyframes spin{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}' .
      '.progress{margin-top:1rem;font-size:0.9rem;color:#666}' .
      '.error{color:#e74c3c;margin-top:1rem}' .
      'noscript{display:block;padding:1rem;background:#fff3cd;border:1px solid #ffc107;border-radius:4px}' .
      '</style></head><body>' .
      '<div class="container"><div class="spinner"></div>' .
      '<h2>' . $this->t('Verifying Your Browser') . '</h2>' .
      '<p>' . $this->t('Please wait while we verify your browser...') . '</p>' .
      '<div class="progress" id="progress"></div>' .
      '<div class="error" id="error"></div></div>' .
      '<noscript><div class="container"><h2>' . $this->t('JavaScript Required') . '</h2>' .
      '<p>' . $this->t('Please enable JavaScript to continue.') . '</p></div></noscript>' .
      '<script>(async function(){' .
      'const challenge=' . $challengeJson . ';' .
      'const difficulty=' . $difficulty . ';' .
      'const maxIterations=' . $maxIterations . ';' .
      'const timeout=' . $timeout . ';' .
      'const exp=' . $expMs . ';' .
      'const sig=' . $sigJson . ';' .
      'const cookieName=' . $cookieNameJson . ';' .
      'const progressEl=document.getElementById("progress");' .
      'const errorEl=document.getElementById("error");' .
      'try{' .
      'const workerBlob=atob("' . $workerBlob . '");' .
      'const blob=new Blob([workerBlob],{type:"application/javascript"});' .
      'const workerUrl=URL.createObjectURL(blob);' .
      'const worker=new Worker(workerUrl);' .
      'const timeoutId=setTimeout(()=>{worker.terminate();errorEl.textContent="' . $this->t('Challenge timeout. Please refresh to try again.') . '";},timeout*1000);' .
      'worker.onmessage=function(e){' .
      'if(e.data.progress){progressEl.textContent="' . $this->t('Computing') . ': "+e.data.progress.toLocaleString()+" attempts...";}' .
      'else if(e.data.success){clearTimeout(timeoutId);worker.terminate();URL.revokeObjectURL(workerUrl);' .
      'const scr=screen.width+"x"+screen.height;' .
      'const payload=btoa(JSON.stringify({ts:exp,scr:scr,pow:{challenge:challenge,nonce:e.data.nonce,hash:e.data.hash}}));' .
      'const d=new Date(exp);const val=payload+"."+sig;' .
      'document.cookie=cookieName+"="+val+";path=/;expires="+d.toUTCString()+";SameSite=Lax";' .
      'progressEl.textContent="' . $this->t('Verification complete! Redirecting...') . '";setTimeout(()=>location.reload(),500);}' .
      'else{clearTimeout(timeoutId);worker.terminate();URL.revokeObjectURL(workerUrl);' .
      'errorEl.textContent="' . $this->t('Challenge failed: ') . ' "+(e.data.error||"' . $this->t('Unknown error') . '");}};' .
      'worker.onerror=function(error){clearTimeout(timeoutId);worker.terminate();URL.revokeObjectURL(workerUrl);' .
      'errorEl.textContent="' . $this->t('Worker error: ') . ' "+error.message;};' .
      'worker.postMessage({challenge,difficulty,maxIterations});}' .
      'catch(error){errorEl.textContent="Error: "+error.message;}})();</script>' .
      '</body></html>';

    return $html;
  }

  /**
   * Increment the challenge counter in cache.
   */
  protected function incrementChallengeCounter(): void {
    if ($this->usePersistentCache()) {
      $cached = $this->cacheBackend->get('bg.challenge.count');
      $count = $cached ? $cached->data : 0;
      $this->cacheBackend->set('bg.challenge.count', $count + 1);
    }
    elseif (function_exists('apcu_fetch')) {
      $c = apcu_fetch('bg.challenge.count');
      apcu_store('bg.challenge.count', ($c === FALSE ? 1 : ((int) $c) + 1), 0);
    }
  }

  /**
   * Check if we should use persistent cache (Memcache/Redis).
   *
   * @return bool
   *   TRUE if persistent cache is available.
   */
  protected function usePersistentCache(): bool {
    return (
      $this->moduleHandler->moduleExists('memcache') ||
      $this->moduleHandler->moduleExists('redis')
    );
  }

  /**
   * Generate a proof-of-work challenge string.
   *
   * @param string $ip
   *   The client IP address.
   * @param string $ua
   *   The client User-Agent string.
   * @param int $timestamp
   *   The current timestamp.
   *
   * @return string
   *   A unique challenge string based on request metadata.
   */
  protected function generatePowChallenge(string $ip, string $ua, int $timestamp): string {
    $salt = $this->getHashSalt();
    // Create a challenge from IP, UA, timestamp, and salt
    return hash('sha256', $ip . "\n" . $ua . "\n" . $timestamp . "\n" . $salt);
  }

  /**
   * Validate a proof-of-work solution.
   *
   * @param string $challenge
   *   The challenge string.
   * @param int $nonce
   *   The nonce (iteration number) used to solve the challenge.
   * @param string $hash
   *   The resulting hash that should have the required leading zeros.
   *
   * @return bool
   *   TRUE if the proof-of-work is valid, FALSE otherwise.
   */
  protected function validateProofOfWork(string $challenge, int $nonce, string $hash): bool {
    $config = $this->configFactory->get('bot_guard.settings');
    $difficulty = (int) ($config->get('pow_difficulty') ?? 5);

    // Verify the hash matches the challenge + nonce
    $expectedHash = hash('sha256', $challenge . $nonce);
    if (!hash_equals($expectedHash, $hash)) {
      return FALSE;
    }

    // Verify the hash has the required number of leading zeros
    $requiredPrefix = str_repeat('0', $difficulty);
    if (!str_starts_with($hash, $requiredPrefix)) {
      return FALSE;
    }

    // Additional validation: Verify the challenge format is valid (64 hex chars for SHA-256)
    if (!preg_match('/^[0-9a-f]{64}$/i', $challenge)) {
      return FALSE;
    }

    return TRUE;
  }

}
