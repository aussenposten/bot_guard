# Proof-of-Work Challenge Implementation

## Overview

This document describes the Anubis-style proof-of-work (PoW) challenge implementation in Bot Guard. The PoW challenge ensures that clients are using modern browsers capable of computing SHA-256 hashes, effectively blocking simple bots and scrapers.

## How It Works

### Challenge Flow

1. **Challenge Generation**: When a client without a valid challenge cookie makes a request, the server generates a unique challenge string based on:
   - Client IP address
   - User-Agent string
   - Current timestamp
   - Server hash salt

2. **Client Computation**: The client receives an HTML page with embedded JavaScript that:
   - Spawns a Web Worker for background computation
   - Iteratively computes SHA-256 hashes of `challenge + nonce`
   - Searches for a hash with the required number of leading zeros
   - Reports progress every 10,000 iterations

3. **Solution Submission**: Once a valid hash is found, the client:
   - Includes the proof-of-work data (challenge, nonce, hash) in the cookie payload
   - Also includes screen resolution for additional validation
   - Reloads the page with the signed cookie

4. **Server Validation**: The server validates:
   - Cookie signature (HMAC-SHA256 with server salt)
   - Cookie expiration
   - Proof-of-work solution:
     - Hash matches `SHA-256(challenge + nonce)`
     - Hash has required leading zeros
     - Challenge format is valid

## Configuration

### Settings

All settings are configurable via the Bot Guard admin UI at `/admin/config/system/bot-guard`:

- **Enable proof-of-work challenge**: Toggle PoW on/off
- **Difficulty (leading zeros)**: Number of leading zeros required (3-5)
  - **3**: Very fast (~0.1-0.5s, ~4K attempts) - **Default: 3** - recommended for most sites
  - **4**: Fast (~1-3s, ~65K attempts) - balanced security/UX
  - **5**: Slow (~10-30s, ~1M attempts) - maximum protection, impacts UX
  - **6+**: Not recommended (>30s, often triggers timeout)
- **Maximum iterations**: Safety limit to prevent infinite loops (default: 10,000,000)
- **Client timeout**: Maximum time allowed for solving (default: 60 seconds)

**Performance Note**: Difficulty scales exponentially with factor ~16x per level because SHA-256 produces hexadecimal output (16 possible values per character: 0-F). This means:
- Difficulty 3 requires ~16³ = 4,096 attempts on average
- Difficulty 4 requires ~16⁴ = 65,536 attempts on average
- Difficulty 5 requires ~16⁵ = 1,048,576 attempts on average
- Difficulty 6 requires ~16⁶ = 16,777,216 attempts on average (often exceeds timeout)

## Technical Details

### Challenge Generation

```php
private function generatePowChallenge(string $ip, string $ua, int $timestamp): string {
  $salt = $this->getHashSalt();
  return hash('sha256', $ip . "\n" . $ua . "\n" . $timestamp . "\n" . $salt);
}
```

The challenge is a SHA-256 hash of the client's metadata combined with the server's secret salt. This ensures:
- Each challenge is unique per client and time
- Challenges cannot be pre-computed
- Challenges are tied to the specific request context

### Validation Logic

The server performs these checks:

1. **Hash Verification**: `SHA-256(challenge + nonce) == submitted_hash`
2. **Difficulty Check**: Hash starts with N zeros (where N = difficulty)
3. **Format Validation**: Challenge is a valid 64-character hex string
4. **Cookie Signature**: HMAC-SHA256 signature is valid
5. **Expiration**: Cookie hasn't expired

### Cookie Format

The cookie contains a base64-encoded JSON payload with signature:

```
payload.signature
```

Where payload is:

```json
{
  "ts": 1699564800000,
  "scr": "1920x1080",
  "pow": {
    "challenge": "abc123...",
    "nonce": 42857,
    "hash": "00000a1b2c..."
  }
}
```

## Security Considerations

### Why Proof-of-Work?

Inspired by Hashcash (early 2000s email spam prevention), PoW makes automated scraping expensive:

- **Legitimate Users**: Solve one challenge, minimal impact (1-10 seconds)
- **Scrapers**: Must solve a challenge for every request, computationally prohibitive
- **Modern Browsers**: All modern browsers support Web Workers and SubtleCrypto API

### Attack Vectors & Mitigations

1. **Pre-computed Solutions**
   - ✅ Challenges include timestamp and are unique per request
   - ✅ Challenges tied to IP and User-Agent
   - ✅ Server salt prevents rainbow tables

2. **Challenge Reuse**
   - ✅ Cookie signature includes IP and UA
   - ✅ Cookie has expiration (default: 24 hours)
   - ✅ Signature uses HMAC-SHA256 with server secret

3. **Distributed Solving**
   - ⚠️ Attackers could distribute solving across multiple machines
   - ✅ Mitigated by rate limiting and other Bot Guard features
   - ✅ Each request still requires computational work

4. **GPU Acceleration**
   - ⚠️ Attackers with GPUs can solve faster
   - ✅ Difficulty can be increased (but impacts legitimate users)
   - ✅ Combined with other heuristics (UA, resolution, behavior)

## Performance Impact

### Client-Side

- **Difficulty 3** (default): ~0.1-0.5 seconds on modern hardware
- **Difficulty 4**: ~1-3 seconds on modern hardware
- **Difficulty 5**: ~10-30 seconds on modern hardware (may vary significantly)
- **CPU Usage**: High during solving, but runs in Web Worker (non-blocking UI)
- **Memory**: Minimal (~1-2 MB for worker)
- **Battery**: Negligible for occasional challenges

**Hardware Impact**: Actual solve times depend on CPU performance. Older devices or mobile browsers may take 2-3x longer. The exponential scaling (16x per difficulty level) means small increases in difficulty have dramatic performance impacts.

### Server-Side

- **Validation**: Single SHA-256 hash computation (~microseconds)
- **Memory**: No additional state stored
- **CPU**: Minimal impact

## Browser Compatibility

### Required Features

- **Web Workers**: For background computation
- **SubtleCrypto API**: For SHA-256 hashing
- **JavaScript ES6+**: Async/await, arrow functions

### Supported Browsers

- ✅ Chrome/Edge 37+
- ✅ Firefox 34+
- ✅ Safari 11.1+
- ✅ Opera 24+
- ❌ IE 11 and older (no SubtleCrypto support)

### Fallback Behavior

If JavaScript is disabled or the browser doesn't support required features:
- Challenge page displays error message
- User can enable JavaScript or upgrade browser
- Server-side validation prevents bypass attempts

## Integration with Other Features

The PoW challenge works alongside other Bot Guard features:

1. **Cookie Challenge**: PoW is embedded in the cookie challenge
2. **Screen Resolution Check**: Both collected simultaneously
3. **Rate Limiting**: Applied before challenge is served
4. **IP/UA Allowlists**: Bypass PoW entirely
5. **Decision Caching**: Successful PoW solutions are cached

## Comparison to Anubis

### Similarities

- SHA-256 proof-of-work with configurable difficulty
- Web Worker-based computation
- Challenge derived from request metadata
- JWT-like cookie with signature
- Default difficulty of 3 leading zeros (Bot Guard uses lower default for better UX)

### Differences

| Feature | Anubis | Bot Guard |
|---------|--------|-----------|
| Cookie Format | JWT (ed25519) | Base64 JSON + HMAC-SHA256 |
| Key Management | ed25519 keypair | Drupal hash_salt |
| Challenge Storage | None | None (stateless) |
| Additional Checks | Minimal | Screen resolution, UA patterns, rate limiting |
| Framework | Standalone | Drupal module |

## Troubleshooting

### Challenge Takes Too Long

- **Reduce difficulty**: Lower to 3 (recommended default) or even 2 for very slow devices
- **Increase timeout**: Give clients more time (default: 60s, can increase to 90-120s for difficulty 5)
- **Check client hardware**: Older devices may struggle with difficulty 4+
- **Consider disabling PoW**: For sites with many mobile/older device users, rely on other Bot Guard features instead

### Legitimate Users Blocked

- **Disable PoW temporarily**: Set `pow_enabled: false`
- **Add to allowlist**: Use IP or path allowlists
- **Check browser compatibility**: Ensure modern browser

### High Server Load

- **Enable decision caching**: Cache successful validations
- **Increase cache TTL**: Reduce validation frequency
- **Use persistent cache**: Memcache/Redis instead of APCu

## Future Enhancements

Potential improvements for future versions:

1. **Adaptive Difficulty**: Adjust based on client performance
2. **Challenge Whitelisting**: Skip PoW for known-good clients
3. **Alternative Algorithms**: Support for other hash functions
4. **Distributed Key Management**: Share keys across multiple servers
5. **Analytics**: Track solve times and success rates
6. **CAPTCHA Fallback**: Alternative for incompatible browsers

## References

- [Hashcash](http://www.hashcash.org/) - Original PoW concept for spam prevention
- [Anubis](https://github.com/Xe/x/tree/master/cmd/anubis) - Inspiration for this implementation
- [SubtleCrypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) - Browser crypto API
- [Web Workers](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API) - Background computation
