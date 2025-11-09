# Bot Guard

## Introduction

Bot Guard is a Drupal module designed to provide a lightweight, high-performance defense against common bots, scrapers, and other forms of malicious traffic. It operates at the very beginning of the request lifecycle to block unwanted requests before they can consume significant server resources.

## How It Works

Bot Guard inspects each incoming request and processes it through a sequence of checks. This multi-layered approach is highly efficient, as it starts with the computationally cheapest checks first.

1.  **Bypass & Caching:** Checks for allowed IPs and previously cached decisions to quickly pass legitimate traffic.
2.  **Signatures & Heuristics:** Analyzes User-Agent strings and request headers for patterns commonly associated with bots.
3.  **Behavioral Checks:** Applies rate limiting and serves a JavaScript cookie challenge to filter out automated clients that cannot process JavaScript.
4.  **Proof-of-Work Validation:** When enabled, requires clients to solve a SHA-256 computational puzzle, making automated scraping expensive while having minimal impact on legitimate users.
5.  **Screen Resolution Validation:** Checks that the reported screen resolution matches the User-Agent device type, catching headless browsers and spoofed clients.
6.  **Integration Checks:** Includes specialized protections, such as for the Facets module, to prevent abuse.

A request is blocked as soon as it fails one of these checks. If it passes all of them, it is allowed to proceed to Drupal.

### Challenge Flow

When a client without a valid challenge cookie makes a GET/HEAD request:

1. **Server generates challenge:** Creates a unique SHA-256 challenge based on IP, User-Agent, timestamp, and server salt
2. **Client receives challenge page:** A minimal HTML page with embedded JavaScript and Web Worker
3. **Proof-of-Work computation:** Web Worker iteratively computes `SHA-256(challenge + nonce)` until finding a hash with the required leading zeros
4. **Cookie creation:** Client creates a signed cookie containing:
   - Timestamp and expiration
   - Screen resolution
   - Proof-of-work solution (challenge, nonce, hash)
5. **Page reload:** Client reloads with the valid cookie
6. **Server validation:** Verifies signature, expiration, proof-of-work, and screen resolution
7. **Access granted:** Request proceeds to Drupal

This multi-factor validation ensures that only genuine browsers with JavaScript support and computational capability can access the site.

## Features

- **High-Performance Defense:** Uses APCu for fast, in-memory caching and rate limiting to minimize performance impact.
- **IP & User-Agent Filtering:** Supports allow-lists for IPs (with CIDR notation) and allow/block-lists for User-Agent strings (using regex).
- **Heuristic Analysis:** Blocks requests with suspicious characteristics common to low-quality bots.
- **JavaScript Cookie Challenge:** A stateless, signed cookie challenge effectively filters out bots that don't execute JavaScript.
- **Proof-of-Work Challenge:** Anubis-style SHA-256 proof-of-work system that requires clients to solve computational puzzles, making automated scraping prohibitively expensive while having minimal impact on legitimate users.
- **Screen Resolution Check:** Validates that screen resolutions match the reported User-Agent (e.g., desktop UA should have desktop resolution), catching headless browsers and spoofed clients.
- **Facet Protection:** Prevents denial-of-service attacks via excessive facet parameter combinations.
- **Statistics Dashboard:** A real-time dashboard to monitor traffic and analyze block reasons.

## Requirements

### Server Requirements
- Drupal 9, 10, or 11
- **APCu PHP Extension:** **Required** for core functionality
- **(Optional) Redis or Memcache:** Recommended for persistent metrics across server restarts

### Browser Requirements (for Proof-of-Work)
When proof-of-work is enabled, clients need:
- **Web Workers:** For background computation
- **SubtleCrypto API:** For SHA-256 hashing
- **JavaScript ES6+:** Async/await, arrow functions

**Supported Browsers:**
- ✅ Chrome/Edge 37+
- ✅ Firefox 34+
- ✅ Safari 11.1+
- ✅ Opera 24+
- ❌ Internet Explorer (no SubtleCrypto support)

**Note:** If a browser doesn't support these features, the challenge will fail and the user will see an error message. Consider disabling proof-of-work if you need to support older browsers.

## Installation

Install the module via Composer:
```bash
composer require drupal/bot_guard
```
Then, enable the module at `/admin/modules` or with Drush:
```bash
drush en bot_guard
```

## Configuration

All features are configurable at **Administration > Configuration > System > Bot Guard** (`/admin/config/system/bot-guard`).

### Key Configuration Options

#### Cookie Challenge
- **Enable cookie challenge:** Toggle JavaScript-based cookie challenge
- **Cookie name:** Name of the challenge cookie (default: `bg_chal`)
- **Cookie TTL:** How long the cookie remains valid (default: 24 hours)

#### Proof-of-Work Challenge
- **Enable proof-of-work:** Toggle Anubis-style computational challenge
- **Difficulty:** Number of leading zeros required in SHA-256 hash (3-8, default: 5)
  - **3-4:** Very fast (< 1 second) - suitable for high-traffic sites
  - **5-6:** Moderate (1-10 seconds) - recommended default
  - **7-8:** Slow (10+ seconds) - maximum protection, may impact UX
- **Maximum iterations:** Safety limit to prevent infinite loops (default: 10M)
- **Client timeout:** Maximum time allowed for solving (default: 30 seconds)

**Note:** The proof-of-work challenge runs in a Web Worker, so it doesn't block the browser UI. See `PROOF_OF_WORK.md` for detailed documentation.

#### Screen Resolution Check
- **Enable screen resolution check:** Validates that screen resolution matches User-Agent
  - Blocks desktop UAs with mobile resolutions
  - Blocks mobile UAs with desktop resolutions
  - Catches headless browsers with suspicious resolutions (e.g., 800x600)

#### Rate Limiting
- **Rate limit hits:** Maximum requests per time window (default: 20)
- **Rate window:** Time window in seconds (default: 10)

#### IP & Path Allow-lists
- **IP Allow-list:** IPs/CIDR ranges that bypass all checks (e.g., `192.168.0.0/16`)
- **Path Allow-list:** URL paths that bypass all checks (e.g., `/api/webhook`)

#### User-Agent Filtering
- **Allow-list:** Regex patterns for legitimate bots (e.g., `Googlebot`, `Bingbot`)
- **Block-list:** Regex patterns for unwanted bots (e.g., `GPTBot`, `ClaudeBot`, `curl`)

## Dashboard

View real-time statistics at **Administration > Reports > Bot Guard** (`/admin/reports/bot-guard`). The dashboard provides:

- **Overall Statistics:** Total requests, blocks, allows, challenge success rate
- **Block Types Breakdown:** Detailed breakdown by reason (UA blocks, rate limits, failed challenges, etc.)
- **Last Blocked Request:** Details of the most recent block
- **Recent Block Events:** History of the last 20 blocked requests with context-specific details

### Block Reasons

The dashboard tracks various block reasons:
- **User Agent Blocked:** Matched block-list pattern
- **Challenge Failed:** Invalid or expired cookie (includes failed proof-of-work)
- **Suspicious Screen Resolution:** Resolution doesn't match User-Agent
- **Rate Limit Exceeded:** Too many requests in time window
- **Facet Flood Pattern Detected:** Excessive unique facet combinations
- And more...

## Best Practices

### Proof-of-Work Configuration

**For High-Traffic Sites:**
- Start with difficulty **4** to minimize impact on legitimate users
- Monitor "Challenge Failed" metrics in the dashboard
- Gradually increase difficulty if bot traffic persists

**For Low-Traffic Sites:**
- Use difficulty **5-6** for stronger protection
- Higher difficulty has minimal impact when traffic is low

**For Maximum Protection:**
- Use difficulty **7** (expect 10-30 second solve times)
- Only recommended if bot attacks are severe
- Consider adding IP allow-list for known legitimate users

### Screen Resolution Check

The screen resolution check is highly effective at catching:
- **Headless browsers** (Puppeteer, Selenium) with default resolutions
- **Spoofed User-Agents** (mobile UA with desktop resolution)
- **Automated tools** that don't properly emulate device characteristics

### Allow-lists

Always add to IP allow-list:
- Your own office/home IPs
- Monitoring services (UptimeRobot, etc.)
- Known API clients
- CI/CD systems

Always add to UA allow-list:
- Legitimate search engine bots (Googlebot, Bingbot)
- Social media crawlers (if you want social sharing previews)
- Monitoring bots

### Performance Optimization

1. **Enable Decision Caching:** Caches allow/block decisions to reduce repeated checks
2. **Use Persistent Cache:** Install Redis or Memcache for metrics that survive server restarts
3. **Tune Rate Limiting:** Adjust rate limits based on your traffic patterns
4. **Monitor Dashboard:** Regularly check for false positives

### Troubleshooting

**Legitimate Users Being Blocked:**
1. Check dashboard for block reason
2. Add their IP to allow-list temporarily
3. Adjust configuration (lower PoW difficulty, disable resolution check, etc.)
4. Check if they're using an outdated browser (for PoW)

**High "Challenge Failed" Count:**
- May indicate bot attacks (good!)
- Or configuration too strict (check if legitimate users affected)
- Review recent block events in dashboard for patterns

**No Metrics Showing:**
- Ensure APCu extension is installed and enabled
- Check PHP configuration: `php -i | grep apcu`
- Consider installing Redis/Memcache for persistent metrics

## Advanced Topics

### Proof-of-Work Deep Dive

For detailed information about the proof-of-work implementation, including:
- How the challenge generation works
- Security considerations
- Performance impact analysis
- Browser compatibility details
- Comparison to Anubis

See the dedicated documentation: **[PROOF_OF_WORK.md](PROOF_OF_WORK.md)**
