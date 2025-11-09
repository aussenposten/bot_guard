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

## Features

- **High-Performance Defense:** Uses APCu for fast, in-memory caching and rate limiting to minimize performance impact.
- **IP & User-Agent Filtering:** Supports allow-lists for IPs (with CIDR notation) and allow/block-lists for User-Agent strings (using regex).
- **Heuristic Analysis:** Blocks requests with suspicious characteristics common to low-quality bots.
- **JavaScript Cookie Challenge:** A stateless, signed cookie challenge effectively filters out bots that don't execute JavaScript.
- **Proof-of-Work Challenge:** SHA-256 computational challenge that makes automated scraping expensive while having minimal impact on legitimate users.
- **Screen Resolution Check:** Detects headless browsers and automation tools by identifying obviously fake resolutions, impossible aspect ratios, and common automation defaults (800x600, 1280x720).
- **Facet Protection:** Prevents denial-of-service attacks via excessive facet parameter combinations.
- **Statistics Dashboard:** A real-time dashboard to monitor traffic and analyze block reasons.

## Requirements

### Server Requirements
- Drupal 9, 10, or 11
- **APCu PHP Extension:** **Required** for core functionality
- **(Optional) Redis or Memcache:** Recommended for persistent metrics across server restarts

### Browser Requirements (for Proof-of-Work)
When proof-of-work is enabled, clients need modern browser features (Web Workers, SubtleCrypto API). Supported: Chrome 37+, Firefox 34+, Safari 11.1+, Opera 24+. Internet Explorer is not supported. See [PROOF_OF_WORK.md](PROOF_OF_WORK.md) for details.

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
- **Enable proof-of-work:** Toggle computational challenge
- **Difficulty:** Number of leading zeros required in SHA-256 hash (default: 3)
  - **3:** ~0.1-0.5s - **recommended for most sites**
  - **4:** ~1-3s - balanced security/UX
  - **5:** ~10-30s - maximum protection, impacts UX
  - **6+:** Not recommended (often triggers timeout)
- **Maximum iterations:** Safety limit (default: 10M)
- **Client timeout:** Maximum solve time (default: 60s)

**Note:** Difficulty scales exponentially (~16x per level). See [PROOF_OF_WORK.md](PROOF_OF_WORK.md) for detailed documentation.

#### Screen Resolution Check
- **Enable screen resolution check:** Detects obviously fake resolutions and headless browsers
  - Blocks extremely unusual resolutions (< 320px or > 4000px)
  - Blocks impossible aspect ratios (> 3.0)
  - Catches headless browser defaults (800x600, 1280x720)
  - Detects phone UAs with desktop resolutions

**Note:** iPads with Safari report as "Macintosh" (desktop) in their User-Agent, so the check is permissive with tablet-sized resolutions to avoid false positives. The focus is on catching automation tools rather than precise device type validation.

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

- **Block Token Decoder:** Troubleshoot false positives by decoding reference tokens from error pages
- **Overall Statistics:** Total requests, blocks, allows, challenge success rate
- **Block Types Breakdown:** Detailed breakdown by reason (UA blocks, rate limits, failed challenges, etc.)
- **Last Blocked Request:** Details of the most recent block
- **Recent Block Events:** History of the last 20 blocked requests with context-specific details

### Troubleshooting False Positives

When a user is blocked, they receive an error page with a **reference token** like:

```
Access Denied
Your request was blocked.

Reference: BG1a2bC3d4E5f6g7H8i9J0k1L2m3N4o5P6q7R8s9T0
```

To troubleshoot:

1. Copy the reference token from the error page
2. Go to the Bot Guard Dashboard
3. Paste the token into the "Block Token Decoder" section
4. Click "Decode" to see full details:
   - Block reason
   - IP address
   - User-Agent
   - Path
   - Screen resolution (if available)
   - Cookie information (if available)
   - Timestamp

This allows you to quickly identify why a legitimate user was blocked and adjust the configuration accordingly.

### Block Reasons

The dashboard tracks various block reasons:
- **User Agent Blocked:** Matched block-list pattern
- **Challenge Failed:** Invalid or expired cookie (includes failed proof-of-work)
- **Suspicious Screen Resolution:** Resolution doesn't match User-Agent
- **Rate Limit Exceeded:** Too many requests in time window
- **Facet Flood Pattern Detected:** Excessive unique facet combinations
- And more...

### Troubleshooting

**Legitimate Users Being Blocked:**
1. Get the reference token from the error page
2. Decode it in the dashboard's **Block Token Decoder**
3. Review the block reason:
   - **UA Block:** Adjust allow-list or block patterns
   - **Challenge Failed:** Lower PoW difficulty or check JavaScript support
   - **Suspicious Resolution:** May be false positive, consider disabling
   - **Rate Limit:** Add IP to allow-list
4. Adjust configuration based on findings

**High "Challenge Failed" Count:**
- May indicate bot attacks (expected behavior)
- Or difficulty too high (check if legitimate users affected)
- Review recent block events for patterns

**No Metrics Showing:**
- Ensure APCu is installed: `php -i | grep apcu`
- Consider Redis/Memcache for persistent metrics
