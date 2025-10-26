# Bot Guard

## Introduction

Bot Guard is a Drupal module designed to provide a lightweight, high-performance defense against common bots, scrapers, and other forms of malicious traffic. It operates at the very beginning of the request lifecycle to block unwanted requests before they can consume significant server resources.

## How It Works

Bot Guard inspects each incoming request and processes it through a sequence of checks. This multi-layered approach is highly efficient, as it starts with the computationally cheapest checks first.

1.  **Bypass & Caching:** Checks for allowed IPs and previously cached decisions to quickly pass legitimate traffic.
2.  **Signatures & Heuristics:** Analyzes User-Agent strings and request headers for patterns commonly associated with bots.
3.  **Behavioral Checks:** Applies rate limiting and serves a JavaScript cookie challenge to filter out automated clients that cannot process JavaScript.
4.  **Integration Checks:** Includes specialized protections, such as for the Facets module, to prevent abuse.

A request is blocked as soon as it fails one of these checks. If it passes all of them, it is allowed to proceed to Drupal.

## Features

- **High-Performance Defense:** Uses APCu for fast, in-memory caching and rate limiting to minimize performance impact.
- **IP & User-Agent Filtering:** Supports allow-lists for IPs (with CIDR notation) and allow/block-lists for User-Agent strings (using regex).
- **Heuristic Analysis:** Blocks requests with suspicious characteristics common to low-quality bots.
- **JavaScript Cookie Challenge:** A stateless, signed cookie challenge effectively filters out bots that don't execute JavaScript.
- **Facet Protection:** Prevents denial-of-service attacks via excessive facet parameter combinations.
- **Statistics Dashboard:** A real-time dashboard to monitor traffic and analyze block reasons.

## Requirements

- Drupal 9, 10, or 11.
- **APCu PHP Extension:** **Required** for core functionality.
- **(Optional) Redis or Memcache:** Recommended for persistent metrics across server restarts.

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

## Dashboard

View real-time statistics at **Administration > Reports > Bot Guard** (`/admin/reports/bot-guard`). The dashboard provides an overview of blocked vs. allowed requests, a breakdown of block reasons, and a history of recent block events.
