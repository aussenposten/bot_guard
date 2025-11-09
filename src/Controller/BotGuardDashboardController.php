<?php

namespace Drupal\bot_guard\Controller;

use Drupal\bot_guard\Service\BotGuardMetricsService;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Controller\ControllerBase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Dashboard for Bot Guard blocking statistics and metrics.
 */
class BotGuardDashboardController extends ControllerBase {

  /**
   * The default cache backend.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cache;

  /**
   * The time service.
   *
   * @var \Drupal\Component\Datetime\TimeInterface
   */
  protected $time;

  /**
   * The config factory service.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The metrics service.
   *
   * @var \Drupal\bot_guard\Service\BotGuardMetricsService
   */
  protected $metricsService;

  /**
   * Constructs a BotGuardDashboardController object.
   *
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache
   *   The default cache backend.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   * @param \Drupal\bot_guard\Service\BotGuardMetricsService $metricsService
   *   The metrics service.
   */
  public function __construct(
    CacheBackendInterface $cache,
    TimeInterface $time,
    ConfigFactoryInterface $configFactory,
    BotGuardMetricsService $metricsService
  ) {
    $this->cache = $cache;
    $this->time = $time;
    $this->configFactory = $configFactory;
    $this->metricsService = $metricsService;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container): self {
    return new static(
      $container->get('cache.default'),
      $container->get('datetime.time'),
      $container->get('config.factory'),
      $container->get('bot_guard.metrics'),
    );
  }

  /**
   * Dashboard route callback.
   */
  /**
   * Builds the dashboard page.
   *
   * @return array
   *   A render array for the dashboard page.
   */
  public function dashboard(): array {
    $config = $this->configFactory->get('bot_guard.settings');

    // Initialize metrics early to ensure start time is set.
    $this->metricsService->ensureMetricsInitialized();

    // Check if Bot Guard is enabled.
    $bot_guard_enabled = (bool) $config->get('enabled');

    // Check cache availability
    $cache_backend = $this->getCacheBackendName();
    $use_persistent = $this->usePersistentCache();

    // Load metrics
    if ($use_persistent) {
      // Use Drupal cache backend (Memcache/Redis)
      $blocked_cache = $this->cache->get('bg.blocked.count');
      $allowed_cache = $this->cache->get('bg.allowed.count');
      $challenge_cache = $this->cache->get('bg.challenge.count');
      $start_cache = $this->cache->get('bg.metrics.start');
      $last_cache = $this->cache->get('bg.blocked.last');
      $history_cache = $this->cache->get('bg.history');

      $blocked = $blocked_cache ? $blocked_cache->data : 0;
      $allowed = $allowed_cache ? $allowed_cache->data : 0;
      $challenge_count = $challenge_cache ? $challenge_cache->data : 0;
      $start = $start_cache ? $start_cache->data : $this->time->getRequestTime();
      $last = $last_cache ? $last_cache->data : [];
      $history = $history_cache ? $history_cache->data : [];

      // Collect reason breakdown
      $reasons = $this->collectReasonBreakdownFromCache();
    }
    elseif (function_exists('apcu_fetch')) {
      // APCu fallback
      $blocked = (int) apcu_fetch('bg.blocked.count');
      $allowed = (int) apcu_fetch('bg.allowed.count');
      $challenge_count = (int) apcu_fetch('bg.challenge.count');
      $start = (int) apcu_fetch('bg.metrics.start') ?: $this->time->getRequestTime();
      $last = apcu_fetch('bg.blocked.last') ?: [];
      $history = apcu_fetch('bg.history') ?: [];

      // Collect reason breakdown from APCu
      $reasons = $this->collectReasonBreakdownFromApcu();
    }
    else {
      // No cache available
      $blocked = 0;
      $allowed = 0;
      $challenge_count = 0;
      $start = $this->time->getRequestTime();
      $last = [];
      $history = [];
      $reasons = [];
    }

    // Calculate time since metrics started.
    $time_since = $this->time->getRequestTime() - $start;
    $time_since_str = $this->formatDuration($time_since);

    // Calculate statistics.
    $checked_requests = $blocked + $allowed;
    $percent_blocked = $checked_requests > 0 ? sprintf("%.2f%%", ($blocked / $checked_requests) * 100) : '0%';
    $percent_allowed = $checked_requests > 0 ? sprintf("%.2f%%", ($allowed / $checked_requests) * 100) : '0%';

    // Requests per hour.
    $hours = max(1, $time_since / 3600);
    $requests_per_hour = round($checked_requests / $hours, 1);
    $blocked_per_hour = round($blocked / $hours, 1);

    // Overall statistics table.
    $status_markup = $bot_guard_enabled
      ? [
        '#type' => 'html_tag',
        '#tag' => 'strong',
        '#value' => '✓ ' . $this->t('Enabled'),
        '#attributes' => ['style' => 'color: green;'],
      ]
      : [
        '#type' => 'html_tag',
        '#tag' => 'strong',
        '#value' => '✗ ' . $this->t('Disabled'),
        '#attributes' => ['style' => 'color: red;'],
      ];

    $overall_rows = [
      [
        $this->t('Bot Guard Status'),
        ['data' => $status_markup],
      ],
      [$this->t('Checked Requests'), $checked_requests],
      [$this->t('Blocked Requests'), $blocked],
      [$this->t('Allowed Requests'), $allowed],
      [$this->t('Cookie Challenges Served'), $challenge_count],
      [$this->t('Percent Blocked'), $percent_blocked],
      [$this->t('Percent Allowed'), $percent_allowed],
      [$this->t('Requests per Hour'), $requests_per_hour],
      [$this->t('Blocks per Hour'), $blocked_per_hour],
      [$this->t('Metrics Collection Started'), date('Y-m-d H:i:s', $start)],
      [$this->t('Time Since Start'), $time_since_str],
      [$this->t('Cache Backend'), $cache_backend],
    ];

    // Last blocked request details.
    $last_blocked_rows = [];
    if (!empty($last)) {
      $last_time = isset($last['time']) ? $last['time'] : (isset($last['ts']) ? $last['ts'] : time());
      $last_blocked_rows = [
        [$this->t('IP Address'), $last['ip'] ?? $this->t('Unknown')],
        [$this->t('Path'), $last['path'] ?? $this->t('Unknown')],
        [$this->t('User Agent'), $last['ua'] ?? $this->t('Unknown')],
        [
          $this->t('Block Reason'),
          $this->formatReason($last['reason'] ?? 'unknown'),
        ],
        [$this->t('Timestamp'), date('Y-m-d H:i:s', $last_time)],
        [
          $this->t('Time Ago'),
          $this->formatTimeAgo($this->time->getRequestTime() - $last_time),
        ],
      ];
    }

    // Build render array.
    $build = [
      '#type' => 'container',
      '#attributes' => ['class' => ['bot-guard-dashboard']],
      'title' => [
        '#markup' => '<h1>' . $this->t('Bot Guard Dashboard') . '</h1>',
      ],
    ];

    // Critical warning if Bot Guard is disabled.
    if (!$bot_guard_enabled) {
      $build['disabled_warning'] = [
        '#type' => 'markup',
        '#markup' => '<div class="messages messages--error">' .
          '<h3>⚠ ' . $this->t('Bot Guard is Currently Disabled') . '</h3>' .
          '<p>' . $this->t('Bot protection is <strong>not active</strong>. All requests are being allowed through without any bot checks.') . '</p>' .
          '<p>' . $this->t('To enable bot protection, go to the <a href="@url">Bot Guard configuration page</a> and enable the module.', [
            '@url' => '/admin/config/system/bot-guard',
          ]) . '</p>' .
          '</div>',
        '#weight' => -100,
      ];
    }

    // Warning if no cache is available.
    if ($cache_backend === 'None - Metrics disabled') {
      $build['warning'] = [
        '#type' => 'markup',
        '#markup' => '<div class="messages messages--warning">' .
          '<h3>' . $this->t('No Cache Backend Available') . '</h3>' .
          '<p>' . $this->t('Metrics collection is disabled because no cache backend (Memcache, Redis, or APCu) is available. Please install and configure one of these caching systems to enable Bot Guard metrics.') . '</p>' .
          '<ul>' .
          '<li>' . $this->t('<strong>Recommended:</strong> Install Memcache or Redis module for persistent metrics across server restarts.') . '</li>' .
          '<li>' . $this->t('<strong>Fallback:</strong> Enable APCu PHP extension for basic metrics (lost on PHP-FPM restart).') . '</li>' .
          '</ul>' .
          '</div>',
      ];
    }

    $build['overall'] = [
      '#type' => 'details',
      '#title' => $this->t('Overall Statistics'),
      '#open' => TRUE,
      'table' => [
        '#type' => 'table',
        '#header' => [$this->t('Metric'), $this->t('Value')],
        '#rows' => $overall_rows,
        '#attributes' => ['class' => ['bot-guard-overall-stats']],
      ],
    ];

    // Block types breakdown.
    if (!empty($reasons)) {
      $reason_rows = [];
      $total_blocks = array_sum($reasons);

      // Sort by count descending.
      arsort($reasons);

      foreach ($reasons as $reason => $count) {
        $percentage = $total_blocks > 0 ? sprintf("%.1f%%", ($count / $total_blocks) * 100) : '0%';
        $reason_rows[] = [
          $this->formatReason($reason),
          $count,
          $percentage,
        ];
      }

      $build['reasons'] = [
        '#type' => 'details',
        '#title' => $this->t('Block Types Breakdown'),
        '#open' => TRUE,
        'table' => [
          '#type' => 'table',
          '#header' => [
            $this->t('Block Type'),
            $this->t('Count'),
            $this->t('Percentage'),
          ],
          '#rows' => $reason_rows,
          '#attributes' => ['class' => ['bot-guard-reason-breakdown']],
        ],
      ];
    }

    // Last blocked request.
    if (!empty($last_blocked_rows)) {
      $build['last_blocked'] = [
        '#type' => 'details',
        '#title' => $this->t('Last Blocked Request'),
        '#open' => TRUE,
        'table' => [
          '#type' => 'table',
          '#header' => [$this->t('Field'), $this->t('Value')],
          '#rows' => $last_blocked_rows,
          '#attributes' => ['class' => ['bot-guard-last-blocked']],
        ],
      ];
    }

    // Recent block history (last 20).
    if (!empty($history)) {
      $hist_rows = [];
      $slice = array_slice($history, 0, 20);

      foreach ($slice as $entry) {
        $entry_time = isset($entry['time']) ? $entry['time'] : (isset($entry['ts']) ? $entry['ts'] : time());
        $reason = $entry['reason'] ?? 'unknown';
        
        // Build context-specific details column
        $details = $this->buildDetailsColumn($entry, $reason);
        
        $hist_rows[] = [
          date('Y-m-d H:i:s', $entry_time),
          $entry['ip'] ?? '-',
          $entry['path'] ?? '-',
          ['data' => ['#markup' => $details]],
          $this->formatReason($reason),
        ];
      }

      $build['history'] = [
        '#type' => 'details',
        '#title' => $this->t('Recent Block Events (Last 20)'),
        '#open' => TRUE,
        'table' => [
          '#type' => 'table',
          '#header' => [
            $this->t('Timestamp'),
            $this->t('IP Address'),
            $this->t('Path'),
            $this->t('Details'),
            $this->t('Block Reason'),
          ],
          '#rows' => $hist_rows,
          '#attributes' => ['class' => ['bot-guard-history']],
        ],
      ];
    }

    return $build;
  }

  /**
   * Collect reason breakdown from cache backend.
   *
   * @return array
   *   Array of reason => count.
   */
  protected function collectReasonBreakdownFromCache(): array {
    $reasons = [];

    // Known reason types from BotGuardSubscriber.
    $known_reasons = [
      'cached-block',
      'ua-block',
      'ua-short',
      'no-accept-language',
      'suspicious-resolution',
      'facet-limit',
      'facet-flood-ban',
      'ratelimit',
      'method-block',
    ];

    foreach ($known_reasons as $reason) {
      $key = 'bg.reason.' . $reason;
      $cached = $this->cache->get($key);
      if ($cached && $cached->data > 0) {
        $reasons[$reason] = (int) $cached->data;
      }
    }

    return $reasons;
  }

  /**
   * Collect reason breakdown from APCu.
   *
   * @return array
   *   Array of reason => count.
   */
  protected function collectReasonBreakdownFromApcu(): array {
    $reasons = [];

    // Known reason types from BotGuardSubscriber.
    $known_reasons = [
      'cached-block',
      'ua-block',
      'ua-short',
      'no-accept-language',
      'facet-limit',
      'facet-flood-ban',
      'ratelimit',
      'method-block',
    ];

    foreach ($known_reasons as $reason) {
      $key = 'bg.reason.' . $reason;
      $count = apcu_fetch($key);
      if ($count !== FALSE && $count > 0) {
        $reasons[$reason] = (int) $count;
      }
    }

    return $reasons;
  }

  /**
   * Check if persistent cache is available.
   *
   * @return bool
   *   TRUE if Memcache or Redis is available.
   */
  protected function usePersistentCache(): bool {
    return (
      $this->moduleHandler()->moduleExists('memcache') ||
      $this->moduleHandler()->moduleExists('redis')
    );
  }

  /**
   * Get cache backend name for display.
   *
   * @return string
   *   The cache backend name.
   */
  protected function getCacheBackendName(): string {
    if ($this->moduleHandler()->moduleExists('memcache')) {
      return 'Memcache';
    }
    if ($this->moduleHandler()->moduleExists('redis')) {
      return 'Redis';
    }
    if (function_exists('apcu_fetch')) {
      return 'APCu (fallback)';
    }
    return 'None - Metrics disabled';
  }

  /**
   * Build context-specific details column for history table.
   *
   * @param array $entry
   *   The history entry.
   * @param string $reason
   *   The block reason.
   *
   * @return string
   *   HTML markup for details column.
   */
  protected function buildDetailsColumn(array $entry, string $reason): string {
    $ua = $entry['ua'] ?? '-';
    $ua_short = mb_strlen($ua) > 50 ? mb_substr($ua, 0, 47) . '...' : $ua;
    
    switch ($reason) {
      case 'suspicious-resolution':
        // Show screen resolution + UA
        $resolution = $entry['screen_resolution'] ?? 'unknown';
        return '<strong>Resolution:</strong> ' . htmlspecialchars($resolution, ENT_QUOTES) . '<br>' .
               '<span style="font-size:0.9em" title="' . htmlspecialchars($ua, ENT_QUOTES) . '">' . 
               htmlspecialchars($ua_short, ENT_QUOTES) . '</span>';
        
      case 'ua-block':
      case 'ua-short':
        // Show full UA (most important for these reasons)
        return '<span title="' . htmlspecialchars($ua, ENT_QUOTES) . '">' . 
               htmlspecialchars($ua_short, ENT_QUOTES) . '</span>';
        
      case 'facet-limit':
      case 'facet-flood-ban':
        // Show facet params if available
        if (!empty($entry['facet_params'])) {
          $params = is_array($entry['facet_params']) ? implode(', ', $entry['facet_params']) : $entry['facet_params'];
          $params_short = mb_strlen($params) > 50 ? mb_substr($params, 0, 47) . '...' : $params;
          return '<strong>Facets:</strong> ' . htmlspecialchars($params_short, ENT_QUOTES) . '<br>' .
                 '<span style="font-size:0.9em" title="' . htmlspecialchars($ua, ENT_QUOTES) . '">' . 
                 htmlspecialchars($ua_short, ENT_QUOTES) . '</span>';
        }
        return '<span title="' . htmlspecialchars($ua, ENT_QUOTES) . '">' . 
               htmlspecialchars($ua_short, ENT_QUOTES) . '</span>';
        
      default:
        // Default: show UA
        return '<span title="' . htmlspecialchars($ua, ENT_QUOTES) . '">' . 
               htmlspecialchars($ua_short, ENT_QUOTES) . '</span>';
    }
  }

  /**
   * Format a block reason for display.
   *
   * @param string $reason
   *   The reason code.
   *
   * @return \Drupal\Core\StringTranslation\TranslatableMarkup
   *   Formatted reason.
   */
  protected function formatReason(string $reason) {
    $map = [
      'cached-block' => $this->t('Cached Block Decision'),
      'ua-block' => $this->t('User Agent Blocked'),
      'ua-short' => $this->t('User Agent Too Short'),
      'no-accept-language' => $this->t('Missing Accept-Language Header'),
      'suspicious-resolution' => $this->t('Suspicious Screen Resolution'),
      'facet-limit' => $this->t('Facet Parameter Limit Exceeded'),
      'facet-flood-ban' => $this->t('Facet Flood Pattern Detected'),
      'ratelimit' => $this->t('Rate Limit Exceeded'),
      'method-block' => $this->t('HTTP Method Block'),
    ];

    return $map[$reason] ?? $this->t('Unknown (@reason)', ['@reason' => $reason]);
  }

  /**
   * Format duration in human-readable format.
   *
   * @param int $seconds
   *   Duration in seconds.
   *
   * @return string
   *   Formatted duration.
   */
  protected function formatDuration(int $seconds): string {
    if ($seconds < 60) {
      return $seconds . ' ' . $this->t('seconds');
    }
    elseif ($seconds < 3600) {
      return round($seconds / 60, 1) . ' ' . $this->t('minutes');
    }
    elseif ($seconds < 86400) {
      return round($seconds / 3600, 1) . ' ' . $this->t('hours');
    }
    else {
      return round($seconds / 86400, 1) . ' ' . $this->t('days');
    }
  }

  /**
   * Format time ago in human-readable format.
   *
   * @param int $seconds
   *   Seconds ago.
   *
   * @return string
   *   Formatted time ago.
   */
  protected function formatTimeAgo(int $seconds): string {
    if ($seconds < 60) {
      return $this->t('@count seconds ago', ['@count' => $seconds]);
    }
    elseif ($seconds < 3600) {
      return $this->t('@count minutes ago', ['@count' => round($seconds / 60)]);
    }
    elseif ($seconds < 86400) {
      return $this->t('@count hours ago', ['@count' => round($seconds / 3600)]);
    }
    else {
      return $this->t('@count days ago', ['@count' => round($seconds / 86400)]);
    }
  }

}
