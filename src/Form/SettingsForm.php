<?php

namespace Drupal\bot_guard\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

class SettingsForm extends ConfigFormBase {

  /**
   * The module handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * Constructs a SettingsForm object.
   *
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler service.
   */
  public function __construct(ModuleHandlerInterface $module_handler) {
    $this->moduleHandler = $module_handler;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('module_handler')
    );
  }

  protected function getEditableConfigNames(): array {
    return ['bot_guard.settings'];
  }

  public function getFormId(): string {
    return 'bot_guard_settings_form';
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('bot_guard.settings');

    $form['enabled'] = [
      '#type' => 'checkbox',
      '#title' => 'Enable Bot Guard',
      '#default_value' => $config->get('enabled') ?? TRUE,
    ];

    $form['allow_bots'] = [
      '#type' => 'textarea',
      '#title' => 'Allow-list (regex, one per line)',
      '#default_value' => $config->get('allow_bots') ?? "Googlebot\nBingbot\nDuckDuckBot\nApplebot\nUptimeRobot\nUptime-Kuma",
      '#description' => 'UA patterns allowed.',
    ];

    $form['block_bots'] = [
      '#type' => 'textarea',
      '#title' => 'Block-list (regex, one per line)',
      '#default_value' => $config->get('block_bots') ??
        "GPTBot\nPerplexity(Bot|Crawler)\nClaudeBot\nBytespider\nAmazonbot\nMeta-ExternalAgent\nGoogle-Extended\n" .
        "AhrefsBot\nSemrushBot\nMJ12bot\nDotBot\nDataForSeoBot\nspbot\nia_archiver\nScreaming Frog\nSeobility\nSeznamBot\n" .
        "curl\nwget\npython-requests\nhttpclient\nGo-http-client\nlibwww-perl\nJava/\nRuby\nPHP/\nnode-fetch\naiohttp\nokhttp\n" .
        "(?<!Google)bot\ncrawler\nspider\nscraper",
      '#description' => 'UA patterns to block.',
    ];

    $form['language_gate_paths'] = [
      '#type' => 'textarea',
      '#title' => 'Language-gate paths (regex per line)',
      '#default_value' => $config->get('language_gate_paths') ?? "",
      '#description' => 'Optional. Example: ^/vorgaenge',
    ];

    $form['language_allow'] = [
      '#type' => 'textfield',
      '#title' => 'Allowed Accept-Language regex',
      '#default_value' => $config->get('language_allow') ?? '\bde(-(DE|AT|CH))?\b',
    ];

    // Rate Limiting.
    $form['rate_limiting'] = [
      '#type' => 'details',
      '#title' => 'Rate Limiting',
      '#open' => TRUE,
    ];
    $form['rate_limiting']['rate_limit'] = [
      '#type' => 'number',
      '#title' => 'Rate-limit hits (per window)',
      '#default_value' => $config->get('rate_limit') ?? 20,
      '#min' => 0,
      '#description' => '0 = disabled. Applies to all requests from same IP.',
    ];
    $form['rate_limiting']['rate_window'] = [
      '#type' => 'number',
      '#title' => 'Rate-limit window (seconds)',
      '#default_value' => $config->get('rate_window') ?? 10,
      '#min' => 1,
    ];

    // Error Response Configuration.
    $form['error_responses'] = [
      '#type' => 'details',
      '#title' => 'Error Response Configuration',
      '#open' => TRUE,
      '#description' => 'Centralized configuration for all block responses.',
    ];
    $form['error_responses']['block_status_code'] = [
      '#type' => 'select',
      '#title' => 'Default block status code',
      '#options' => [
        '403' => '403 Forbidden',
        '404' => '404 Not Found',
        '410' => '410 Gone',
        '429' => '429 Too Many Requests',
      ],
      '#default_value' => $config->get('block_status_code') ?? '404',
      '#description' => 'HTTP status code for blocked requests (UA blocks, language gate, etc.).',
    ];
    $form['error_responses']['block_message'] = [
      '#type' => 'textarea',
      '#title' => 'Default block message',
      '#default_value' => $config->get('block_message') ?? '<h1>Access Denied</h1><p>Your request was blocked.</p>',
      '#description' => 'HTML message for blocked requests.',
      '#rows' => 3,
    ];
    $form['error_responses']['ratelimit_status_code'] = [
      '#type' => 'select',
      '#title' => 'Rate limit status code',
      '#options' => [
        '403' => '403 Forbidden',
        '429' => '429 Too Many Requests',
        '503' => '503 Service Unavailable',
      ],
      '#default_value' => $config->get('ratelimit_status_code') ?? '429',
      '#description' => 'HTTP status code for rate limit violations.',
    ];
    $form['error_responses']['ratelimit_message'] = [
      '#type' => 'textarea',
      '#title' => 'Rate limit message',
      '#default_value' => $config->get('ratelimit_message') ?? '<h1>Too Many Requests</h1><p>Please slow down.</p>',
      '#description' => 'HTML message for rate limit violations.',
      '#rows' => 3,
    ];
    $form['error_responses']['ratelimit_retry_after'] = [
      '#type' => 'number',
      '#title' => 'Retry-After header (seconds)',
      '#default_value' => $config->get('ratelimit_retry_after') ?? 30,
      '#min' => 1,
      '#description' => 'Value for Retry-After header in rate limit responses.',
    ];

    // Cookie Challenge.
    $form['cookie_challenge'] = [
      '#type' => 'details',
      '#title' => 'Cookie Challenge',
      '#open' => TRUE,
    ];
    $form['cookie_challenge']['challenge_enabled'] = [
      '#type' => 'checkbox',
      '#title' => 'Enable cookie challenge',
      '#default_value' => $config->get('challenge_enabled') ?? TRUE,
      '#description' => 'Serves a tiny HTML/JS page to set a signed cookie, then reloads.',
    ];
    $form['cookie_challenge']['cookie_name'] = [
      '#type' => 'textfield',
      '#title' => 'Cookie name',
      '#default_value' => $config->get('cookie_name') ?? 'bg_chal',
    ];
    $form['cookie_challenge']['cookie_ttl'] = [
      '#type' => 'number',
      '#title' => 'Cookie TTL (seconds)',
      '#default_value' => $config->get('cookie_ttl') ?? 86400,
      '#min' => 60,
    ];

    // Decision Cache.
    $form['decision_cache'] = [
      '#type' => 'details',
      '#title' => 'Decision Cache',
      '#open' => TRUE,
    ];
    $form['decision_cache']['cache_enabled'] = [
      '#type' => 'checkbox',
      '#title' => 'Enable decision caching (APCu)',
      '#default_value' => $config->get('cache_enabled') ?? TRUE,
      '#description' => 'Caches allow/block decisions by IP+UA+path bucket.',
    ];
    $form['decision_cache']['cache_ttl'] = [
      '#type' => 'number',
      '#title' => 'Decision cache TTL (seconds)',
      '#default_value' => $config->get('cache_ttl') ?? 300,
      '#min' => 10,
    ];

    // Facet protections - only show if Facet module is installed.
    if ($this->moduleHandler->moduleExists('facets')) {
      $form['facet'] = [
        '#type' => 'details',
        '#title' => 'Facet Bot Protection',
        '#open' => TRUE,
      ];
      $form['facet']['facet_enabled'] = [
        '#type' => 'checkbox',
        '#title' => 'Enable facet parameter limit',
        '#default_value' => $config->get('facet_enabled') ?? TRUE,
      ];
      $form['facet']['facet_limit'] = [
        '#type' => 'number',
        '#title' => 'Facet parameter limit',
        '#default_value' => $config->get('facet_limit') ?? 5,
        '#min' => 1,
        '#description' => 'Maximum allowed count of f[] parameters before request is blocked.',
      ];

      // Facet Flood Pattern Detection.
      $form['facet']['facet_flood_enabled'] = [
        '#type' => 'checkbox',
        '#title' => 'Enable facet flood detection',
        '#default_value' => $config->get('facet_flood_enabled') ?? TRUE,
        '#description' => 'Detect and block IPs that crawl many unique facet combinations.',
      ];
      $form['facet']['facet_flood_threshold'] = [
        '#type' => 'number',
        '#title' => 'Facet flood threshold (unique combinations per window)',
        '#default_value' => $config->get('facet_flood_threshold') ?? 20,
        '#min' => 5,
        '#description' => 'Number of unique facet combinations before IP is temporarily banned.',
      ];
      $form['facet']['facet_flood_window'] = [
        '#type' => 'number',
        '#title' => 'Facet flood window (seconds)',
        '#default_value' => $config->get('facet_flood_window') ?? 600,
        '#min' => 60,
        '#description' => 'Time window for counting unique facet combinations.',
      ];
      $form['facet']['facet_flood_ban'] = [
        '#type' => 'number',
        '#title' => 'Temporary IP ban duration (seconds)',
        '#default_value' => $config->get('facet_flood_ban') ?? 1800,
        '#min' => 300,
        '#description' => 'How long to ban IPs that exceed the flood threshold.',
      ];
    }

    return parent::buildForm($form, $form_state);
  }

  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $config = $this->config('bot_guard.settings')
      ->set('enabled', $form_state->getValue('enabled'))
      ->set('allow_bots', $form_state->getValue('allow_bots'))
      ->set('block_bots', $form_state->getValue('block_bots'))
      ->set('language_gate_paths', $form_state->getValue('language_gate_paths'))
      ->set('language_allow', $form_state->getValue('language_allow'))
      ->set('rate_limit', $form_state->getValue('rate_limit'))
      ->set('rate_window', $form_state->getValue('rate_window'))
      ->set('challenge_enabled', $form_state->getValue('challenge_enabled'))
      ->set('cookie_name', $form_state->getValue('cookie_name'))
      ->set('cookie_ttl', $form_state->getValue('cookie_ttl'))
      ->set('cache_enabled', $form_state->getValue('cache_enabled'))
      ->set('cache_ttl', $form_state->getValue('cache_ttl'))
      ->set('block_status_code', $form_state->getValue('block_status_code'))
      ->set('block_message', $form_state->getValue('block_message'))
      ->set('ratelimit_status_code', $form_state->getValue('ratelimit_status_code'))
      ->set('ratelimit_message', $form_state->getValue('ratelimit_message'))
      ->set('ratelimit_retry_after', $form_state->getValue('ratelimit_retry_after'));

    // Only save facet settings if Facet module is installed.
    if ($this->moduleHandler->moduleExists('facets')) {
      $config
        ->set('facet_enabled', $form_state->getValue('facet_enabled'))
        ->set('facet_limit', $form_state->getValue('facet_limit'))
        ->set('facet_flood_enabled', $form_state->getValue('facet_flood_enabled'))
        ->set('facet_flood_threshold', $form_state->getValue('facet_flood_threshold'))
        ->set('facet_flood_window', $form_state->getValue('facet_flood_window'))
        ->set('facet_flood_ban', $form_state->getValue('facet_flood_ban'));
    }

    $config->save();

    parent::submitForm($form, $form_state);
  }
}
