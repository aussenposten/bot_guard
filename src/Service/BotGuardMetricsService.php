<?php

namespace Drupal\bot_guard\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Cache\CacheBackendInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;

/**
 * Service for Bot Guard metrics initialization and management.
 */
class BotGuardMetricsService {

  /**
   * The cache backend.
   *
   * @var \Drupal\Core\Cache\CacheBackendInterface
   */
  protected $cacheBackend;

  /**
   * The time service.
   *
   * @var \Drupal\Component\Datetime\TimeInterface
   */
  protected $time;

  /**
   * The module handler service.
   *
   * @var \Drupal\Core\Extension\ModuleHandlerInterface
   */
  protected $moduleHandler;

  /**
   * Constructs a BotGuardMetricsService object.
   *
   * @param \Drupal\Core\Cache\CacheBackendInterface $cache_backend
   *   The cache backend.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $module_handler
   *   The module handler service.
   */
  public function __construct(
    CacheBackendInterface $cache_backend,
    TimeInterface $time,
    ModuleHandlerInterface $module_handler
  ) {
    $this->cacheBackend = $cache_backend;
    $this->time = $time;
    $this->moduleHandler = $module_handler;
  }

  /**
   * Ensures that metrics are initialized in the cache.
   *
   * This method checks if the cache is available and initializes
   * the metrics start time and counters if they don't exist yet.
   * It is safe to call this method multiple times.
   */
  public function ensureMetricsInitialized(): void {
    if (!$this->isCacheAvailable()) {
      return;
    }

    if ($this->usePersistentCache()) {
      // Use Drupal cache backend (Memcache/Redis).
      if (!$this->cacheBackend->get('bg.metrics.start')) {
        $currentTime = $this->time->getRequestTime();
        $this->cacheBackend->set('bg.metrics.start', $currentTime);

        // Also initialize counters to prevent null checks elsewhere.
        $this->cacheBackend->set('bg.blocked.count', 0);
        $this->cacheBackend->set('bg.allowed.count', 0);
        $this->cacheBackend->set('bg.challenge.count', 0);
        $this->cacheBackend->set('bg.ua.stats', []);
      }
    }
    elseif (function_exists('apcu_store') && !apcu_exists('bg.metrics.start')) {
      // APCu fallback.
      apcu_store('bg.metrics.start', time(), 0);

      // Also initialize counters.
      if (!apcu_exists('bg.blocked.count')) {
        apcu_store('bg.blocked.count', 0, 0);
      }
      if (!apcu_exists('bg.allowed.count')) {
        apcu_store('bg.allowed.count', 0, 0);
      }
      if (!apcu_exists('bg.challenge.count')) {
        apcu_store('bg.challenge.count', 0, 0);
      }
      if (!apcu_exists('bg.ua.stats')) {
        apcu_store('bg.ua.stats', [], 0);
      }
    }
  }

  /**
   * Check if cache is available (Memcache/Redis or APCu fallback).
   *
   * @return bool
   *   TRUE if cache is available.
   */
  private function isCacheAvailable(): bool {
    return (
      $this->moduleHandler->moduleExists('memcache') ||
      $this->moduleHandler->moduleExists('redis') ||
      function_exists('apcu_fetch')
    );
  }

  /**
   * Check if we should use persistent cache (Memcache/Redis).
   *
   * @return bool
   *   TRUE if persistent cache is available.
   */
  private function usePersistentCache(): bool {
    return (
      $this->moduleHandler->moduleExists('memcache') ||
      $this->moduleHandler->moduleExists('redis')
    );
  }

}
