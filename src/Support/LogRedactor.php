<?php

namespace Cycoslave\Proxmox\Support;

use Cycoslave\Proxmox\Exceptions\ApiException;
use Cycoslave\Proxmox\Exceptions\ConnectionException;

/**
 * LogRedactor — builds log context that is useful for debugging without
 * echoing endpoint configuration or raw network diagnostics.
 *
 * LPX-006 (CWE-532): log entries previously carried the configured host
 * verbatim and the raw exception message (curl text with resolved IPs,
 * hostnames, ports and local path fragments). Logs now carry:
 *   - a stable, non-reversible endpoint identifier (operators can match it
 *     by hashing their own configured host:port), and
 *   - a categorised error (category, exception class, code / HTTP status,
 *     curl errno for network failures) instead of the raw message.
 */
final class LogRedactor
{
    /**
     * Stable connection identifier: "pve-" + first 12 hex chars of
     * sha256("{host}:{port}"). Same endpoint -> same id across processes.
     */
    public static function endpointId(string $host, int $port): string
    {
        return 'pve-' . substr(hash('sha256', strtolower($host) . ':' . $port), 0, 12);
    }

    /**
     * Categorised, redacted context for a caught exception. Never includes
     * $e->getMessage().
     *
     * @return array{category: string, error_class: string, error_code: int|string, http_status?: int}
     */
    public static function exceptionContext(\Throwable $e): array
    {
        $context = [
            'category'    => match (true) {
                $e instanceof ConnectionException => 'network',
                $e instanceof ApiException        => 'api',
                default                           => 'internal',
            },
            'error_class' => (new \ReflectionClass($e))->getShortName(),
            // ConnectionException carries the curl errno as its code.
            'error_code'  => $e->getCode(),
        ];

        if ($e instanceof ApiException) {
            $context['http_status'] = $e->getStatusCode();
        }

        return $context;
    }
}
