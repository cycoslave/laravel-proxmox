<?php

namespace Cycoslave\Proxmox\Support;

use Illuminate\Support\Facades\Log;

/**
 * SafeLog — logging that never throws.
 *
 * F-09 (CWE-613 / robustness): the package is usable without a booted Laravel
 * application. An unguarded Log::warning() then raises
 * "A facade root has not been set." and masks the real error (e.g. the
 * AuthenticationException that should follow). This helper drops the entry
 * when no logger is available and swallows logger failures.
 */
final class SafeLog
{
    /** @param array<string, mixed> $context */
    public static function warning(string $message, array $context = []): void
    {
        try {
            if (Log::getFacadeRoot() === null) {
                return;
            }

            Log::warning($message, $context);
        } catch (\Throwable) {
            // No app / no 'log' binding / logger failure: logging is best-effort.
        }
    }
}
