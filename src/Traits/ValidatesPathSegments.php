<?php

namespace Cycoslave\Proxmox\Traits;

/**
 * Provides path-segment validation for Proxmox API classes.
 *
 * Proxmox identifiers (node names, storage IDs, realms, VMIDs, etc.)
 * must consist only of word chars, hyphens, and dots.
 * Rejects traversal sequences (../../), null bytes, and other
 * characters that could corrupt the constructed URL.
 */
trait ValidatesPathSegments
{
    /**
     * Assert that a URL path segment is safe to interpolate.
     *
     * Allowed characters: [A-Za-z0-9_\-.]
     * No slashes, no null bytes, no percent-encoded sequences.
     *
     * Uses \A...\z (not ^...$) so a trailing newline cannot slip through:
     * with the multi-line-unaware `$` anchor, PCRE still matches `$` right
     * before a final "\n" (e.g. "pve1\n" would pass), even though `\z`
     * correctly rejects it. That mismatch is CWE-20/CWE-625 (SAST-003):
     * a caller-supplied "pve1\n" would then fail downstream in libcurl
     * (bad URL, errno 3) instead of being rejected here with a clear
     * validation error — a mis-classified failure, not a traversal.
     *
     * @param  string  $value  The caller-supplied value.
     * @param  string  $name   Parameter name used in the exception message.
     * @throws \InvalidArgumentException
     */
    private function validateSegment(string $value, string $name): void
    {
        if ($value === '') {
            throw new \InvalidArgumentException("Proxmox path segment [{$name}] must not be empty.");
        }

        if ($value === '.' || $value === '..') {
            throw new \InvalidArgumentException("Proxmox path segment [{$name}] cannot be a traversal indicator.");
        }

        if (! preg_match('/\A[\w\-\.]+\z/', $value)) {
            throw new \InvalidArgumentException("Invalid Proxmox path segment for [{$name}]: [{$value}]");
        }
    }

    /**
     * Assert that a URL path segment holding a Proxmox user/token
     * identifier is safe to interpolate.
     *
     * Proxmox user IDs are `<name>@<realm>` (e.g. "root@pam") and API
     * token IDs extend that to `<name>@<realm>!<tokenid>`
     * (e.g. "root@pam!automation"). validateSegment()'s [\w\-.] class
     * rejects both legitimate forms, breaking every /access/users/*
     * endpoint for real Proxmox identifiers. This validator keeps the
     * same traversal/null-byte/slash protections but additionally
     * allows the `@`, `!`, and `:` characters that appear in valid
     * user and token IDs (`:` covers realm-qualified tokens some
     * Proxmox tooling emits, e.g. "root@pam:automation").
     *
     * Still anchored with \A...\z (see validateSegment()) so a
     * trailing newline cannot slip through.
     *
     * @param  string  $value  The caller-supplied value.
     * @param  string  $name   Parameter name used in the exception message.
     * @throws \InvalidArgumentException
     */
    private function validateIdentifierSegment(string $value, string $name): void
    {
        if ($value === '') {
            throw new \InvalidArgumentException("Proxmox path segment [{$name}] must not be empty.");
        }

        if ($value === '.' || $value === '..') {
            throw new \InvalidArgumentException("Proxmox path segment [{$name}] cannot be a traversal indicator.");
        }

        if (! preg_match('/\A[\w\-.@!:]+\z/', $value)) {
            throw new \InvalidArgumentException("Invalid Proxmox path segment for [{$name}]: [{$value}]");
        }
    }
}