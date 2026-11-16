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
            throw new \InvalidArgumentException("Invalid Proxmox path segment for [{$name}]: contains characters outside the allowed set.");
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
            throw new \InvalidArgumentException("Invalid Proxmox path segment for [{$name}]: contains characters outside the allowed set.");
        }
    }

    /**
     * Validate a Proxmox storage volume identifier and return it
     * URL-encoded as a single path segment (LPX-SAST-006).
     *
     * Volume IDs are `<storage>:<volname>` or `<storage>:<type>/<volname>`
     * (e.g. "local:iso/ubuntu.iso", "local-lvm:vm-100-disk-0"), so they
     * legitimately contain ':' and '/'. Allowed: [A-Za-z0-9._@:+-] and '/'
     * as an inner separator. Rejected: empty values, '.'/'..' path
     * components, empty components (leading/trailing/double '/'), control
     * characters, '%', backslash, '?', '#', whitespace and anything else.
     *
     * The caller MUST interpolate the returned (rawurlencoded) value, not
     * the original, so '/' travels as %2F inside one URL path segment.
     *
     * @throws \InvalidArgumentException
     */
    private function volumeSegment(string $value, string $name = 'volume'): string
    {
        if ($value === '') {
            throw new \InvalidArgumentException("Proxmox path segment [{$name}] must not be empty.");
        }

        if (! preg_match('/\A[\w\-.@:+\/]+\z/', $value)) {
            throw new \InvalidArgumentException("Invalid Proxmox volume identifier for [{$name}].");
        }

        foreach (explode('/', $value) as $part) {
            if ($part === '' || $part === '.' || $part === '..') {
                throw new \InvalidArgumentException("Invalid Proxmox volume identifier for [{$name}]: empty or traversal component.");
            }
        }

        return rawurlencode($value);
    }

    /**
     * Validate an IPv4/IPv6 address or CIDR block and return it URL-encoded
     * as a single path segment (LPX-SAST-006).
     *
     * Accepts `192.168.1.0/24`, `10.0.0.1` (no prefix), `2001:db8::/32`,
     * and an optional single leading '!' (Proxmox IPSet "nomatch" entries).
     * The prefix length must be an integer within 0-32 (IPv4) / 0-128 (IPv6).
     * The address part is checked with filter_var(), so hostnames, ports,
     * whitespace, traversal and control characters are all rejected.
     *
     * @throws \InvalidArgumentException
     */
    private function cidrSegment(string $value, string $name = 'cidr'): string
    {
        $addr = ltrim($value, '!');
        if (strlen($value) - strlen($addr) > 1) {
            throw new \InvalidArgumentException("Invalid CIDR for [{$name}].");
        }

        $prefix = null;
        if (str_contains($addr, '/')) {
            [$addr, $prefix] = explode('/', $addr, 2);
            if (! preg_match('/\A\d{1,3}\z/', $prefix)) {
                throw new \InvalidArgumentException("Invalid CIDR prefix length for [{$name}].");
            }
        }

        $isV4 = filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $isV6 = ! $isV4 && filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;

        if (! $isV4 && ! $isV6) {
            throw new \InvalidArgumentException("Invalid CIDR address for [{$name}].");
        }

        if ($prefix !== null && (int) $prefix > ($isV4 ? 32 : 128)) {
            throw new \InvalidArgumentException("CIDR prefix length out of range for [{$name}].");
        }

        return rawurlencode($value);
    }

    /**
     * Assert that a value is a single VM disk slot key and return it
     * (carbon F-03, CWE-88).
     *
     * `POST .../config` takes a comma/space separated `delete` list of ANY
     * config keys, so only one bare disk-slot key is allowed through
     * (`scsi0`, `sata1`, `ide2`, `virtio3`, `efidisk0`, `tpmstate0`,
     * `unused4`). Anchored with \A...\z; the index is ASCII digits only.
     *
     * @throws \InvalidArgumentException
     */
    private function diskSlot(string $value, string $name = 'disk'): string
    {
        if (! preg_match('/\A(?:scsi|sata|ide|virtio|efidisk|tpmstate|unused)[0-9]+\z/', $value)) {
            throw new \InvalidArgumentException("Invalid VM disk slot identifier for [{$name}].");
        }

        return $value;
    }

    /**
     * Strictly parse a disk size and return it in whole GiB (carbon F-06,
     * CWE-20), the unit of the `<storage>:<size>` allocation syntax.
     *
     * Accepts an int, or a string matching `\A[0-9]+[KMGT]?\z` (case
     * insensitive; no suffix means GiB). K/M/T are converted to GiB and must
     * land on a whole number >= 1. Nothing is ever stripped or rounded:
     * fractional, signed, zero, exponent, whitespace-padded, non-scalar and
     * absurdly large values are rejected.
     *
     * @throws \InvalidArgumentException
     */
    private function diskSizeGiB(mixed $size, string $name = 'size'): int
    {
        if (is_int($size)) {
            $size = (string) $size;
        }

        if (! is_string($size) || ! preg_match('/\A([0-9]{1,12})([KMGT]?)\z/i', $size, $m)) {
            throw new \InvalidArgumentException("Invalid disk size for [{$name}]: expected a whole number with optional K/M/G/T suffix.");
        }

        $n = (int) $m[1];
        $gib = match (strtoupper($m[2])) {
            'K'     => ($n % 1048576 === 0) ? intdiv($n, 1048576) : 0,
            'M'     => ($n % 1024 === 0) ? intdiv($n, 1024) : 0,
            'T'     => $n * 1024,
            default => $n,
        };

        if ($gib < 1) {
            throw new \InvalidArgumentException("Invalid disk size for [{$name}]: must be a whole number of GiB >= 1.");
        }

        return $gib;
    }

    /**
     * Assert that a value can be interpolated into a Proxmox property string
     * (e.g. `ipconfig0` = `ip=A/B,gw=C`) and return it as a string (carbon
     * F-04, CWE-88).
     *
     * Only int / string / Stringable values pass, and never one that is empty
     * or contains the property delimiters `,` and `=` or any control
     * character (CR / LF / NUL ...), which would add or override siblings.
     *
     * @throws \InvalidArgumentException
     */
    private function cloudInitValue(mixed $value, string $name): string
    {
        if (is_int($value) || $value instanceof \Stringable) {
            $value = (string) $value;
        }

        if (! is_string($value) || $value === '' || preg_match('/[,=\x00-\x1F\x7F]/', $value)) {
            throw new \InvalidArgumentException("Invalid cloud-init value for [{$name}].");
        }

        return $value;
    }

    /**
     * Validate a single SSH public key for the cloud-init `sshkeys` option and
     * return it percent-encoded, as PVE requires (carbon F-04; LPX-SAST-002).
     *
     * `sshkeys` is newline separated, so an embedded CR/LF/NUL (or any other
     * control character) would smuggle in additional authorized keys; the
     * value must also begin with a key type, never `authorized_keys` options
     * such as `command="..."`. rawurlencode() (not urlencode(), which turns
     * spaces into '+') is used consistently by every caller.
     *
     * @throws \InvalidArgumentException
     */
    private function encodedSshKey(mixed $key, string $name = 'sshKey'): string
    {
        if (! is_string($key)) {
            throw new \InvalidArgumentException("Invalid SSH public key for [{$name}].");
        }

        $key = trim($key);

        if ($key === ''
            || preg_match('/[\x00-\x1F\x7F]/', $key)
            || ! preg_match('/\A(?:ssh-[A-Za-z0-9]+|ecdsa-sha2-[A-Za-z0-9]+|sk-[A-Za-z0-9.@-]+)[ \t]+\S/', $key)) {
            throw new \InvalidArgumentException("Invalid SSH public key for [{$name}]: expected a single 'type base64 [comment]' key on one line.");
        }

        return rawurlencode($key);
    }
}