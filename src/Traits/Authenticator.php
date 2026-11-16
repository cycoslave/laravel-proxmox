<?php

namespace Cycoslave\Proxmox\Traits;

use Cycoslave\Proxmox\Exceptions\AuthenticationException;
use Cycoslave\Proxmox\Exceptions\ProxmoxException;
use Cycoslave\Proxmox\Support\LogRedactor;
use Cycoslave\Proxmox\Support\SafeLog;

/**
 * Authenticator trait — ticket and API token auth for Proxmox.
 *
 * Auth strategy priority:
 *   1. API token  — if both tokenId and tokenSecret are set
 *   2. Ticket     — username + password, auto-refreshed on expiry
 */
trait Authenticator
{
    // SAST-008 (CWE-613): the ticket lifetime the server actually issues,
    // less a safety margin so we proactively re-auth slightly before Proxmox
    // would reject the ticket outright.
    private const TICKET_TTL_SECONDS        = 7200;
    private const TICKET_TTL_SAFETY_MARGIN  = 60;

    // TODO: These are per-process/per-worker. Under PHP-FPM or Octane,
    //       each worker authenticates independently, causing redundant
    //       POST /access/ticket calls under load.
    //       Future improvement: back this with a shared cache (Redis)
    //       keyed on connection name, with TTL = ticketExpiry.
    //
    // SAST-008 (CWE-613) mitigation: a locally-tracked TTL cannot detect a
    // ticket that the server invalidated early (password change, realm
    // sync, PVE restart, etc). ProxmoxAccess::request() now catches a 401
    // response, calls invalidateTicket() below, and retries once with a
    // freshly issued ticket — so a stale/revoked ticket self-heals on the
    // next call instead of wedging every subsequent request until the
    // local TTL happens to expire.
    private ?string $ticket       = null;
    private ?string $csrf         = null;
    private ?int    $ticketExpiry = null;

    protected function usingTokenAuth(): bool
    {
        return ! empty($this->tokenId) && ! empty($this->tokenSecret);
    }

    /**
     * Build auth headers for the current request.
     * API token takes precedence over ticket auth.
     *
     * @return string[]
     * @throws AuthenticationException
     */
    protected function authHeaders(): array
    {
        if ($this->usingTokenAuth()) {
            // F-05 (CWE-113): CR/LF/NUL in a header value would let a caller
            // smuggle extra headers / a second request onto the wire.
            $this->assertSafeHeaderValue((string) $this->tokenId, 'API token id');
            $this->assertSafeHeaderValue((string) $this->tokenSecret, 'API token secret');

            return [
                "Authorization: PVEAPIToken={$this->tokenId}={$this->tokenSecret}",
            ];
        }

        if ($this->ticket === null || time() >= ($this->ticketExpiry ?? 0)) {
            $this->loginWithTicket();
        }

        $this->assertSafeHeaderValue((string) $this->ticket, 'ticket');
        $this->assertSafeHeaderValue((string) $this->csrf, 'CSRF token');

        return [
            'Cookie: PVEAuthCookie=' . $this->ticket,
            'CSRFPreventionToken: '  . $this->csrf,
        ];
    }

    /**
     * F-05 (CWE-113): reject CR, LF and NUL bytes in a value destined for an
     * HTTP header. The message names the field only, never the value.
     *
     * @throws ProxmoxException
     */
    private function assertSafeHeaderValue(#[\SensitiveParameter] string $value, string $what): void
    {
        if (preg_match('/[\r\n\x00]/', $value) === 1) {
            throw new ProxmoxException(
                "Proxmox {$what} contains a forbidden control character (CR, LF or NUL)."
            );
        }
    }

    /**
     * Perform ticket auth (POST /access/ticket).
     * Calls sendRequest() with empty headers — bypasses authHeaders()
     * to prevent infinite recursion.
     *
     * @throws AuthenticationException
     */
    protected function loginWithTicket(): void
    {
        if (empty($this->password)) {
            throw new AuthenticationException(
                'Proxmox ticket auth requires a password; none is configured. ' .
                'Set PROXMOX_PASSWORD or use API token auth instead.'
            );
        }

        $url  = $this->baseUrl() . '/access/ticket';
        $data = [
            'username' => "{$this->username}@{$this->realm}",
            'password' => $this->password,
        ];

        try {
            $response = $this->sendRequest('POST', $url, $data, []);
        } catch (\Throwable $e) {
            // SAST-006 (CWE-209): $e->getMessage() may embed curl diagnostics
            // (resolved IPs, hostnames, local paths); the caller-facing
            // exception message stays generic.
            // LPX-006 (CWE-532): the log entry carries a stable endpoint id
            // and a categorised error, never the host or raw message.
            // F-09: SafeLog is a no-op when no Log facade root is bound, so
            // standalone use still surfaces the AuthenticationException below.
            SafeLog::warning('Proxmox ticket authentication request failed.', [
                'endpoint' => LogRedactor::endpointId((string) $this->host, (int) $this->port),
                ...LogRedactor::exceptionContext($e),
            ]);

            throw new AuthenticationException(
                'Proxmox ticket authentication failed: unable to reach the Proxmox API.',
                previous: $e,
            );
        }

        if (empty($response['data']['ticket']) || ! is_string($response['data']['ticket'])) {
            throw new AuthenticationException(
                'Proxmox ticket authentication failed: no ticket in response.'
            );
        }

        // F-05: the CSRF token is mandatory for ticket auth; guard the read
        // instead of raising an "Undefined array key" warning.
        if (empty($response['data']['CSRFPreventionToken']) || ! is_string($response['data']['CSRFPreventionToken'])) {
            throw new AuthenticationException(
                'Proxmox ticket authentication failed: no CSRF prevention token in response.'
            );
        }

        // Validate before caching so a hostile value is never stored.
        $this->assertSafeHeaderValue($response['data']['ticket'], 'ticket');
        $this->assertSafeHeaderValue($response['data']['CSRFPreventionToken'], 'CSRF token');

        $this->ticket       = $response['data']['ticket'];
        $this->csrf         = $response['data']['CSRFPreventionToken'];
        $this->ticketExpiry = time() + self::TICKET_TTL_SECONDS - self::TICKET_TTL_SAFETY_MARGIN;
    }

    /**
     * Discard the cached ticket/CSRF pair so the next authHeaders() call
     * re-authenticates from scratch.
     *
     * SAST-008 (CWE-613): called by ProxmoxAccess::request() when a request
     * comes back 401 despite a locally-unexpired ticket (e.g. the server
     * revoked it early), so the caller's single retry gets a fresh ticket
     * instead of repeating the same stale one.
     */
    protected function invalidateTicket(): void
    {
        $this->ticket       = null;
        $this->csrf         = null;
        $this->ticketExpiry = null;
    }

    /**
     * Returns redacted ticket state for __debugInfo().
     * Prevents live credentials from leaking into debug output.
     *
     * @return array<string, mixed>
     */
    public function redactedAuthState(): array
    {
        return [
            'ticket'       => $this->ticket       !== null ? '[REDACTED]' : null,
            'csrf'         => $this->csrf          !== null ? '[REDACTED]' : null,
            'ticketExpiry' => $this->ticketExpiry,
        ];
    }
}