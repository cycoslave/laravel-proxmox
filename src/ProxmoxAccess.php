<?php

namespace Cycoslave\Proxmox;

use Cycoslave\Proxmox\Support\LogRedactor;
use Cycoslave\Proxmox\Support\SafeLog;
use Cycoslave\Proxmox\Traits\Authenticator;
use Cycoslave\Proxmox\Traits\HttpClient;
use Cycoslave\Proxmox\Exceptions\ApiException;

/**
 * ProxmoxAccess — HTTP connection layer.
 *
 * Responsibilities (per spec):
 *   - Holds connection credentials and config
 *   - Builds base URLs:  https://{host}:{port}/api2/json/{path}
 *   - Exposes get / post / put / delete
 *   - Returns decoded array or throws on error
 *   - Delegates auth to Authenticator trait (ticket or API token)
 *   - Delegates raw cURL to HttpClient trait
 *
 * Used by ProxmoxManager::resolve() and injected into all resource classes
 * (ProxmoxNode, ProxmoxCluster, ProxmoxStorage, ProxmoxPools, ProxmoxAccessApi).
 *
 * NOT to be confused with ProxmoxAccessApi, which wraps the /access/* endpoints.
 */
class ProxmoxAccess
{
    use Authenticator, HttpClient;

    /** @var array<string, true> Hosts a TLS-disabled warning has already been logged for (SAST-007 log-noise fix). */
    private static array $tlsWarnedHosts = [];

    public function __construct(
        protected string  $host,
        protected int     $port        = 8006,
        protected string  $username    = 'root',
        protected string  $realm       = 'pam',
        #[\SensitiveParameter] protected ?string $password    = null,
        #[\SensitiveParameter] protected ?string $tokenId     = null,
        #[\SensitiveParameter] protected ?string $tokenSecret = null,
        protected bool    $verifyTls   = true,
        protected int     $timeout     = 10,
        protected ?string $pinnedPublicKey = null,
    ) {
        // F-02 (CWE-918): host/port are interpolated into the base URL, so a
        // value such as "attacker.example/collect?" would move the request
        // (and its credentials) to another origin. Validate before anything
        // else; IPv6 literals are normalised to their bracketed form.
        $this->host = self::normaliseHost($this->host);
        self::assertValidPort($this->port);

        // H2: SPKI pinning (CURLOPT_PINNEDPUBLICKEY). Empty string == no pin.
        // Accepts one or more "sha256//<base64>" hashes separated by ';'.
        $this->pinnedPublicKey = self::normalisePin($this->pinnedPublicKey);

        // SAST-007 (CWE-393/CWE-532): previously logged on every construction
        // (e.g. once per named connection resolve, or per test), flooding logs
        // with the same warning + hostname. Once-guard per host, per process.
        // With a pin set, curl still enforces the public key even when
        // chain/host verification is off, so the warning only applies to the
        // unpinned verify-off case.
        if (! $this->verifyTls && $this->pinnedPublicKey === null && ! isset(self::$tlsWarnedHosts[$this->host])) {
            self::$tlsWarnedHosts[$this->host] = true;
            // LPX-006 (CWE-532): log a stable endpoint id, not the host.
            // F-09: SafeLog is a no-op when no Log facade root is bound.
            SafeLog::warning('Proxmox: TLS verification disabled. Do not use in production.', [
                'endpoint' => LogRedactor::endpointId($this->host, $this->port),
            ]);
        }
    }

    /**
     * F-02: accept only a bare hostname (RFC 1123), an IPv4 address or an IPv6
     * literal. Returns the host as it must appear in the URL authority
     * (IPv6 always bracketed). Rejects scheme, userinfo, path, query,
     * fragment, port, zone id, whitespace and control characters.
     *
     * @throws \InvalidArgumentException
     */
    private static function normaliseHost(string $host): string
    {
        if ($host !== '' && strlen($host) <= 255) {
            if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                return $host;
            }

            $bare = $host;
            if ($host[0] === '[' && str_ends_with($host, ']')) {
                $bare = substr($host, 1, -1);
            }
            if (str_contains($bare, ':') && filter_var($bare, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                return '[' . $bare . ']';
            }

            $labels = explode('.', $host);
            $valid  = strlen($host) <= 253;
            foreach ($labels as $label) {
                if (! preg_match('/\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z/', $label)) {
                    $valid = false;
                    break;
                }
            }
            // An all-numeric final label is never a valid TLD; it would be a
            // malformed/abbreviated IPv4 that curl may reinterpret.
            if ($valid && ctype_digit(end($labels))) {
                $valid = false;
            }
            if ($valid) {
                return $host;
            }
        }

        throw new \InvalidArgumentException(
            'Proxmox: host must be a hostname, an IPv4 address or an IPv6 literal '
            . '(no scheme, userinfo, port, path, query or fragment).'
        );
    }

    /**
     * @throws \InvalidArgumentException
     */
    private static function assertValidPort(int $port): void
    {
        if ($port < 1 || $port > 65535) {
            throw new \InvalidArgumentException('Proxmox: port must be an integer between 1 and 65535.');
        }
    }

    /**
     * Validate and normalise a CURLOPT_PINNEDPUBLICKEY value.
     *
     * @throws \InvalidArgumentException  When the value is not "sha256//<base64>" (';'-separated list allowed)
     */
    private static function normalisePin(?string $pin): ?string
    {
        $pin = $pin === null ? '' : trim($pin);

        if ($pin === '') {
            return null;
        }

        foreach (explode(';', $pin) as $hash) {
            if (! preg_match('#^sha256//[A-Za-z0-9+/]{43}=$#', $hash)) {
                throw new \InvalidArgumentException(
                    'Proxmox: pinned_public_key must be "sha256//<base64>" (44-char base64 SHA-256 SPKI hash); '
                    . 'multiple hashes may be separated by ";".'
                );
            }
        }

        return $pin;
    }

    // -------------------------------------------------------------------------
    // Debug protection
    // -------------------------------------------------------------------------

    /**
     * Prevents credentials and live tickets from appearing in:
     *   - var_dump() / print_r()
     *   - Laravel Telescope / Sentry / Flare object captures
     *   - dd() / dump()
     *
     * The Authenticator trait supplies redactedAuthState() for ticket fields.
     */
    public function __debugInfo(): array
    {
        return [
            'host'      => $this->host,
            'port'      => $this->port,
            'username'  => $this->username,
            'realm'     => $this->realm,
            'verifyTls' => $this->verifyTls,
            'timeout'   => $this->timeout,
            'pinnedPublicKey' => $this->pinnedPublicKey,
            'password'  => '[REDACTED]',
            'tokenId'   => '[REDACTED]',
            'tokenSecret' => '[REDACTED]',
            ...$this->redactedAuthState(),   // ticket, csrf, ticketExpiry
        ];
    }

    // -------------------------------------------------------------------------
    // URL builder
    // -------------------------------------------------------------------------

    /**
     * Base URL for all API calls.
     */
    protected function baseUrl(): string
    {
        return "https://{$this->host}:{$this->port}/api2/json";
    }

    // -------------------------------------------------------------------------
    // Public HTTP interface
    // -------------------------------------------------------------------------

    /**
     * GET request.
     *
     * @param  string  $path    e.g. 'nodes' or 'nodes/pve1/qemu'
     * @param  array   $params  Optional query parameters
     * @return array   Decoded JSON response
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException  On network/cURL failure
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException         On HTTP 4xx/5xx or bad JSON
     */
    public function get(string $path, #[\SensitiveParameter] array $params = []): array
    {
        return $this->request('GET', $path, $params);
    }

    /**
     * POST request.
     *
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     */
    public function post(string $path, #[\SensitiveParameter] array $data = []): array
    {
        return $this->request('POST', $path, $data);
    }

    /**
     * PUT request.
     *
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     */
    public function put(string $path, #[\SensitiveParameter] array $data = []): array
    {
        return $this->request('PUT', $path, $data);
    }

    /**
     * DELETE request.
     *
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     */
    public function delete(string $path, #[\SensitiveParameter] array $params = []): array
    {
        return $this->request('DELETE', $path, $params);
    }

    // -------------------------------------------------------------------------
    // Internal dispatcher
    // -------------------------------------------------------------------------

    /**
     * Build the full URL, attach auth headers, and dispatch via HttpClient.
     *
     * SAST-008 (CWE-613): a ticket can be invalidated server-side before our
     * locally-tracked TTL expires (password change, realm resync, PVE
     * restart, ...). When that happens Proxmox answers 401 even though we
     * believe the ticket is still fresh. Detect that once, drop the cached
     * ticket, and retry exactly once with a newly issued one instead of
     * failing every call until the local TTL catches up. Token auth is
     * static (nothing to refresh) so it is excluded from the retry.
     *
     * @throws \Exception
     */
    protected function request(string $method, string $path, #[\SensitiveParameter] array $payload = []): array
    {
        $url     = $this->baseUrl() . '/' . ltrim($path, '/');
        $headers = $this->authHeaders();   // resolved by Authenticator trait

        try {
            return $this->sendRequest($method, $url, $payload, $headers);
        } catch (ApiException $e) {
            if ($e->getStatusCode() !== 401 || $this->usingTokenAuth()) {
                throw $e;
            }

            $this->invalidateTicket();
            $headers = $this->authHeaders();

            return $this->sendRequest($method, $url, $payload, $headers);
        }
    }
}