<?php

namespace Cycoslave\Proxmox;

use Illuminate\Support\Facades\Log;
use Cycoslave\Proxmox\Support\LogRedactor;
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
        // H2: SPKI pinning (CURLOPT_PINNEDPUBLICKEY). Empty string == no pin.
        // Accepts one or more "sha256//<base64>" hashes separated by ';'.
        $this->pinnedPublicKey = self::normalisePin($this->pinnedPublicKey);

        // SAST-007 (CWE-393/CWE-532): previously logged on every construction
        // (e.g. once per named connection resolve, or per test), flooding logs
        // with the same warning + hostname. Once-guard per host, per process.
        // With a pin set, curl still enforces the public key even when
        // chain/host verification is off, so the warning only applies to the
        // unpinned verify-off case.
        if (! $this->verifyTls && $this->pinnedPublicKey === null && ! isset(self::$tlsWarnedHosts[$host])) {
            self::$tlsWarnedHosts[$host] = true;
            // LPX-006 (CWE-532): log a stable endpoint id, not the host.
            Log::warning('Proxmox: TLS verification disabled. Do not use in production.', [
                'endpoint' => LogRedactor::endpointId($host, $this->port),
            ]);
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
    public function get(string $path, array $params = []): array
    {
        return $this->request('GET', $path, $params);
    }

    /**
     * POST request.
     *
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     */
    public function post(string $path, array $data = []): array
    {
        return $this->request('POST', $path, $data);
    }

    /**
     * PUT request.
     *
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     */
    public function put(string $path, array $data = []): array
    {
        return $this->request('PUT', $path, $data);
    }

    /**
     * DELETE request.
     *
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     */
    public function delete(string $path, array $params = []): array
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
    protected function request(string $method, string $path, array $payload = []): array
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