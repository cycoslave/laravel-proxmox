<?php

namespace Cycoslave\Proxmox;

use Illuminate\Contracts\Foundation\Application;
use InvalidArgumentException;

class ProxmoxManager
{
    protected Application $app;

    /** @var array<string, ProxmoxAccess> */
    protected array $connections = [];

    /** @var array<string, ProxmoxNode> */
    protected array $nodes = [];

    /** @var array<string, ProxmoxCluster> */
    protected array $clusters = [];

    /** @var array<string, ProxmoxStorage> */
    protected array $storages = [];

    /** @var array<string, ProxmoxPools> */
    protected array $poolsCache = [];

    /** @var array<string, ProxmoxAccessApi> */
    protected array $accessApis = [];

    public function __construct(Application $app)
    {
        $this->app = $app;
    }

    /**
     * Resolve a named ProxmoxAccess connection (lazy + cached).
     */
    public function connection(?string $name = null): ProxmoxAccess
    {
        // Resolve 'default' → config('proxmox.default')
        $name ??= $this->app['config']['proxmox.default']
            ?? throw new InvalidArgumentException('No default Proxmox connection configured.');

        if (! isset($this->connections[$name])) {
            $this->connections[$name] = $this->resolve($name);
        }

        return $this->connections[$name];
    }

    /**
     * Instantiate ProxmoxAccess from the multi-connection config schema.
     */
    protected function resolve(string $name): ProxmoxAccess
    {
        // ✅ Reads connections.{name}.* — NOT the old flat keys
        $config = $this->app['config']["proxmox.connections.{$name}"]
            ?? throw new InvalidArgumentException("Proxmox connection [{$name}] is not defined.");

        // F-02: fail with a clear InvalidArgumentException (not an "Undefined
        // array key" warning / TypeError) when required keys are missing or
        // not strings. Host/port syntax is validated by ProxmoxAccess.
        foreach (['host', 'username'] as $key) {
            if (! isset($config[$key]) || ! is_string($config[$key]) || $config[$key] === '') {
                throw new InvalidArgumentException(
                    "Proxmox connection [{$name}] requires a non-empty string '{$key}'."
                );
            }
        }
        if (isset($config['port']) && ! is_int($config['port']) && ! (is_string($config['port']) && ctype_digit($config['port']))) {
            throw new InvalidArgumentException("Proxmox connection [{$name}] has an invalid 'port'.");
        }

        return new ProxmoxAccess(
            host:        $config['host'],
            port:        (int) ($config['port']        ?? 8006),
            username:    $config['username'],
            realm:       $config['realm']               ?? 'pam',
            password:    $config['password']            ?? null,
            tokenId:     $config['token_id']            ?? null,
            tokenSecret: $config['token_secret']        ?? null,
            verifyTls:   (bool) ($config['verify_tls'] ?? true),
            timeout:     (int) ($config['timeout']      ?? 10),
            pinnedPublicKey: isset($config['pinned_public_key']) ? (string) $config['pinned_public_key'] : null,
        );
    }

    /**
     * Typed accessors used by the service provider singletons
     */
    public function node(?string $connection = null): ProxmoxNode
    {
        $key = $connection ?? $this->defaultName();
        return $this->nodes[$key] ??= new ProxmoxNode($this->connection($connection));
    }

    public function cluster(?string $connection = null): ProxmoxCluster
    {
        $key = $connection ?? $this->defaultName();
        return $this->clusters[$key] ??= new ProxmoxCluster($this->connection($connection));
    }

    public function storage(?string $connection = null): ProxmoxStorage
    {
        $key = $connection ?? $this->defaultName();
        return $this->storages[$key] ??= new ProxmoxStorage($this->connection($connection));
    }

    public function pools(?string $connection = null): ProxmoxPools
    {
        $key = $connection ?? $this->defaultName();
        return $this->poolsCache[$key] ??= new ProxmoxPools($this->connection($connection));
    }

    public function accessApi(?string $connection = null): ProxmoxAccessApi
    {
        $key = $connection ?? $this->defaultName();
        return $this->accessApis[$key] ??= new ProxmoxAccessApi($this->connection($connection));
    }

    /** Container keys of the facade-backed resource singletons (see ProxmoxServiceProvider). */
    private const FACADE_SINGLETONS = [
        'proxmox-node',
        'proxmox-cluster',
        'proxmox-storage',
        'proxmox-pools',
        'proxmox-access-api',
    ];

    /** Also update purge() to flush resource caches too */
    public function purge(?string $name = null): void
    {
        if ($name === null) {
            $this->connections = [];
            $this->nodes       = [];
            $this->clusters    = [];
            $this->storages    = [];
            $this->poolsCache  = [];
            $this->accessApis  = [];
        } else {
            unset(
                $this->connections[$name],
                $this->nodes[$name],
                $this->clusters[$name],
                $this->storages[$name],
                $this->poolsCache[$name],
                $this->accessApis[$name],
            );
        }

        // F-09 (CWE-613): the facade-backed singletons are bound to the
        // *default* connection's resource objects. Without this they keep the
        // purged ProxmoxAccess (and its cached ticket / token) alive in
        // persistent workers (Octane, queue workers).
        $default = $this->app['config']['proxmox.default'] ?? null;
        if ($name === null || $default === null || $name === $default) {
            $this->forgetFacadeSingletons();
        }
    }

    private function forgetFacadeSingletons(): void
    {
        foreach (self::FACADE_SINGLETONS as $key) {
            if (method_exists($this->app, 'forgetInstance')) {
                $this->app->forgetInstance($key);
            }
            \Illuminate\Support\Facades\Facade::clearResolvedInstance($key);
        }
    }

    /** Helper used by the caching wrappers above */
    private function defaultName(): string
    {
        return $this->app['config']['proxmox.default']
            ?? throw new InvalidArgumentException('No default Proxmox connection configured.');
    }
}