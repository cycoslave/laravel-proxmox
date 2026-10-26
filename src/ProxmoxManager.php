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
    }

    /** Helper used by the caching wrappers above */
    private function defaultName(): string
    {
        return $this->app['config']['proxmox.default']
            ?? throw new InvalidArgumentException('No default Proxmox connection configured.');
    }
}