<?php

namespace Cycoslave\Proxmox\Tests\Feature;

use PHPUnit\Framework\Attributes\Test;
use Orchestra\Testbench\TestCase;
use Cycoslave\Proxmox\ProxmoxServiceProvider;
use Cycoslave\Proxmox\ProxmoxManager;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\ProxmoxCluster;
use Cycoslave\Proxmox\ProxmoxStorage;
use Cycoslave\Proxmox\ProxmoxPools;
use Cycoslave\Proxmox\ProxmoxAccessApi;
use Cycoslave\Proxmox\Facades\Proxmox;

class ProxmoxServiceProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [ProxmoxServiceProvider::class];
    }

    protected function getPackageAliases($app): array
    {
        return [
            'Proxmox' => \Cycoslave\Proxmox\Facades\Proxmox::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('proxmox.default', 'primary');
        $app['config']->set('proxmox.connections.primary', [
            'host'         => '127.0.0.1',
            'port'         => 8006,
            'username'     => 'root',
            'realm'        => 'pam',
            'password'     => null,
            'token_id'     => 'root@pam!testtoken',
            'token_secret' => 'aaaabbbb-cccc-dddd-eeee-ffffffffffff',
            'verify_tls'   => true,
            'timeout'      => 10,
        ]);
    }

    // -------------------------------------------------------------------------
    // Container bindings
    // -------------------------------------------------------------------------

    #[Test]
    public function proxmox_manager_is_bound_in_the_container(): void
    {
        $this->assertInstanceOf(ProxmoxManager::class, $this->app->make(ProxmoxManager::class));
    }

    #[Test]
    public function proxmox_string_alias_resolves_to_manager(): void
    {
        $this->assertInstanceOf(ProxmoxManager::class, $this->app->make('proxmox'));
    }

    #[Test]
    public function proxmox_manager_is_a_singleton(): void
    {
        $this->assertSame(
            $this->app->make(ProxmoxManager::class),
            $this->app->make(ProxmoxManager::class),
        );
    }

    // -------------------------------------------------------------------------
    // Resource singletons
    // -------------------------------------------------------------------------

    #[Test]
    public function proxmox_node_is_bound_as_singleton(): void
    {
        $a = $this->app->make('proxmox-node');
        $this->assertInstanceOf(ProxmoxNode::class, $a);
        $this->assertSame($a, $this->app->make('proxmox-node'));
    }

    #[Test]
    public function proxmox_cluster_is_bound_as_singleton(): void
    {
        $a = $this->app->make('proxmox-cluster');
        $this->assertInstanceOf(ProxmoxCluster::class, $a);
        $this->assertSame($a, $this->app->make('proxmox-cluster'));
    }

    #[Test]
    public function proxmox_storage_is_bound_as_singleton(): void
    {
        $a = $this->app->make('proxmox-storage');
        $this->assertInstanceOf(ProxmoxStorage::class, $a);
        $this->assertSame($a, $this->app->make('proxmox-storage'));
    }

    #[Test]
    public function proxmox_pools_is_bound_as_singleton(): void
    {
        $a = $this->app->make('proxmox-pools');
        $this->assertInstanceOf(ProxmoxPools::class, $a);
        $this->assertSame($a, $this->app->make('proxmox-pools'));
    }

    #[Test]
    public function proxmox_access_api_is_bound_as_singleton(): void
    {
        $a = $this->app->make('proxmox-access-api');
        $this->assertInstanceOf(ProxmoxAccessApi::class, $a);
        $this->assertSame($a, $this->app->make('proxmox-access-api'));
    }

    // -------------------------------------------------------------------------
    // Facade
    // -------------------------------------------------------------------------

    #[Test]
    public function proxmox_facade_resolves_to_manager(): void
    {
        $this->assertInstanceOf(ProxmoxManager::class, Proxmox::getFacadeRoot());
    }

    #[Test]
    public function proxmox_facade_connection_method_returns_proxmox_access(): void
    {
        $this->assertInstanceOf(
            \Cycoslave\Proxmox\ProxmoxAccess::class,
            Proxmox::connection('primary'),
        );
    }

    #[Test]
    public function proxmox_facade_node_method_returns_proxmox_node(): void
    {
        $this->assertInstanceOf(ProxmoxNode::class, Proxmox::node());
    }

    #[Test]
    public function proxmox_facade_cluster_method_returns_proxmox_cluster(): void
    {
        $this->assertInstanceOf(ProxmoxCluster::class, Proxmox::cluster());
    }

    #[Test]
    public function proxmox_facade_storage_method_returns_proxmox_storage(): void
    {
        $this->assertInstanceOf(ProxmoxStorage::class, Proxmox::storage());
    }

    #[Test]
    public function proxmox_facade_pools_method_returns_proxmox_pools(): void
    {
        $this->assertInstanceOf(ProxmoxPools::class, Proxmox::pools());
    }

    // -------------------------------------------------------------------------
    // Config
    // -------------------------------------------------------------------------

    #[Test]
    public function package_config_is_merged_into_app_config(): void
    {
        $this->assertNotNull(config('proxmox'));
        $this->assertArrayHasKey('default', config('proxmox'));
        $this->assertArrayHasKey('connections', config('proxmox'));
    }

    #[Test]
    public function default_connection_resolves_to_primary_per_spec(): void
    {
        $this->assertSame('primary', config('proxmox.default'));
    }

    // -------------------------------------------------------------------------
    // Config publish
    // -------------------------------------------------------------------------

    #[Test]
    public function provider_registers_config_for_publishing(): void
    {
        $publishes = ProxmoxServiceProvider::pathsToPublish(
            ProxmoxServiceProvider::class,
            'proxmox-config',
        );

        $this->assertNotEmpty($publishes);
        $this->assertStringEndsWith('proxmox.php', array_values($publishes)[0]);
    }
}