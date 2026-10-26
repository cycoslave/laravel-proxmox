<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use Orchestra\Testbench\TestCase;
use Cycoslave\Proxmox\ProxmoxManager;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\ProxmoxCluster;
use Cycoslave\Proxmox\ProxmoxStorage;
use Cycoslave\Proxmox\ProxmoxPools;
use Cycoslave\Proxmox\ProxmoxAccessApi;
use InvalidArgumentException;

/**
 * PLG-R2-01 remediation: ProxmoxManager::__construct() is typed to
 * Illuminate\Contracts\Foundation\Application (production code, not
 * touched here). The previous suite passed a bespoke ArrayAccess-only
 * stand-in that satisfied `$app['config'][...]` reads at the call sites
 * but not the constructor's type hint, so every test errored with a
 * TypeError before the real assertions ever ran.
 *
 * Fix: extend Orchestra\Testbench\TestCase (already a require-dev
 * dependency, used by tests/Feature/ProxmoxServiceProviderTest.php) so
 * $this->app is a real Illuminate\Foundation\Application booted by
 * Testbench, and drive each scenario by setting the 'proxmox' config key
 * directly on it instead of faking the container.
 */
class ProxmoxManagerTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function primaryConfig(): array
    {
        return [
            'default' => 'primary',
            'connections' => [
                'primary' => [
                    'host'         => '10.0.0.1',
                    'port'         => 8006,
                    'username'     => 'root',
                    'realm'        => 'pam',
                    'token_id'     => 'root@pam!test',
                    'token_secret' => 'uuid-secret-value',
                    'verify_tls'   => true,
                    'timeout'      => 10,
                ],
                'secondary' => [
                    'host'         => '10.0.0.2',
                    'port'         => 8006,
                    'username'     => 'admin',
                    'realm'        => 'pve',
                    'token_id'     => 'admin@pve!tok',
                    'token_secret' => 'another-uuid',
                    'verify_tls'   => false,
                    'timeout'      => 5,
                ],
            ],
        ];
    }

    private function makeManager(?array $proxmoxConfig = null): ProxmoxManager
    {
        $this->app['config']->set('proxmox', $proxmoxConfig ?? $this->primaryConfig());

        return new ProxmoxManager($this->app);
    }

    // -------------------------------------------------------------------------
    // Default connection resolution
    // -------------------------------------------------------------------------

    #[Test]
    public function connection_resolves_default_when_no_name_given(): void
    {
        $this->assertInstanceOf(ProxmoxAccess::class, $this->makeManager()->connection());
    }

    #[Test]
    public function connection_resolves_named_connection(): void
    {
        $manager = $this->makeManager();
        $this->assertInstanceOf(ProxmoxAccess::class, $manager->connection('primary'));
        $this->assertInstanceOf(ProxmoxAccess::class, $manager->connection('secondary'));
    }

    #[Test]
    public function connection_throws_when_default_config_is_missing(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $manager = $this->makeManager([
            'connections' => ['primary' => ['host' => '1.2.3.4']],
        ]);

        $manager->connection();
    }

    #[Test]
    public function connection_throws_when_named_connection_is_not_defined(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/nonexistent/');

        $this->makeManager()->connection('nonexistent');
    }

    // -------------------------------------------------------------------------
    // Connection caching
    // -------------------------------------------------------------------------

    #[Test]
    public function same_connection_name_returns_identical_instance(): void
    {
        $manager = $this->makeManager();
        $this->assertSame($manager->connection('primary'), $manager->connection('primary'));
    }

    #[Test]
    public function different_connection_names_return_different_instances(): void
    {
        $manager = $this->makeManager();
        $this->assertNotSame($manager->connection('primary'), $manager->connection('secondary'));
    }

    // -------------------------------------------------------------------------
    // Resource wrapper types
    // -------------------------------------------------------------------------

    #[Test]
    public function node_returns_proxmox_node_instance(): void
    {
        $this->assertInstanceOf(ProxmoxNode::class, $this->makeManager()->node());
    }

    #[Test]
    public function cluster_returns_proxmox_cluster_instance(): void
    {
        $this->assertInstanceOf(ProxmoxCluster::class, $this->makeManager()->cluster());
    }

    #[Test]
    public function storage_returns_proxmox_storage_instance(): void
    {
        $this->assertInstanceOf(ProxmoxStorage::class, $this->makeManager()->storage());
    }

    #[Test]
    public function pools_returns_proxmox_pools_instance(): void
    {
        $this->assertInstanceOf(ProxmoxPools::class, $this->makeManager()->pools());
    }

    #[Test]
    public function access_api_returns_proxmox_access_api_instance(): void
    {
        $this->assertInstanceOf(ProxmoxAccessApi::class, $this->makeManager()->accessApi());
    }

    // -------------------------------------------------------------------------
    // Resource wrapper caching
    // -------------------------------------------------------------------------

    #[Test]
    public function node_is_cached_across_calls_for_same_connection(): void
    {
        $manager = $this->makeManager();
        $this->assertSame($manager->node(), $manager->node());
    }

    #[Test]
    public function cluster_is_cached_across_calls_for_same_connection(): void
    {
        $manager = $this->makeManager();
        $this->assertSame($manager->cluster(), $manager->cluster());
    }

    #[Test]
    public function different_connections_return_different_node_instances(): void
    {
        $manager = $this->makeManager();
        $this->assertNotSame($manager->node('primary'), $manager->node('secondary'));
    }

    // -------------------------------------------------------------------------
    // purge()
    // -------------------------------------------------------------------------

    #[Test]
    public function purge_named_connection_forces_new_access_instance(): void
    {
        $manager = $this->makeManager();
        $before  = $manager->connection('primary');
        $manager->purge('primary');
        $this->assertNotSame($before, $manager->connection('primary'));
    }

    #[Test]
    public function purge_named_connection_forces_new_resource_wrapper_instance(): void
    {
        $manager = $this->makeManager();
        $before  = $manager->node('primary');
        $manager->purge('primary');
        $this->assertNotSame($before, $manager->node('primary'));
    }

    #[Test]
    public function purge_null_clears_all_connections(): void
    {
        $manager           = $this->makeManager();
        $primaryBefore     = $manager->connection('primary');
        $secondaryBefore   = $manager->connection('secondary');
        $manager->purge();
        $this->assertNotSame($primaryBefore,   $manager->connection('primary'));
        $this->assertNotSame($secondaryBefore, $manager->connection('secondary'));
    }

    #[Test]
    public function purge_null_clears_all_resource_caches(): void
    {
        $manager       = $this->makeManager();
        $nodeBefore    = $manager->node('primary');
        $clusterBefore = $manager->cluster('primary');
        $storageBefore = $manager->storage('primary');
        $poolsBefore   = $manager->pools('primary');
        $apiBefore     = $manager->accessApi('primary');

        $manager->purge();

        $this->assertNotSame($nodeBefore,    $manager->node('primary'));
        $this->assertNotSame($clusterBefore, $manager->cluster('primary'));
        $this->assertNotSame($storageBefore, $manager->storage('primary'));
        $this->assertNotSame($poolsBefore,   $manager->pools('primary'));
        $this->assertNotSame($apiBefore,     $manager->accessApi('primary'));
    }

    #[Test]
    public function purge_named_does_not_affect_other_connections(): void
    {
        $manager         = $this->makeManager();
        $secondaryBefore = $manager->connection('secondary');
        $manager->purge('primary');
        $this->assertSame($secondaryBefore, $manager->connection('secondary'));
    }
}
