<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\Exceptions\AuthenticationException;
use Cycoslave\Proxmox\Exceptions\ConnectionException;
use Cycoslave\Proxmox\Facades\ProxmoxNode as ProxmoxNodeFacade;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxManager;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\ProxmoxServiceProvider;
use Cycoslave\Proxmox\Support\SafeLog;
use Illuminate\Support\Facades\Facade;
use Orchestra\Testbench\TestCase as TestbenchTestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Regression tests for carbon F-09:
 *  (a) ProxmoxManager::purge() left the facade-backed container singletons
 *      (proxmox-node/-cluster/-storage/-pools/-access-api) bound to the
 *      purged ProxmoxAccess;
 *  (b) unguarded Log::warning() threw "A facade root has not been set."
 *      in standalone use.
 */
class CarbonF09Test extends TestbenchTestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();

        // See CarbonF02Test::tearDown(): keep the global container clean for
        // later plain-TestCase suites that consult app().
        \Illuminate\Container\Container::setInstance(null);
    }
    protected function getPackageProviders($app): array
    {
        return [ProxmoxServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('proxmox.default', 'primary');
        $app['config']->set('proxmox.connections.primary', [
            'host' => '10.0.0.1', 'port' => 8006, 'username' => 'root',
            'token_id' => 'root@pam!a', 'token_secret' => 'secret-a',
        ]);
        $app['config']->set('proxmox.connections.other', [
            'host' => '10.0.0.2', 'port' => 8006, 'username' => 'root',
            'token_id' => 'root@pam!b', 'token_secret' => 'secret-b',
        ]);
    }

    /** @return string[] */
    private function keys(): array
    {
        return ['proxmox-node', 'proxmox-cluster', 'proxmox-storage', 'proxmox-pools', 'proxmox-access-api'];
    }

    private function hostOf(object $resource): string
    {
        $client = (new \ReflectionProperty($resource, 'client'))->getValue($resource);

        return (new \ReflectionProperty(ProxmoxAccess::class, 'host'))->getValue($client);
    }

    #[Test]
    public function purge_all_forgets_every_resource_singleton(): void
    {
        $before = [];
        foreach ($this->keys() as $key) {
            $before[$key] = $this->app->make($key);
            $this->assertSame($before[$key], $this->app->make($key), "{$key} is a singleton");
        }

        $this->app->make(ProxmoxManager::class)->purge();

        foreach ($this->keys() as $key) {
            $this->assertNotSame($before[$key], $this->app->make($key), "{$key} survived purge()");
        }
    }

    #[Test]
    public function after_purge_facades_and_singletons_pick_up_rotated_config(): void
    {
        $this->assertSame('10.0.0.1', $this->hostOf($this->app->make('proxmox-node')));
        $this->assertSame('10.0.0.1', $this->hostOf(ProxmoxNodeFacade::getFacadeRoot()));

        $this->app['config']->set('proxmox.connections.primary.host', '10.9.9.9');
        $this->app->make(ProxmoxManager::class)->purge();

        $this->assertSame('10.9.9.9', $this->hostOf($this->app->make('proxmox-node')));
        $this->assertSame('10.9.9.9', $this->hostOf(ProxmoxNodeFacade::getFacadeRoot()));
    }

    #[Test]
    public function purging_the_default_connection_by_name_forgets_the_singletons(): void
    {
        $node = $this->app->make('proxmox-node');
        $this->app->make(ProxmoxManager::class)->purge('primary');

        $this->assertNotSame($node, $this->app->make('proxmox-node'));
    }

    #[Test]
    public function purging_a_non_default_connection_leaves_the_default_singletons_alone(): void
    {
        $node = $this->app->make('proxmox-node');
        $this->app->make(ProxmoxManager::class)->purge('other');

        $this->assertSame($node, $this->app->make('proxmox-node'));
    }

    #[Test]
    public function purge_still_clears_the_manager_caches(): void
    {
        $manager = $this->app->make(ProxmoxManager::class);
        $conn    = $manager->connection();
        $node    = $manager->node();

        $manager->purge();

        $this->assertNotSame($conn, $manager->connection());
        $this->assertNotSame($node, $manager->node());
        $this->assertInstanceOf(ProxmoxNode::class, $manager->node());
    }

    // -------------------------------------------------------------------------
    // Standalone use: no booted app / no Log facade root
    // -------------------------------------------------------------------------

    private function withoutFacadeRoot(callable $fn): void
    {
        $saved = Facade::getFacadeApplication();
        Facade::setFacadeApplication(null);
        Facade::clearResolvedInstances();
        try {
            $fn();
        } finally {
            Facade::setFacadeApplication($saved);
            Facade::clearResolvedInstances();
        }
    }

    #[Test]
    public function safe_log_is_a_noop_without_a_facade_root(): void
    {
        $this->withoutFacadeRoot(function (): void {
            SafeLog::warning('no app bound', ['k' => 'v']);
            $this->addToAssertionCount(1);
        });
    }

    #[Test]
    public function safe_log_logs_when_a_logger_is_bound(): void
    {
        $logger = new class {
            public array $seen = [];
            public function warning(string $m, array $c = []): void { $this->seen[] = [$m, $c]; }
        };
        $this->app->instance('log', $logger);
        Facade::clearResolvedInstance('log');

        SafeLog::warning('hello', ['a' => 1]);

        $this->assertSame([['hello', ['a' => 1]]], $logger->seen);
    }

    #[Test]
    public function tls_disabled_construction_does_not_crash_standalone(): void
    {
        $this->withoutFacadeRoot(function (): void {
            $access = new ProxmoxAccess(host: '198.51.100.77', tokenId: 'root@pam!t', tokenSecret: 's', verifyTls: false);

            $this->assertInstanceOf(ProxmoxAccess::class, $access);
        });
    }

    #[Test]
    public function failed_ticket_login_surfaces_authentication_exception_not_a_facade_error(): void
    {
        $access = new class extends ProxmoxAccess {
            public function __construct()
            {
                parent::__construct(host: '127.0.0.1', password: 'pw');
            }

            protected function sendRequest(string $method, string $url, array $params = [], array $headers = []): array
            {
                throw new ConnectionException('Proxmox cURL error (7): boom', 7);
            }

            public function login(): void
            {
                $this->loginWithTicket();
            }
        };

        $this->withoutFacadeRoot(function () use ($access): void {
            $this->expectException(AuthenticationException::class);
            $access->login();
        });
    }
}
