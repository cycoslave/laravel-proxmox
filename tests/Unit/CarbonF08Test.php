<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\Exceptions\ApiException;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for carbon F-08 (CWE-400) in the guest-agent / delete helpers:
 *  - a hardcoded ostype=l26 overwrote the guest's real ostype (win11, BSD, ...);
 *  - an unconditional hard status/stop (no graceful shutdown, not even a running check);
 *  - fixed 30-35 s synchronous sleep() calls and a wall-clock sleep(2) loop in deleteVM().
 *
 * HTTP is mocked at the ProxmoxAccess layer and the clock is virtual: sleeping advances
 * the fake time and is recorded, nothing really waits.
 */
class CarbonF08Test extends TestCase
{
    private const UPID_SHUTDOWN = 'UPID:pve1:00001A2B:0003C4D5:6540F0A1:qmshutdown:100:root@pam:';
    private const UPID_STOP     = 'UPID:pve1:00001A2C:0003C4D6:6540F0A2:qmstop:100:root@pam:';
    private const UPID_START    = 'UPID:pve1:00001A2D:0003C4D7:6540F0A3:qmstart:100:root@pam:';

    /** @var array<int, array{method:string,path:string,data:array}> */
    private array $calls = [];

    /** @var int[] seconds passed to sleepSeconds() */
    private array $sleeps = [];

    protected function setUp(): void
    {
        parent::setUp();
        Log::swap(new class {
            public function warning($message, array $context = []) {}
            public function error($message, array $context = []) {}
        });
        $this->calls = [];
        $this->sleeps = [];
    }

    protected function tearDown(): void
    {
        Log::clearResolvedInstance();
        parent::tearDown();
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Fake PVE. $vm['status'] is the guest state. $tasks maps UPID => list of task-status
     * answers (last one repeats). $shutdownThrows makes POST status/shutdown raise an ApiException.
     *
     * @param array<string,mixed> $vm
     * @param array<string,array<int,array<string,mixed>>> $tasks
     */
    private function access(array &$vm, array $tasks = [], bool $shutdownThrows = false, int $pingFailures = 0): ProxmoxAccess
    {
        return new class($this->calls, $vm, $tasks, $shutdownThrows, $pingFailures) extends ProxmoxAccess {
            private int $pingsLeftToFail;

            public function __construct(
                private array &$calls,
                private array &$vm,
                private array $tasks,
                private bool $shutdownThrows,
                int $pingFailures,
            ) {
                $this->pingsLeftToFail = $pingFailures;
                parent::__construct(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            private function rec(string $m, string $p, array $d): void
            {
                $this->calls[] = ['method' => $m, 'path' => $p, 'data' => $d];
            }

            public function get(string $path, array $params = []): array
            {
                $this->rec('GET', $path, $params);
                if (str_ends_with($path, '/status/current')) {
                    return ['data' => $this->vm['current'] ?? ['status' => $this->vm['status']]];
                }
                if (preg_match('#/tasks/([^/]+)/status$#', $path, $m)) {
                    $this->tasks[$m[1]] ??= [['status' => 'stopped', 'exitstatus' => 'OK']];
                    $queue = &$this->tasks[$m[1]];
                    $answer = count($queue) > 1 ? array_shift($queue) : $queue[0];
                    if (($answer['status'] ?? null) === 'stopped' && ($answer['exitstatus'] ?? null) === 'OK') {
                        $this->vm['status'] = $this->vm['after'][$m[1]] ?? $this->vm['status'];
                    }
                    return ['data' => $answer];
                }
                if (str_ends_with($path, '/agent/ping')) {
                    if ($this->pingsLeftToFail-- > 0) {
                        throw new ApiException('QEMU guest agent is not running');
                    }
                    return ['data' => []];
                }
                return ['data' => null];
            }

            public function post(string $path, array $data = []): array
            {
                $this->rec('POST', $path, $data);
                if (str_ends_with($path, '/status/shutdown')) {
                    if ($this->shutdownThrows) {
                        throw new ApiException('shutdown refused');
                    }
                    return ['data' => ProxmoxNode_F08_UPIDS::SHUTDOWN];
                }
                if (str_ends_with($path, '/status/stop')) {
                    return ['data' => ProxmoxNode_F08_UPIDS::STOP];
                }
                if (str_ends_with($path, '/status/start')) {
                    return ['data' => ProxmoxNode_F08_UPIDS::START];
                }
                return ['data' => null];
            }

            public function delete(string $path, array $params = []): array
            {
                $this->rec('DELETE', $path, $params);
                return ['data' => 'UPID:pve1:0000DEAD:00000001:6540F0A9:qmdestroy:100:root@pam:'];
            }
        };
    }

    /** ProxmoxNode with a virtual clock; shrinks nothing, so the real default bounds are tested. */
    private function node(ProxmoxAccess $client): ProxmoxNode
    {
        return new class($client, $this->sleeps) extends ProxmoxNode {
            private float $now = 5000.0;

            public function __construct(ProxmoxAccess $client, private array &$sleeps)
            {
                parent::__construct($client);
            }

            public function virtualElapsed(): float { return $this->now - 5000.0; }

            protected function monotonicSeconds(): float { return $this->now; }

            protected function sleepSeconds(int $seconds): void
            {
                $this->sleeps[] = $seconds;
                $this->now += $seconds;
            }
        };
    }

    private static function ok(): array
    {
        return ['status' => 'stopped', 'exitstatus' => 'OK'];
    }

    private static function running(): array
    {
        return ['status' => 'running'];
    }

    /** @return string[] "METHOD path" of recorded calls */
    private function trace(): array
    {
        return array_map(fn ($c) => $c['method'] . ' ' . $c['path'], $this->calls);
    }

    private function callsTo(string $suffix, string $method = 'POST'): array
    {
        return array_values(array_filter(
            $this->calls,
            fn ($c) => $c['method'] === $method && str_ends_with($c['path'], $suffix)
        ));
    }

    // ------------------------------------------------------------------ ostype

    /** @return array<string, array{0:string}> */
    public static function ostypeMethods(): array
    {
        return [
            'fixGuestAgent'       => ['fixGuestAgent'],
            'enableGuestAgent'    => ['enableGuestAgent'],
            'configureGuestAgent' => ['configureGuestAgent'],
        ];
    }

    #[Test]
    #[DataProvider('ostypeMethods')]
    public function ostype_is_not_sent_unless_the_caller_passes_one(string $method): void
    {
        $vm = ['status' => 'stopped'];
        $node = $this->node($this->access($vm));

        $node->$method('pve1', 100);

        $configs = $this->callsTo('/config');
        $this->assertCount(1, $configs);
        $this->assertArrayNotHasKey('ostype', $configs[0]['data'], 'existing guest ostype must be preserved');
        $this->assertArrayHasKey('agent', $configs[0]['data']);
    }

    #[Test]
    #[DataProvider('ostypeMethods')]
    public function caller_supplied_ostype_is_sent(string $method): void
    {
        $vm = ['status' => 'stopped'];
        $node = $this->node($this->access($vm));

        $node->$method('pve1', 100, 'win11');

        $this->assertSame('win11', $this->callsTo('/config')[0]['data']['ostype']);
    }

    #[Test]
    #[DataProvider('ostypeMethods')]
    public function unknown_ostype_is_rejected_before_any_request(string $method): void
    {
        $vm = ['status' => 'stopped'];
        $node = $this->node($this->access($vm));

        $this->expectException(\InvalidArgumentException::class);
        try {
            $node->$method('pve1', 100, 'l26,ide0=evil');
        } finally {
            $this->assertSame([], $this->calls);
        }
    }

    #[Test]
    public function enable_guest_agent_success_shape_is_unchanged(): void
    {
        $vm = ['status' => 'stopped'];
        $result = $this->node($this->access($vm))->enableGuestAgent('pve1', 100);

        $this->assertTrue($result['success']);
        $this->assertSame(['agent' => 1], $result['config']);
        $this->assertArrayHasKey('response', $result);
    }

    // ------------------------------------------------------------------ graceful stop

    #[Test]
    public function fix_guest_agent_shuts_down_gracefully_and_never_hard_stops_when_that_works(): void
    {
        $vm = ['status' => 'running', 'after' => [self::UPID_SHUTDOWN => 'stopped']];
        $tasks = [
            self::UPID_SHUTDOWN => [self::ok()],
            self::UPID_START    => [self::ok()],
        ];
        $node = $this->node($this->access($vm, $tasks));

        $result = $node->fixGuestAgent('pve1', 100);

        $this->assertCount(1, $this->callsTo('/status/shutdown'));
        $this->assertSame([], $this->callsTo('/status/stop'), 'hard stop must not be used when shutdown succeeds');
        $this->assertCount(1, $this->callsTo('/status/start'));
        $this->assertGreaterThan(0, $this->callsTo('/status/shutdown')[0]['data']['timeout'], 'shutdown is bounded');
        $this->assertTrue($result['success']);
        $this->assertTrue($result['vm_restarted']);
        $this->assertTrue($result['agent_running']);
        $this->assertSame([], $this->sleeps, 'tasks finished on the first poll: nothing to wait for');
    }

    #[Test]
    public function failed_graceful_shutdown_falls_back_to_hard_stop(): void
    {
        $vm = ['status' => 'running'];
        $tasks = [
            self::UPID_SHUTDOWN => [['status' => 'stopped', 'exitstatus' => 'VM quit/powerdown failed - got timeout']],
            self::UPID_STOP     => [self::ok()],
            self::UPID_START    => [self::ok()],
        ];
        $node = $this->node($this->access($vm, $tasks));

        $result = $node->fixGuestAgent('pve1', 100);

        $order = array_values(array_filter($this->trace(), fn ($t) => str_contains($t, '/status/') && !str_contains($t, 'tasks')
            && str_starts_with($t, 'POST')));
        $this->assertSame([
            'POST nodes/pve1/qemu/100/status/shutdown',
            'POST nodes/pve1/qemu/100/status/stop',
            'POST nodes/pve1/qemu/100/status/start',
        ], $order);
        $this->assertTrue($result['vm_restarted']);
    }

    #[Test]
    public function rejected_shutdown_request_also_falls_back_to_hard_stop(): void
    {
        $vm = ['status' => 'running'];
        $tasks = [self::UPID_STOP => [self::ok()], self::UPID_START => [self::ok()]];
        $node = $this->node($this->access($vm, $tasks, shutdownThrows: true));

        $node->fixGuestAgent('pve1', 100);

        $this->assertCount(1, $this->callsTo('/status/stop'));
        $this->assertCount(1, $this->callsTo('/status/start'));
    }

    #[Test]
    public function hung_shutdown_is_bounded_then_falls_back_without_real_sleeping(): void
    {
        $vm = ['status' => 'running'];
        $tasks = [
            self::UPID_SHUTDOWN => [['status' => 'running']], // never finishes
            self::UPID_STOP     => [self::ok()],
            self::UPID_START    => [self::ok()],
        ];
        $node = $this->node($this->access($vm, $tasks));

        $realStart = microtime(true);
        $node->fixGuestAgent('pve1', 100);
        $realElapsed = microtime(true) - $realStart;

        $this->assertCount(1, $this->callsTo('/status/stop'), 'timed-out shutdown falls back to stop');
        $this->assertLessThan(1.0, $realElapsed, 'tests must not really sleep');
        $this->assertNotEmpty($this->sleeps);
        // shutdown timeout (60) + 10 s slack; the virtual clock never runs past the bound
        $this->assertLessThanOrEqual(70 + 2, $node->virtualElapsed());
        $this->assertLessThanOrEqual(2, max($this->sleeps));
    }

    #[Test]
    public function hard_stop_that_never_finishes_throws_instead_of_waiting_forever(): void
    {
        $vm = ['status' => 'running'];
        $tasks = [
            self::UPID_SHUTDOWN => [['status' => 'running']],
            self::UPID_STOP     => [['status' => 'running']],
        ];
        $node = $this->node($this->access($vm, $tasks));

        try {
            $node->configureGuestAgent('pve1', 100);
            $this->fail('Expected exception');
        } catch (\Exception $e) {
            $this->assertSame('Failed to configure guest agent.', $e->getMessage());
            $this->assertInstanceOf(\Cycoslave\Proxmox\Exceptions\TaskTimeoutException::class, $e->getPrevious());
        }
        $this->assertLessThanOrEqual(70 + 60 + 4, $node->virtualElapsed());
        $this->assertSame([], $this->callsTo('/status/start'), 'no start after a failed stop');
    }

    // ------------------------------------------------------------------ configureGuestAgent

    #[Test]
    public function configure_guest_agent_does_not_stop_a_guest_that_is_not_running(): void
    {
        $vm = ['status' => 'stopped'];
        $tasks = [self::UPID_START => [self::ok()]];
        $node = $this->node($this->access($vm, $tasks));

        $result = $node->configureGuestAgent('pve1', 100);

        $this->assertSame([], $this->callsTo('/status/stop'));
        $this->assertSame([], $this->callsTo('/status/shutdown'));
        $this->assertCount(1, $this->callsTo('/status/start'));
        $this->assertTrue($result['success']);
        $this->assertSame(['success', 'config_result', 'start_result', 'agent_status'], array_keys($result));
    }

    #[Test]
    public function configure_guest_agent_polls_the_agent_with_a_bound_instead_of_sleeping_20_seconds(): void
    {
        $vm = ['status' => 'stopped'];
        $tasks = [self::UPID_START => [self::ok()]];
        $node = $this->node($this->access($vm, $tasks, pingFailures: 3));

        $result = $node->configureGuestAgent('pve1', 100);

        $this->assertTrue($result['success']);
        $this->assertSame([2, 2, 2], $this->sleeps);
    }

    #[Test]
    public function configure_guest_agent_gives_up_after_the_agent_timeout(): void
    {
        $vm = ['status' => 'stopped'];
        $tasks = [self::UPID_START => [self::ok()]];
        $node = $this->node($this->access($vm, $tasks, pingFailures: PHP_INT_MAX));

        try {
            $node->configureGuestAgent('pve1', 100);
            $this->fail('Expected exception');
        } catch (\Exception $e) {
            $this->assertSame('Failed to configure guest agent.', $e->getMessage());
        }
        $this->assertSame(30.0, $node->virtualElapsed());
    }

    #[Test]
    public function fix_guest_agent_reports_agent_not_running_after_bounded_wait(): void
    {
        $vm = ['status' => 'running'];
        $tasks = [
            self::UPID_SHUTDOWN => [self::ok()],
            self::UPID_START    => [self::ok()],
        ];
        $node = $this->node($this->access($vm, $tasks, pingFailures: PHP_INT_MAX));

        $result = $node->fixGuestAgent('pve1', 100);

        $this->assertTrue($result['success']);
        $this->assertFalse($result['agent_running']);
        $this->assertNotEmpty($result['next_steps']);
        $this->assertLessThanOrEqual(35, $node->virtualElapsed());
    }

    #[Test]
    public function fix_guest_agent_on_a_stopped_guest_neither_stops_nor_starts_it(): void
    {
        $vm = ['status' => 'stopped'];
        $node = $this->node($this->access($vm));

        $result = $node->fixGuestAgent('pve1', 100);

        $this->assertSame([], $this->callsTo('/status/stop'));
        $this->assertSame([], $this->callsTo('/status/shutdown'));
        $this->assertSame([], $this->callsTo('/status/start'));
        $this->assertFalse($result['vm_restarted']);
        $this->assertSame([], $this->sleeps);
    }

    // ------------------------------------------------------------------ deleteVM

    #[Test]
    public function delete_vm_force_uses_graceful_shutdown_then_deletes(): void
    {
        $vm = ['status' => 'running', 'after' => [self::UPID_SHUTDOWN => 'stopped']];
        $tasks = [self::UPID_SHUTDOWN => [['status' => 'running'], self::ok()]];
        $node = $this->node($this->access($vm, $tasks));

        $result = $node->deleteVM('pve1', 100, force: true, purge: true);

        $this->assertTrue($result['success']);
        $this->assertSame([], $this->callsTo('/status/stop'), 'no hard stop when graceful shutdown works');
        $this->assertCount(1, $this->callsTo('/status/shutdown'));
        $this->assertCount(1, $this->callsTo('nodes/pve1/qemu/100', 'DELETE'));
        $this->assertSame([2], $this->sleeps, 'one bounded task poll interval, not a fixed sleep loop');
    }

    #[Test]
    public function delete_vm_force_falls_back_to_hard_stop(): void
    {
        $vm = ['status' => 'running', 'after' => [self::UPID_STOP => 'stopped']];
        $tasks = [
            self::UPID_SHUTDOWN => [['status' => 'stopped', 'exitstatus' => 'timeout']],
            self::UPID_STOP     => [self::ok()],
        ];
        $node = $this->node($this->access($vm, $tasks));

        $result = $node->deleteVM('pve1', 100, force: true);

        $this->assertTrue($result['success']);
        $this->assertCount(1, $this->callsTo('/status/stop'));
    }

    #[Test]
    public function delete_vm_gives_up_with_the_original_message_when_the_guest_never_stops(): void
    {
        $vm = ['status' => 'running']; // tasks "succeed" but the guest stays running
        $tasks = [self::UPID_SHUTDOWN => [self::ok()]];
        $node = $this->node($this->access($vm, $tasks));

        $realStart = microtime(true);
        try {
            $node->deleteVM('pve1', 100, force: true);
            $this->fail('Expected exception');
        } catch (\Exception $e) {
            $this->assertSame('Failed to stop VM 100 within timeout period', $e->getMessage());
        }
        $this->assertLessThan(1.0, microtime(true) - $realStart);
        $this->assertSame(60.0, $node->virtualElapsed(), 'bounded by guestTaskTimeout');
        $this->assertSame([], $this->callsTo('nodes/pve1/qemu/100', 'DELETE'), 'nothing deleted');
    }

    #[Test]
    public function delete_vm_without_force_still_refuses_a_running_guest(): void
    {
        $vm = ['status' => 'running'];
        $node = $this->node($this->access($vm));

        try {
            $node->deleteVM('pve1', 100);
            $this->fail('Expected exception');
        } catch (\Exception $e) {
            $this->assertSame('Cannot delete running VM. Either stop the VM first or use force option.', $e->getMessage());
        }
        $this->assertSame([], $this->callsTo('/status/shutdown'));
        $this->assertSame([], $this->callsTo('/status/stop'));
    }

    #[Test]
    public function delete_vm_tolerates_a_status_payload_without_status_key(): void
    {
        $vm = ['status' => 'stopped', 'current' => ['name' => 'x']]; // no 'status' key
        $node = $this->node($this->access($vm));

        $result = $node->deleteVM('pve1', 100);

        $this->assertTrue($result['success']);
        $this->assertSame([], $this->sleeps);
    }

    #[Test]
    public function delete_vm_on_a_stopped_guest_deletes_immediately(): void
    {
        $vm = ['status' => 'stopped'];
        $node = $this->node($this->access($vm));

        $result = $node->deleteVM('pve1', 100, purge: true);

        $this->assertTrue($result['success']);
        $this->assertSame([], $this->callsTo('/status/shutdown'));
        $this->assertSame([], $this->callsTo('/status/stop'));
        $this->assertSame([], $this->sleeps);
    }
}

/** Constant holder for the anonymous ProxmoxAccess stub (anonymous classes cannot see test consts). */
final class ProxmoxNode_F08_UPIDS
{
    public const SHUTDOWN = 'UPID:pve1:00001A2B:0003C4D5:6540F0A1:qmshutdown:100:root@pam:';
    public const STOP     = 'UPID:pve1:00001A2C:0003C4D6:6540F0A2:qmstop:100:root@pam:';
    public const START    = 'UPID:pve1:00001A2D:0003C4D7:6540F0A3:qmstart:100:root@pam:';
}
