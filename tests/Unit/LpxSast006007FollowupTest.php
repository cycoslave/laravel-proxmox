<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\Exceptions\ProxmoxException;
use Cycoslave\Proxmox\Exceptions\TaskTimeoutException;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * LPX-SAST-006 (volume/CIDR validators, storageUpload/destroyCephPool signatures)
 * and LPX-SAST-007 (checkTaskStatus failure, waitForTaskCompletion timeout).
 * No network: ProxmoxAccess is stubbed and the clock/sleep are virtual.
 */
class LpxSast006007FollowupTest extends TestCase
{
    private const UPID = 'UPID:pve1:00001A2B:0003C4D5:6540F0A1:vzdump:100:root@pam:';

    /** @param \Closure(string,string,array):array $responder */
    private function access(array &$calls, \Closure|array $responder = ['data' => null]): ProxmoxAccess
    {
        return new class($calls, $responder) extends ProxmoxAccess {
            public function __construct(private array &$calls, private \Closure|array $responder)
            {
                parent::__construct(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            private function record(string $m, string $p, array $d): array
            {
                $this->calls[] = ['method' => $m, 'path' => $p, 'data' => $d];
                return $this->responder instanceof \Closure ? ($this->responder)($m, $p, $d) : $this->responder;
            }

            public function get(string $path, array $params = []): array { return $this->record('GET', $path, $params); }
            public function post(string $path, array $data = []): array { return $this->record('POST', $path, $data); }
            public function put(string $path, array $data = []): array { return $this->record('PUT', $path, $data); }
            public function delete(string $path, array $params = []): array { return $this->record('DELETE', $path, $params); }
        };
    }

    /** ProxmoxNode with a virtual clock: sleeping advances time and is recorded. */
    private function virtualClockNode(array &$calls, \Closure|array $responder, array &$sleeps): ProxmoxNode
    {
        return new class($this->access($calls, $responder), $sleeps) extends ProxmoxNode {
            private float $now = 1000.0;

            public function __construct(ProxmoxAccess $client, private array &$sleeps)
            {
                parent::__construct($client);
            }

            protected function monotonicSeconds(): float { return $this->now; }

            protected function sleepSeconds(int $seconds): void
            {
                $this->sleeps[] = $seconds;
                $this->now += $seconds;
            }
        };
    }

    // ------------------------------------------------------------------
    // LPX-SAST-006: volume validator
    // ------------------------------------------------------------------

    /** @return array<string, array{0: string, 1: string}> */
    public static function validVolumes(): array
    {
        return [
            'iso'        => ['local:iso/ubuntu-24.04.iso', 'local%3Aiso%2Fubuntu-24.04.iso'],
            'lvm disk'   => ['local-lvm:vm-100-disk-0', 'local-lvm%3Avm-100-disk-0'],
            'vztmpl'     => ['local:vztmpl/debian-12_12.2-1_amd64.tar.zst', 'local%3Avztmpl%2Fdebian-12_12.2-1_amd64.tar.zst'],
            'backup'     => ['pbs:backup/vm/100/2026-10-31T00:00:00Z', 'pbs%3Abackup%2Fvm%2F100%2F2026-10-31T00%3A00%3A00Z'],
        ];
    }

    #[Test]
    #[DataProvider('validVolumes')]
    public function volume_methods_accept_real_volume_ids_and_encode_them_as_one_segment(string $volume, string $encoded): void
    {
        $calls = [];
        $node = new ProxmoxNode($this->access($calls, ['data' => []]));

        $node->storageContentVolume('pve1', 'local', $volume);
        $node->copyStorageContentVolume('pve1', 'local', $volume, ['target' => 'x']);
        $node->deleteStorageContentVolume('pve1', 'local', $volume);

        $this->assertSame(['GET', 'POST', 'DELETE'], array_column($calls, 'method'));
        foreach ($calls as $call) {
            $this->assertSame("nodes/pve1/storage/local/content/{$encoded}", $call['path']);
        }
    }

    /** @return array<string, array{0: string}> */
    public static function badVolumes(): array
    {
        return [
            'empty'            => [''],
            'dotdot'           => ['..'],
            'traversal'        => ['local:iso/../../cluster'],
            'leading slash'    => ['/etc/passwd'],
            'trailing slash'   => ['local:iso/'],
            'double slash'     => ['local:iso//x.iso'],
            'dot component'    => ['local:iso/./x.iso'],
            'percent encoded'  => ['local:iso%2f..%2fx'],
            'query injection'  => ['local:iso/x.iso?foo=bar'],
            'fragment'         => ['local:iso/x.iso#a'],
            'backslash'        => ['local:iso\\x.iso'],
            'space'            => ['local:iso/x y.iso'],
            'newline'          => ["local:iso/x.iso\n"],
            'null byte'        => ["local:iso/x\0.iso"],
        ];
    }

    #[Test]
    #[DataProvider('badVolumes')]
    public function volume_methods_reject_unsafe_values_without_a_request(string $volume): void
    {
        foreach (['storageContentVolume', 'deleteStorageContentVolume'] as $method) {
            $calls = [];
            $node = new ProxmoxNode($this->access($calls));
            try {
                $node->{$method}('pve1', 'local', $volume);
                $this->fail("{$method} accepted an unsafe volume");
            } catch (\InvalidArgumentException) {
                $this->assertSame([], $calls);
            }
        }

        $calls = [];
        $this->expectException(\InvalidArgumentException::class);
        (new ProxmoxNode($this->access($calls)))->copyStorageContentVolume('pve1', 'local', $volume, []);
    }

    // ------------------------------------------------------------------
    // LPX-SAST-006: CIDR validator
    // ------------------------------------------------------------------

    /** @return array<string, array{0: string, 1: string}> */
    public static function validCidrs(): array
    {
        return [
            'v4 net'    => ['192.168.1.0/24', '192.168.1.0%2F24'],
            'v4 host'   => ['10.0.0.1', '10.0.0.1'],
            'v4 /0'     => ['0.0.0.0/0', '0.0.0.0%2F0'],
            'v4 /32'    => ['10.1.2.3/32', '10.1.2.3%2F32'],
            'v6 net'    => ['2001:db8::/32', '2001%3Adb8%3A%3A%2F32'],
            'v6 host'   => ['::1', '%3A%3A1'],
            'v6 /128'   => ['fe80::1/128', 'fe80%3A%3A1%2F128'],
            'nomatch'   => ['!10.0.0.0/8', '%2110.0.0.0%2F8'],
        ];
    }

    #[Test]
    #[DataProvider('validCidrs')]
    public function ipset_cidr_methods_accept_real_cidrs_and_encode_them(string $cidr, string $encoded): void
    {
        $calls = [];
        $node = new ProxmoxNode($this->access($calls, ['data' => []]));

        $node->lxcFirewallIpsetNameCidr('pve1', 101, 'web', $cidr);
        $node->updateLxcFirewallIpsetNameCidr('pve1', 101, 'web', $cidr, ['comment' => 'x']);
        $node->deleteLxcFirewallIpsetNameCidr('pve1', 101, 'web', $cidr);
        $node->qemuFirewallIpsetNameCidr('pve1', 100, 'web', $cidr);
        $node->updateQemuFirewallIpsetNameCidr('pve1', 100, 'web', $cidr, ['comment' => 'x']);
        $node->deleteQemuFirewallIpsetNameCidr('pve1', 100, 'web', $cidr);

        $this->assertCount(6, $calls);
        foreach ($calls as $i => $call) {
            $kind = $i < 3 ? 'lxc/101' : 'qemu/100';
            $this->assertSame("nodes/pve1/{$kind}/firewall/ipset/web/{$encoded}", $call['path']);
        }
    }

    /** @return array<string, array{0: string}> */
    public static function badCidrs(): array
    {
        return [
            'empty'           => [''],
            'hostname'        => ['example.com'],
            'traversal'       => ['../../cluster'],
            'bad octet'       => ['999.1.1.1/24'],
            'v4 prefix > 32'  => ['10.0.0.0/33'],
            'v6 prefix > 128' => ['2001:db8::/129'],
            'neg prefix'      => ['10.0.0.0/-1'],
            'alpha prefix'    => ['10.0.0.0/ab'],
            'empty prefix'    => ['10.0.0.0/'],
            'two slashes'     => ['10.0.0.0/24/8'],
            'double bang'     => ['!!10.0.0.0/8'],
            'query'           => ['10.0.0.0/24?x=1'],
            'space'           => ['10.0.0.0/24 '],
            'newline'         => ["10.0.0.0/24\n"],
            'null byte'       => ["10.0.0.0\0/24"],
            'port'            => ['10.0.0.1:8006'],
        ];
    }

    #[Test]
    #[DataProvider('badCidrs')]
    public function ipset_cidr_methods_reject_invalid_cidrs_without_a_request(string $cidr): void
    {
        $calls = [];
        $node = new ProxmoxNode($this->access($calls));

        $attempts = [
            fn () => $node->lxcFirewallIpsetNameCidr('pve1', 101, 'web', $cidr),
            fn () => $node->updateLxcFirewallIpsetNameCidr('pve1', 101, 'web', $cidr, []),
            fn () => $node->deleteLxcFirewallIpsetNameCidr('pve1', 101, 'web', $cidr),
            fn () => $node->qemuFirewallIpsetNameCidr('pve1', 100, 'web', $cidr),
            fn () => $node->updateQemuFirewallIpsetNameCidr('pve1', 100, 'web', $cidr, []),
            fn () => $node->deleteQemuFirewallIpsetNameCidr('pve1', 100, 'web', $cidr),
        ];

        foreach ($attempts as $attempt) {
            try {
                $attempt();
                $this->fail('An invalid CIDR reached the API');
            } catch (\InvalidArgumentException) {
                // expected
            }
        }
        $this->assertSame([], $calls);
    }

    // ------------------------------------------------------------------
    // LPX-SAST-006: new signatures
    // ------------------------------------------------------------------

    #[Test]
    public function storage_upload_posts_to_the_storage_upload_endpoint(): void
    {
        $calls = [];
        $data = ['content' => 'iso', 'filename' => 'x.iso'];
        $result = (new ProxmoxNode($this->access($calls, ['data' => self::UPID])))->storageUpload('pve1', 'local', $data);

        $this->assertTrue($result['success']);
        $this->assertSame('POST', $calls[0]['method']);
        $this->assertSame('nodes/pve1/storage/local/upload', $calls[0]['path']);
        $this->assertSame($data, $calls[0]['data']);
    }

    #[Test]
    public function storage_upload_returns_failure_envelope_when_response_has_no_data_key(): void
    {
        $calls = [];
        $this->assertFalse((new ProxmoxNode($this->access($calls, [])))->storageUpload('pve1', 'local')['success']);
    }

    #[Test]
    public function storage_upload_rejects_unsafe_storage_and_node(): void
    {
        $calls = [];
        $node = new ProxmoxNode($this->access($calls));
        foreach ([['pve1', '../x'], ['pve1', 'a/b'], ['pve1', ''], ['a/b', 'local']] as [$n, $s]) {
            try {
                $node->storageUpload($n, $s, []);
                $this->fail('unsafe segment accepted');
            } catch (\InvalidArgumentException) {
            }
        }
        $this->assertSame([], $calls);
    }

    #[Test]
    public function destroy_ceph_pool_deletes_the_named_pool(): void
    {
        $calls = [];
        $result = (new ProxmoxNode($this->access($calls, ['data' => self::UPID])))->destroyCephPool('pve1', 'rbd-pool');

        $this->assertTrue($result['success']);
        $this->assertSame('DELETE', $calls[0]['method']);
        $this->assertSame('nodes/pve1/ceph/pools/rbd-pool', $calls[0]['path']);
    }

    #[Test]
    public function destroy_ceph_pool_rejects_unsafe_pool_names(): void
    {
        $calls = [];
        $node = new ProxmoxNode($this->access($calls));
        foreach (['', '..', '../mon', 'a/b', "p\n", 'a b'] as $name) {
            try {
                $node->destroyCephPool('pve1', $name);
                $this->fail("accepted pool name [{$name}]");
            } catch (\InvalidArgumentException) {
            }
        }
        $this->assertSame([], $calls);
    }

    #[Test]
    public function changed_signatures_require_the_new_parameters(): void
    {
        $upload = new ReflectionMethod(ProxmoxNode::class, 'storageUpload');
        $this->assertSame(['node', 'storage', 'data'], array_map(fn ($p) => $p->getName(), $upload->getParameters()));
        $this->assertSame(2, $upload->getNumberOfRequiredParameters());

        $pool = new ReflectionMethod(ProxmoxNode::class, 'destroyCephPool');
        $this->assertSame(['node', 'name'], array_map(fn ($p) => $p->getName(), $pool->getParameters()));
        $this->assertSame(2, $pool->getNumberOfRequiredParameters());
    }

    // ------------------------------------------------------------------
    // LPX-SAST-007: checkTaskStatus
    // ------------------------------------------------------------------

    #[Test]
    public function check_task_status_returns_the_envelope_for_a_running_task(): void
    {
        $calls = [];
        $env = ['data' => ['status' => 'running']];
        $this->assertSame($env, (new ProxmoxNode($this->access($calls, $env)))->checkTaskStatus('pve1', self::UPID));
    }

    #[Test]
    public function check_task_status_returns_the_envelope_for_a_successful_task(): void
    {
        $calls = [];
        $env = ['data' => ['status' => 'stopped', 'exitstatus' => 'OK']];
        $this->assertSame($env, (new ProxmoxNode($this->access($calls, $env)))->checkTaskStatus('pve1', self::UPID));
    }

    #[Test]
    public function check_task_status_throws_for_a_failed_task(): void
    {
        $calls = [];
        $node = new ProxmoxNode($this->access($calls, ['data' => ['status' => 'stopped', 'exitstatus' => 'ERROR: boom']]));

        $this->expectException(ProxmoxException::class);
        $this->expectExceptionMessage('Task failed with exit status: ERROR: boom');
        $node->checkTaskStatus('pve1', self::UPID);
    }

    #[Test]
    public function check_task_status_does_not_raise_a_warning_when_data_is_missing(): void
    {
        $calls = [];
        $this->assertSame([], (new ProxmoxNode($this->access($calls, [])))->checkTaskStatus('pve1', self::UPID));
    }

    // ------------------------------------------------------------------
    // LPX-SAST-007: waitForTaskCompletion
    // ------------------------------------------------------------------

    #[Test]
    public function wait_returns_data_once_the_task_stops_ok(): void
    {
        $calls = [];
        $sleeps = [];
        $n = 0;
        $node = $this->virtualClockNode($calls, function () use (&$n) {
            return ++$n < 3
                ? ['data' => ['status' => 'running']]
                : ['data' => ['status' => 'stopped', 'exitstatus' => 'OK']];
        }, $sleeps);

        $this->assertSame(['status' => 'stopped', 'exitstatus' => 'OK'], $node->waitForTaskCompletion('pve1', self::UPID));
        $this->assertCount(3, $calls);
        $this->assertSame([2, 2], $sleeps);
        $this->assertSame("nodes/pve1/tasks/" . self::UPID . "/status", $calls[0]['path']);
    }

    #[Test]
    public function wait_throws_task_timeout_when_the_task_keeps_running(): void
    {
        $calls = [];
        $sleeps = [];
        $node = $this->virtualClockNode($calls, ['data' => ['status' => 'running']], $sleeps);

        try {
            $node->waitForTaskCompletion('pve1', self::UPID, 10, 3);
            $this->fail('expected TaskTimeoutException');
        } catch (TaskTimeoutException $e) {
            $this->assertInstanceOf(ProxmoxException::class, $e);
            $this->assertStringContainsString('10s', $e->getMessage());
        }

        // Never sleeps past the deadline, and the loop is bounded.
        $this->assertSame(10, array_sum($sleeps));
        $this->assertSame([3, 3, 3, 1], $sleeps);
        $this->assertCount(5, $calls);
    }

    #[Test]
    public function wait_default_timeout_is_120_seconds(): void
    {
        $calls = [];
        $sleeps = [];
        $node = $this->virtualClockNode($calls, ['data' => ['status' => 'running']], $sleeps);

        $this->assertSame(120, (new ReflectionMethod(ProxmoxNode::class, 'waitForTaskCompletion'))->getParameters()[2]->getDefaultValue());

        $this->expectException(TaskTimeoutException::class);
        try {
            $node->waitForTaskCompletion('pve1', self::UPID);
        } finally {
            $this->assertSame(120, array_sum($sleeps));
        }
    }

    #[Test]
    public function wait_treats_a_missing_data_key_as_still_running_until_the_deadline(): void
    {
        $calls = [];
        $sleeps = [];
        $node = $this->virtualClockNode($calls, [], $sleeps);

        $this->expectException(TaskTimeoutException::class);
        $node->waitForTaskCompletion('pve1', self::UPID, 4, 2);
    }

    #[Test]
    public function wait_throws_immediately_for_a_failed_task(): void
    {
        $calls = [];
        $sleeps = [];
        $node = $this->virtualClockNode($calls, ['data' => ['status' => 'stopped', 'exitstatus' => 'job errors']], $sleeps);

        try {
            $node->waitForTaskCompletion('pve1', self::UPID);
            $this->fail('expected ProxmoxException');
        } catch (TaskTimeoutException) {
            $this->fail('failure must not be reported as a timeout');
        } catch (ProxmoxException $e) {
            $this->assertSame('Task failed with exit status: job errors', $e->getMessage());
        }
        $this->assertSame([], $sleeps);
        $this->assertCount(1, $calls);
    }

    #[Test]
    public function wait_rejects_non_positive_timeouts_and_intervals_without_a_request(): void
    {
        $calls = [];
        $sleeps = [];
        $node = $this->virtualClockNode($calls, ['data' => ['status' => 'running']], $sleeps);

        foreach ([[0, 2], [-5, 2], [10, 0], [10, -1]] as [$timeout, $interval]) {
            try {
                $node->waitForTaskCompletion('pve1', self::UPID, $timeout, $interval);
                $this->fail('accepted invalid timeout/interval');
            } catch (\InvalidArgumentException) {
            }
        }
        $this->assertSame([], $calls);
    }

    #[Test]
    public function wait_still_rejects_an_unsafe_upid(): void
    {
        $calls = [];
        $this->expectException(\InvalidArgumentException::class);
        try {
            (new ProxmoxNode($this->access($calls)))->waitForTaskCompletion('pve1', 'UPID:x/../../y');
        } finally {
            $this->assertSame([], $calls);
        }
    }
}
