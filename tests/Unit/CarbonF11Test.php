<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Carbon F-11 (CWE-253): 27 ProxmoxNode methods broke the documented
 * ResponseHelper envelope ['success' => bool, 'message' => string, 'data'? => mixed].
 *
 *   - vmQuery, setVMConfig, applyCloudInitVM, injectSSHCredentials, rebuildCloudInit
 *     returned the raw client payload ['data' => ...] (no success/message).
 *   - 22 node methods passed the whole client response instead of its 'data' member
 *     to ResponseHelper::generate(), so payloads were double-nested as $res['data']['data'].
 *
 * The HTTP client is replaced with a scripted stub; nothing touches the network.
 */
class CarbonF11Test extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Log::swap(new class {
            public function warning($message, array $context = []) {}
            public function error($message, array $context = []) {}
        });
    }

    protected function tearDown(): void
    {
        Log::clearResolvedInstance();
        parent::tearDown();
    }

    /** @param array<int, array<string, mixed>> $calls */
    private function node(array &$calls, array|\Closure $responder): ProxmoxNode
    {
        $access = new class($calls, $responder) extends ProxmoxAccess {
            public function __construct(private array &$calls, private array|\Closure $responder)
            {
                parent::__construct(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            private function record(string $method, string $path, array $data): array
            {
                $this->calls[] = ['method' => $method, 'path' => $path, 'data' => $data];
                return $this->responder instanceof \Closure
                    ? ($this->responder)($method, $path)
                    : $this->responder;
            }

            public function get(string $path, array $params = []): array { return $this->record('GET', $path, $params); }
            public function post(string $path, array $data = []): array { return $this->record('POST', $path, $data); }
            public function put(string $path, array $data = []): array { return $this->record('PUT', $path, $data); }
            public function delete(string $path, array $params = []): array { return $this->record('DELETE', $path, $params); }
        };

        return new ProxmoxNode($access);
    }

    /**
     * @return array<string, array{0: string, 1: array, 2: string, 3: string}>
     *         [method, arguments, HTTP verb, path (trailing-slash agnostic)]
     */
    public static function fixedMethods(): array
    {
        $payload = ['node' => 'x'];

        return [
            // The five methods that returned the raw client payload.
            'vmQuery'             => ['vmQuery', ['pve1', 100], 'GET', 'nodes/pve1/qemu/100/status/current'],
            'setVMConfig'         => ['setVMConfig', ['pve1', 100, ['name' => 'x']], 'POST', 'nodes/pve1/qemu/100/config'],
            'applyCloudInitVM'    => ['applyCloudInitVM', ['pve1', 100], 'POST', 'nodes/pve1/qemu/100/cloudinit'],
            'injectSSHCredentials' => ['injectSSHCredentials', ['pve1', 100, 'ubuntu', 'pw'], 'POST', 'nodes/pve1/qemu/100/config'],
            'rebuildCloudInit'    => ['rebuildCloudInit', ['pve1', 100], 'POST', 'nodes/pve1/qemu/100/cloudinit'],
            // The 22 methods that double-nested 'data'.
            'aplinfo'             => ['aplinfo', ['pve1'], 'GET', 'nodes/pve1/aplinfo'],
            'downloadTemplate'    => ['downloadTemplate', ['pve1', $payload], 'POST', 'nodes/pve1/aplinfo'],
            'dns'                 => ['dns', ['pve1'], 'GET', 'nodes/pve1/dns'],
            'setDns'              => ['setDns', ['pve1', $payload], 'PUT', 'nodes/pve1/dns'],
            'execute'             => ['execute', ['pve1', $payload], 'POST', 'nodes/pve1/execute'],
            'migrateAll'          => ['migrateAll', ['pve1', $payload], 'POST', 'nodes/pve1/migrateall'],
            'netstat'             => ['netstat', ['pve1'], 'GET', 'nodes/pve1/netstat'],
            'report'              => ['report', ['pve1'], 'GET', 'nodes/pve1/report'],
            'rrd'                 => ['rrd', ['pve1', 'cpu', 'hour'], 'GET', 'nodes/pve1/rrd'],
            'rrddata'             => ['rrddata', ['pve1', 'hour'], 'GET', 'nodes/pve1/rrddata'],
            'spiceShell'          => ['spiceShell', ['pve1', $payload], 'POST', 'nodes/pve1/spiceshell'],
            'startAll'            => ['startAll', ['pve1', $payload], 'POST', 'nodes/pve1/startall'],
            'reboot'              => ['reboot', ['pve1', ['command' => 'reboot']], 'POST', 'nodes/pve1/status'],
            'stopAll'             => ['stopAll', ['pve1', $payload], 'POST', 'nodes/pve1/stopall'],
            'subscription'        => ['subscription', ['pve1'], 'GET', 'nodes/pve1/subscription'],
            'updateSubscription'  => ['updateSubscription', ['pve1', $payload], 'POST', 'nodes/pve1/subscription'],
            'setSubscription'     => ['setSubscription', ['pve1', ['key' => 'k']], 'PUT', 'nodes/pve1/subscription'],
            'syslog'              => ['syslog', ['pve1'], 'GET', 'nodes/pve1/syslog'],
            'time'                => ['time', ['pve1'], 'GET', 'nodes/pve1/time'],
            'setTime'             => ['setTime', ['pve1', ['timezone' => 'UTC']], 'PUT', 'nodes/pve1/time'],
            'createVNCShell'      => ['createVNCShell', ['pve1', $payload], 'POST', 'nodes/pve1/vncshell'],
            'vNCWebSocket'        => ['vNCWebSocket', ['pve1', 5900, 'ticket'], 'GET', 'nodes/pve1/vncwebsocket'],
        ];
    }

    private function assertEnvelope(array $r): void
    {
        $this->assertArrayHasKey('success', $r);
        $this->assertIsBool($r['success']);
        $this->assertArrayHasKey('message', $r);
        $this->assertIsString($r['message']);
        $this->assertNotSame('', $r['message']);
        $this->assertEmpty(array_diff(array_keys($r), ['success', 'message', 'data']), 'unexpected envelope keys');
    }

    #[Test]
    public function the_provider_covers_all_27_methods(): void
    {
        $this->assertCount(27, self::fixedMethods());
    }

    #[Test]
    #[DataProvider('fixedMethods')]
    public function success_returns_the_envelope_with_unnested_array_data(string $method, array $args, string $verb, string $path): void
    {
        $calls = [];
        $r = $this->node($calls, ['data' => ['k' => 'v']])->$method(...$args);

        $this->assertEnvelope($r);
        $this->assertTrue($r['success']);
        $this->assertSame(['k' => 'v'], $r['data'], 'data must be the Proxmox payload, not the whole client response');
        $this->assertCount(1, $calls);
        $this->assertSame($verb, $calls[0]['method']);
        $this->assertSame($path, ltrim($calls[0]['path'], '/'));
    }

    #[Test]
    #[DataProvider('fixedMethods')]
    public function success_returns_string_data_such_as_a_upid(string $method, array $args, string $verb = "", string $path = ""): void
    {
        $upid = 'UPID:pve1:0001:0002:0003:task:100:root@pam:';
        $calls = [];
        $r = $this->node($calls, ['data' => $upid])->$method(...$args);

        $this->assertEnvelope($r);
        $this->assertTrue($r['success']);
        $this->assertSame($upid, $r['data']);
    }

    #[Test]
    #[DataProvider('fixedMethods')]
    public function a_response_without_a_data_key_is_a_failure_envelope(string $method, array $args, string $verb = "", string $path = ""): void
    {
        $calls = [];
        $r = $this->node($calls, [])->$method(...$args);

        $this->assertEnvelope($r);
        $this->assertFalse($r['success']);
        $this->assertArrayNotHasKey('data', $r);
    }

    /** Mutations Proxmox answers with {"data": null} are successes and carry no 'data' member. */
    public static function mutationMethods(): array
    {
        return array_filter(
            self::fixedMethods(),
            fn (array $m) => $m[2] !== 'GET',
        );
    }

    #[Test]
    #[DataProvider('mutationMethods')]
    public function a_null_data_mutation_is_a_success_envelope(string $method, array $args, string $verb = "", string $path = ""): void
    {
        $calls = [];
        $r = $this->node($calls, ['data' => null])->$method(...$args);

        $this->assertEnvelope($r);
        $this->assertTrue($r['success']);
        $this->assertArrayNotHasKey('data', $r);
    }

    /** GET reads with a null payload are failures (nothing was read). */
    public static function readMethods(): array
    {
        return array_filter(
            self::fixedMethods(),
            fn (array $m) => $m[2] === 'GET',
        );
    }

    #[Test]
    #[DataProvider('readMethods')]
    public function a_null_data_read_is_a_failure_envelope(string $method, array $args, string $verb = "", string $path = ""): void
    {
        $calls = [];
        $r = $this->node($calls, ['data' => null])->$method(...$args);

        $this->assertEnvelope($r);
        $this->assertFalse($r['success']);
    }

    #[Test]
    #[DataProvider('fixedMethods')]
    public function a_malicious_node_segment_is_still_rejected_before_any_request(string $method, array $args, string $verb = "", string $path = ""): void
    {
        $calls = [];
        $args[0] = 'pve1/../../etc';

        $this->expectException(\InvalidArgumentException::class);
        try {
            $this->node($calls, ['data' => []])->$method(...$args);
        } finally {
            $this->assertSame([], $calls);
        }
    }

    // ---- internal callers of setVMConfig() keep working on the envelope ----

    #[Test]
    public function rename_vm_succeeds_on_the_set_vm_config_envelope(): void
    {
        $calls = [];
        $responder = fn (string $m) => $m === 'GET' ? ['data' => ['status' => 'stopped']] : ['data' => null];

        $r = $this->node($calls, $responder)->renameVM('pve1', 100, 'new-name');

        $this->assertEnvelope($r);
        $this->assertTrue($r['success']);
    }

    #[Test]
    public function rename_vm_fails_when_set_vm_config_fails(): void
    {
        $calls = [];
        $responder = fn (string $m) => $m === 'GET' ? ['data' => ['status' => 'stopped']] : [];

        $r = $this->node($calls, $responder)->renameVM('pve1', 100, 'new-name');

        $this->assertEnvelope($r);
        $this->assertFalse($r['success']);
    }

    #[Test]
    public function attach_ssh_key_returns_the_envelope(): void
    {
        $key = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkYn0lUe1hAbCdEfGhIjKlMnOpQrStUvWxYz012345 user@host';
        $calls = [];
        $r = $this->node($calls, ['data' => ['x' => 1]])->attachSSHKey('pve1', 100, $key);

        $this->assertEnvelope($r);
        $this->assertTrue($r['success']);
    }
}
