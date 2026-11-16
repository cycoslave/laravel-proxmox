<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\Exceptions\ConnectionException;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxAccessApi;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\Support\ResponseHelper;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * Regression tests for the Argon SAST/SCA audit findings LPX-SAST-001,
 * -002, -004, -005, -006 and -007 (see _reports/ for the audit). No test
 * touches the network except the loopback connection-refused case.
 */
class LpxSastRemediationTest extends TestCase
{
    protected function tearDown(): void
    {
        Log::clearResolvedInstance();
        parent::tearDown();
    }

    /**
     * @param array         $calls      Receives ['method','path','data'] per request.
     * @param array|\Closure $responder Canned envelope, or fn(method, path): array.
     */
    private function access(array &$calls, array|\Closure $responder = ['data' => null]): ProxmoxAccess
    {
        return new class($calls, $responder) extends ProxmoxAccess {
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
    }

    // -------------------------------------------------------------------------
    // LPX-SAST-001: success/failure predicates must not be inverted
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: callable(ProxmoxNode): array}> */
    public static function mutationMethods(): array
    {
        return [
            'createQemuFirewallRule' => [fn (ProxmoxNode $n) => $n->createQemuFirewallRule('pve1', 100, ['type' => 'in', 'action' => 'ACCEPT'])],
            'removeQemuFirewallRule' => [fn (ProxmoxNode $n) => $n->removeQemuFirewallRule('pve1', 100, 0)],
            'updateVmConfig'         => [fn (ProxmoxNode $n) => $n->updateVmConfig('pve1', 100, ['memory' => 1024])],
            'resizeVm'               => [fn (ProxmoxNode $n) => $n->resizeVm('pve1', 100, ['disk' => 'scsi0', 'size' => '+1G'])],
        ];
    }

    #[Test]
    #[DataProvider('mutationMethods')]
    public function mutation_reports_success_when_proxmox_answers_data_null(callable $call): void
    {
        $calls = [];
        $result = $call(new ProxmoxNode($this->access($calls, ['data' => null])));

        $this->assertTrue($result['success']);
    }

    #[Test]
    #[DataProvider('mutationMethods')]
    public function mutation_reports_success_when_proxmox_answers_a_upid(callable $call): void
    {
        $calls = [];
        $result = $call(new ProxmoxNode($this->access($calls, ['data' => 'UPID:pve1:0001:0002:0003:qmconfig:100:root@pam:'])));

        $this->assertTrue($result['success']);
    }

    #[Test]
    #[DataProvider('mutationMethods')]
    public function mutation_reports_failure_without_warning_when_envelope_has_no_data_key(callable $call): void
    {
        $calls = [];
        $result = $call(new ProxmoxNode($this->access($calls, [])));

        $this->assertFalse($result['success']);
    }

    // -------------------------------------------------------------------------
    // LPX-SAST-002: generated key material is returned; sshkeys is %20-encoded
    // -------------------------------------------------------------------------

    #[Test]
    public function create_ubuntu_vm_with_ssh_returns_generated_key_metadata_and_rawurlencodes_the_key(): void
    {
        $calls = [];
        $node = new class($this->access($calls)) extends ProxmoxNode {
            public function generateSSHKey(?string $name = null, ?string $passphrase = null): array
            {
                return ResponseHelper::generate(true, 'SSH key generated successfully', [
                    'private_key_path'     => '/keys/vm',
                    'public_key_path'      => '/keys/vm.pub',
                    'public_key'           => 'ssh-rsa AAAA+/bb test@host',
                    'passphrase_generated' => true,
                    'passphrase'           => 'one-time-secret',
                ]);
            }
        };

        $result = $node->createUbuntuVMWithSSH('pve1', [
            'vmid' => 100, 'name' => 'vm', 'ostype' => 'l26', 'memory' => 512, 'cores' => 1,
        ]);

        $this->assertSame('/keys/vm', $result['generated_key']['private_key_path']);
        $this->assertSame('/keys/vm.pub', $result['generated_key']['public_key_path']);
        $this->assertSame('one-time-secret', $result['generated_key']['passphrase']);

        $create = array_values(array_filter($calls, fn ($c) => $c['method'] === 'POST' && $c['path'] === 'nodes/pve1/qemu'));
        $this->assertCount(1, $create);
        $this->assertSame('ssh-rsa%20AAAA%2B%2Fbb%20test%40host', $create[0]['data']['sshkeys']);
    }

    #[Test]
    public function create_ubuntu_vm_with_ssh_omits_generated_key_when_caller_supplies_the_key(): void
    {
        $calls = [];
        $result = (new ProxmoxNode($this->access($calls)))->createUbuntuVMWithSSH(
            'pve1',
            ['vmid' => 100, 'name' => 'vm', 'ostype' => 'l26', 'memory' => 512, 'cores' => 1],
            'ssh-ed25519 AAAA caller@host'
        );

        $this->assertArrayNotHasKey('generated_key', $result);
        $this->assertSame('ssh-ed25519 AAAA caller@host', $result['ssh_key']);
    }

    // -------------------------------------------------------------------------
    // LPX-SAST-004: credential-bearing parameters are marked #[SensitiveParameter]
    // -------------------------------------------------------------------------

    /** @return array<string, array{0: class-string, 1: string, 2: string}> */
    public static function sensitiveParameters(): array
    {
        return [
            'generateSSHKey.passphrase'              => [ProxmoxNode::class, 'generateSSHKey', 'passphrase'],
            'injectSSHCredentials.password'          => [ProxmoxNode::class, 'injectSSHCredentials', 'password'],
            'updateCredential.payload'               => [ProxmoxNode::class, 'updateCredential', 'payload'],
            'qemuAgentSetUserPassword.data'          => [ProxmoxNode::class, 'qemuAgentSetUserPassword', 'data'],
            'ProxmoxAccessApi::createUser.data'      => [ProxmoxAccessApi::class, 'createUser', 'data'],
            'ProxmoxAccessApi::changeUserPassword'   => [ProxmoxAccessApi::class, 'changeUserPassword', 'data'],
            'ProxmoxAccessApi::createTicket.data'    => [ProxmoxAccessApi::class, 'createTicket', 'data'],
        ];
    }

    #[Test]
    #[DataProvider('sensitiveParameters')]
    public function credential_parameters_are_sensitive(string $class, string $method, string $param): void
    {
        foreach ((new ReflectionMethod($class, $method))->getParameters() as $p) {
            if ($p->getName() === $param) {
                $this->assertNotEmpty($p->getAttributes(\SensitiveParameter::class), "{$class}::{$method}(\${$param})");
                return;
            }
        }
        $this->fail("Parameter \${$param} not found on {$class}::{$method}");
    }

    #[Test]
    public function connection_exception_does_not_disclose_the_target_endpoint(): void
    {
        // Loopback port 1 is closed: curl fails fast with "connection refused",
        // whose raw curl_error() text names 127.0.0.1 and the port.
        $access = new ProxmoxAccess(
            host: '127.0.0.1',
            port: 1,
            tokenId: 'root@pam!tok',
            tokenSecret: 'uuid-secret',
            timeout: 2,
        );

        try {
            $access->get('nodes');
            $this->fail('Expected ConnectionException');
        } catch (ConnectionException $e) {
            $this->assertStringContainsString('cURL error', $e->getMessage());
            $this->assertStringNotContainsString('127.0.0.1', $e->getMessage());
            $this->assertStringNotContainsString('port 1', $e->getMessage());
            $this->assertGreaterThan(0, $e->getCode());
        }
    }

    // -------------------------------------------------------------------------
    // LPX-SAST-005: no collateral VM config mutation
    // -------------------------------------------------------------------------

    #[Test]
    public function attach_disk_with_options_does_not_overwrite_net0_or_boot_order(): void
    {
        $calls = [];
        $responder = fn (string $m, string $p) => $m === 'GET'
            ? ['data' => ['scsi0' => 'local-lvm:vm-100-disk-0', 'net0' => 'virtio,bridge=vmbr7']]
            : ['data' => null];

        $result = (new ProxmoxNode($this->access($calls, $responder)))->attachDisk('pve1', 100, [
            'storage' => 'local-lvm', 'size' => '10G', 'format' => 'raw', 'cache' => 'none', 'iothread' => '1',
        ]);

        $this->assertTrue($result['success']);
        $post = array_values(array_filter($calls, fn ($c) => $c['method'] === 'POST'))[0];
        $this->assertSame('nodes/pve1/qemu/100/config', $post['path']);
        $this->assertSame(['scsi1' => 'local-lvm:10,format=raw,cache=none,iothread=1'], $post['data']);
    }

    #[Test]
    public function attach_disk_rejects_option_delimiter_injection(): void
    {
        Log::swap(new class {
            public function warning($message, array $context = []) {}
            public function error($message, array $context = []) {}
        });
        $calls = [];
        $responder = fn (string $m, string $p) => $m === 'GET' ? ['data' => ['scsi0' => 'x']] : ['data' => null];

        $result = (new ProxmoxNode($this->access($calls, $responder)))->attachDisk('pve1', 100, [
            'storage' => 'local-lvm', 'size' => '10G', 'cache' => 'none,net0=virtio,bridge=vmbr9',
        ]);

        $this->assertFalse($result['success']);
        $this->assertSame([], array_filter($calls, fn ($c) => $c['method'] === 'POST'));
    }

    #[Test]
    public function create_vm_keeps_a_caller_supplied_cpu(): void
    {
        $calls = [];
        $params = ['vmid' => 100, 'name' => 'vm', 'ostype' => 'l26', 'memory' => 512, 'cores' => 1, 'cpu' => 'host'];

        (new ProxmoxNode($this->access($calls)))->createVM('pve1', $params);

        $this->assertCount(1, $calls, 'No follow-up PUT may overwrite the caller cpu');
        $this->assertSame('POST', $calls[0]['method']);
        $this->assertSame('host', $calls[0]['data']['cpu']);
    }

    #[Test]
    public function create_vm_still_applies_the_default_cpu_when_none_given(): void
    {
        $calls = [];
        $params = ['vmid' => 100, 'name' => 'vm', 'ostype' => 'l26', 'memory' => 512, 'cores' => 1];

        (new ProxmoxNode($this->access($calls)))->createVM('pve1', $params);

        $this->assertCount(2, $calls);
        $this->assertSame('PUT', $calls[1]['method']);
        $this->assertSame(['cpu' => 'x86-64-v2-AES'], $calls[1]['data']);
    }

    #[Test]
    public function vm_monitor_forwards_the_caller_params(): void
    {
        $calls = [];
        (new ProxmoxNode($this->access($calls)))->vmMonitor('pve1', 100, ['command' => 'info status']);

        $this->assertSame(['command' => 'info status'], $calls[0]['data']);
    }

    #[Test]
    public function vm_monitor_defaults_to_info_when_no_params_given(): void
    {
        $calls = [];
        (new ProxmoxNode($this->access($calls)))->vmMonitor('pve1', 100, []);

        $this->assertSame(['command' => 'info'], $calls[0]['data']);
    }

    // -------------------------------------------------------------------------
    // LPX-SAST-006: UPIDs accepted; firewall log endpoint
    // -------------------------------------------------------------------------

    #[Test]
    public function task_methods_accept_a_real_upid(): void
    {
        $upid = 'UPID:pve1:00001A2B:0003C4D5:6540F0A1:qmstart:100:root@pam:';
        $calls = [];
        $node = new ProxmoxNode($this->access($calls, ['data' => ['status' => 'stopped', 'exitstatus' => 'OK']]));

        $this->assertTrue($node->tasksStatus('pve1', $upid)['success']);
        $this->assertSame("nodes/pve1/tasks/{$upid}/status", $calls[0]['path']);
        $this->assertSame('OK', $node->checkTaskStatus('pve1', $upid)['data']['exitstatus']);
    }

    #[Test]
    public function task_methods_still_reject_path_traversal_in_the_upid(): void
    {
        $calls = [];
        $this->expectException(\InvalidArgumentException::class);

        try {
            (new ProxmoxNode($this->access($calls)))->tasksStatus('pve1', 'UPID:x/../../cluster');
        } finally {
            $this->assertSame([], $calls);
        }
    }

    #[Test]
    public function firewall_rules_log_reads_the_node_log_endpoint(): void
    {
        $calls = [];
        (new ProxmoxNode($this->access($calls, ['data' => []])))->firewallRulesLog('pve1');

        $this->assertSame('GET', $calls[0]['method']);
        $this->assertSame('nodes/pve1/firewall/log', $calls[0]['path']);
    }

    // -------------------------------------------------------------------------
    // LPX-SAST-007: renameVM success; failure branches don't dereference a missing key
    // -------------------------------------------------------------------------

    #[Test]
    public function rename_vm_reports_success_when_set_config_answers_data_null(): void
    {
        $calls = [];
        $responder = fn (string $m, string $p) => $m === 'GET'
            ? ['data' => ['status' => 'stopped']]
            : ['data' => null];

        $result = (new ProxmoxNode($this->access($calls, $responder)))->renameVM('pve1', 100, 'new-name');

        $this->assertTrue($result['success']);
    }

    #[Test]
    public function failure_branch_without_data_key_returns_a_failure_envelope_not_a_warning(): void
    {
        $calls = [];
        $node = new ProxmoxNode($this->access($calls, []));

        // destroyVm/dns/vmMonitor previously evaluated $response['data'] on a response that had no such key.
        $this->assertFalse($node->vmMonitor('pve1', 100, [])['success']);
        $this->assertFalse($node->setDns('pve1', ['dns1' => '1.1.1.1'])['success']);
    }
}
