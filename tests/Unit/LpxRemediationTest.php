<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\Exceptions\AuthenticationException;
use Cycoslave\Proxmox\Exceptions\ConnectionException;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxCluster;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\Support\LogRedactor;
use Cycoslave\Proxmox\Support\ResponseHelper;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for the laravel-proxmox code-quality review findings
 * LPX-001..LPX-004 and LPX-006..LPX-008 (LPX-005 lives in
 * GenerateSSHKeyTest). Every HTTP-level assertion goes through a capture
 * client that records the exact verb / path / payload and never touches
 * the network.
 */
class LpxRemediationTest extends TestCase
{
    protected function tearDown(): void
    {
        Log::clearResolvedInstance();
        parent::tearDown();
    }

    /**
     * @param  array  $calls     Receives ['method','path','data'] per dispatched request.
     * @param  array  $response  Canned decoded envelope returned for every call.
     */
    private function captureAccess(array &$calls, array $response = ['data' => null]): ProxmoxAccess
    {
        return new class($calls, $response) extends ProxmoxAccess {
            public function __construct(private array &$calls, private array $canned)
            {
                parent::__construct(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            private function record(string $method, string $path, array $data): array
            {
                $this->calls[] = ['method' => $method, 'path' => $path, 'data' => $data];
                return $this->canned;
            }

            public function get(string $path, array $params = []): array { return $this->record('GET', $path, $params); }
            public function post(string $path, array $data = []): array { return $this->record('POST', $path, $data); }
            public function put(string $path, array $data = []): array { return $this->record('PUT', $path, $data); }
            public function delete(string $path, array $params = []): array { return $this->record('DELETE', $path, $params); }
        };
    }

    private function fakeLogger(): object
    {
        return new class {
            public array $warnings = [];

            public function warning($message, array $context = [])
            {
                $this->warnings[] = compact('message', 'context');
            }
        };
    }

    // -------------------------------------------------------------------------
    // LPX-001: node firewall options stay node-scoped
    // -------------------------------------------------------------------------

    #[Test]
    public function set_firewall_rule_options_puts_to_the_node_endpoint_not_the_cluster(): void
    {
        $calls = [];
        $result = (new ProxmoxNode($this->captureAccess($calls)))->setFirewallRuleOptions('pve1', ['enable' => 0]);

        $this->assertCount(1, $calls);
        $this->assertSame('PUT', $calls[0]['method']);
        $this->assertSame('nodes/pve1/firewall/options', $calls[0]['path']);
        $this->assertSame(['enable' => 0], $calls[0]['data']);
        $this->assertStringNotContainsString('cluster/', $calls[0]['path']);
        $this->assertTrue($result['success'], 'Proxmox answers this PUT with data:null on success');
    }

    #[Test]
    public function set_firewall_rule_options_validates_the_node_segment(): void
    {
        $calls = [];
        $this->expectException(\InvalidArgumentException::class);

        try {
            (new ProxmoxNode($this->captureAccess($calls)))->setFirewallRuleOptions('pve1/../../cluster', ['enable' => 0]);
        } finally {
            $this->assertSame([], $calls, 'No request may be dispatched for an invalid node');
        }
    }

    #[Test]
    public function firewall_rules_options_reads_the_node_options_endpoint(): void
    {
        $calls = [];
        (new ProxmoxNode($this->captureAccess($calls, ['data' => ['enable' => 1]])))->firewallRulesOptions('pve1');

        $this->assertSame('GET', $calls[0]['method']);
        $this->assertSame('nodes/pve1/firewall/options', $calls[0]['path']);
    }

    // -------------------------------------------------------------------------
    // LPX-002: Ceph monitor deletion targets ceph/mon
    // -------------------------------------------------------------------------

    #[Test]
    public function destroy_ceph_mon_deletes_the_monitor_not_the_manager(): void
    {
        $calls = [];
        (new ProxmoxNode($this->captureAccess($calls, ['data' => 'UPID:pve1:x'])))->destroyCephMon('pve1', 'mon1');

        $this->assertSame('DELETE', $calls[0]['method']);
        $this->assertSame('nodes/pve1/ceph/mon/mon1', $calls[0]['path']);
        $this->assertStringNotContainsString('/ceph/mgr/', $calls[0]['path']);
    }

    // -------------------------------------------------------------------------
    // LPX-003: the four QEMU firewall deletions dispatch (no TypeError)
    // -------------------------------------------------------------------------

    #[Test]
    public function qemu_firewall_deletions_dispatch_with_an_array_payload(): void
    {
        $calls = [];
        $node  = new ProxmoxNode($this->captureAccess($calls));

        $results = [
            $node->deleteQemuFirewallAliaseName('pve1', 100, 'alias1'),
            $node->deleteQemuFirewallIpsetName('pve1', 100, 'set1'),
            $node->deleteQemuFirewallIpsetNameCidr('pve1', 100, 'set1', '10.0.0.1'),
            $node->deleteQemuFirewallRulesPos('pve1', 100, 3),
        ];

        $this->assertSame(
            [
                'nodes/pve1/qemu/100/firewall/aliases/alias1',
                'nodes/pve1/qemu/100/firewall/ipset/set1',
                'nodes/pve1/qemu/100/firewall/ipset/set1/10.0.0.1',
                'nodes/pve1/qemu/100/firewall/rules/3',
            ],
            array_column($calls, 'path'),
        );

        foreach ($calls as $call) {
            $this->assertSame('DELETE', $call['method']);
            $this->assertSame([], $call['data']);
        }
        foreach ($results as $result) {
            $this->assertTrue($result['success'], 'A data:null DELETE response is success');
        }
    }

    // -------------------------------------------------------------------------
    // LPX-004: data-key presence (not non-nullness) signals mutation success
    // -------------------------------------------------------------------------

    #[Test]
    public function response_helper_has_data_checks_key_presence(): void
    {
        $this->assertTrue(ResponseHelper::hasData(['data' => null]));
        $this->assertTrue(ResponseHelper::hasData(['data' => 'UPID:x']));
        $this->assertTrue(ResponseHelper::hasData(['data' => []]));
        $this->assertFalse(ResponseHelper::hasData([]));
        $this->assertFalse(ResponseHelper::hasData(['errors' => ['x' => 'y']]));
    }

    #[Test]
    public function set_vm_password_treats_null_data_as_success(): void
    {
        $calls = [];
        $result = (new ProxmoxNode($this->captureAccess($calls)))->setVMPassword('pve1', 100, 's3cret');

        $this->assertTrue($result['success']);
        $this->assertSame('SSH credentials injected successfully', $result['message']);
    }

    #[Test]
    public function set_vm_password_reports_failure_when_data_key_missing(): void
    {
        $calls = [];
        $result = (new ProxmoxNode($this->captureAccess($calls, ['unexpected' => true])))->setVMPassword('pve1', 100, 's3cret');

        $this->assertFalse($result['success']);
    }

    #[Test]
    public function update_credential_treats_null_data_as_success_and_missing_key_as_failure(): void
    {
        $calls = [];
        $ok = (new ProxmoxNode($this->captureAccess($calls)))->updateCredential('pve1', 100, ['password' => 'pw']);
        $this->assertTrue($ok['success']);
        $this->assertSame(['data' => null, 'node' => 'pve1', 'vmid' => 100], $ok['data']);

        $calls = [];
        $bad = (new ProxmoxNode($this->captureAccess($calls, [])))->updateCredential('pve1', 100, ['password' => 'pw']);
        $this->assertFalse($bad['success']);
    }

    #[Test]
    public function update_credential_reports_failure_on_exception(): void
    {
        Log::swap($this->fakeLogger());

        $client = new class('127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret') extends ProxmoxAccess {
            public function post(string $path, array $data = []): array
            {
                throw new ConnectionException('Proxmox cURL error: Connection refused', 7);
            }
        };

        $result = (new ProxmoxNode($client))->updateCredential('pve1', 100, ['password' => 'pw']);

        $this->assertFalse($result['success']);
    }

    #[Test]
    public function async_delete_returning_a_upid_is_success(): void
    {
        // Previously `array_key_exists && is_null` reported a real task UPID
        // (the normal async DELETE answer) as failure.
        $calls = [];
        $result = (new ProxmoxNode($this->captureAccess($calls, ['data' => 'UPID:pve1:0001'])))->deleteQemu('pve1', 100, []);

        $this->assertTrue($result['success']);
        $this->assertSame('UPID:pve1:0001', $result['data']);
    }

    #[Test]
    public function generic_mutation_wrapper_treats_null_data_as_success(): void
    {
        $calls = [];
        $result = (new ProxmoxCluster($this->captureAccess($calls)))->deleteBackup('backup-1');

        $this->assertTrue($result['success']);
    }

    // -------------------------------------------------------------------------
    // LPX-006: logs carry neither the configured host nor raw diagnostics
    // -------------------------------------------------------------------------

    #[Test]
    public function ticket_auth_failure_log_is_redacted(): void
    {
        $logger = $this->fakeLogger();
        Log::swap($logger);

        $access = new class extends ProxmoxAccess {
            public function __construct()
            {
                parent::__construct(host: 'pve-master-01.internal.lan', port: 8443, password: 'secret');
            }

            protected function sendRequest(string $method, string $url, array $params = [], array $headers = []): array
            {
                throw new ConnectionException('Proxmox cURL error: Could not resolve host: pve-master-01.internal.lan', 6);
            }
        };

        try {
            $access->get('nodes');
            $this->fail('Expected AuthenticationException');
        } catch (AuthenticationException) {
            // expected
        }

        $this->assertCount(1, $logger->warnings);
        $context = $logger->warnings[0]['context'];
        $this->assertSame(LogRedactor::endpointId('pve-master-01.internal.lan', 8443), $context['endpoint']);
        $this->assertSame('network', $context['category']);
        $this->assertSame('ConnectionException', $context['error_class']);
        $this->assertSame(6, $context['error_code']);
        $this->assertArrayNotHasKey('host', $context);
        $this->assertArrayNotHasKey('error', $context);
        $this->assertStringNotContainsString('pve-master-01', json_encode($logger->warnings[0]));
    }

    #[Test]
    public function endpoint_id_is_stable_and_does_not_contain_the_host(): void
    {
        $id = LogRedactor::endpointId('10.20.30.40', 8006);

        $this->assertSame($id, LogRedactor::endpointId('10.20.30.40', 8006));
        $this->assertNotSame($id, LogRedactor::endpointId('10.20.30.40', 8007));
        $this->assertMatchesRegularExpression('/^pve-[0-9a-f]{12}$/', $id);
        $this->assertStringNotContainsString('10.20.30.40', $id);
    }

    #[Test]
    public function api_exception_context_includes_http_status_but_not_the_message(): void
    {
        $context = LogRedactor::exceptionContext(
            new \Cycoslave\Proxmox\Exceptions\ApiException('Proxmox API HTTP 500 for: https://10.1.1.1:8006/api2/json/nodes', 500)
        );

        $this->assertSame('api', $context['category']);
        $this->assertSame(500, $context['http_status']);
        $this->assertStringNotContainsString('10.1.1.1', json_encode($context));
    }

    // -------------------------------------------------------------------------
    // LPX-007: SPICE shell is a POST
    // -------------------------------------------------------------------------

    #[Test]
    public function spice_shell_is_created_with_post_and_forwards_the_payload(): void
    {
        $calls = [];
        $result = (new ProxmoxNode($this->captureAccess($calls, ['data' => ['ticket' => 't']])))
            ->spiceShell('pve1', ['proxy' => 'pve1.example']);

        $this->assertSame('POST', $calls[0]['method']);
        $this->assertSame('nodes/pve1/spiceshell', $calls[0]['path']);
        $this->assertSame(['proxy' => 'pve1.example'], $calls[0]['data']);
        $this->assertTrue($result['success']);
    }

    // -------------------------------------------------------------------------
    // LPX-008: firewall-group creation forwards the caller's payload
    // -------------------------------------------------------------------------

    #[Test]
    public function create_firewall_group_forwards_the_payload(): void
    {
        $calls   = [];
        $payload = ['group' => 'web', 'comment' => 'web tier'];
        $result  = (new ProxmoxCluster($this->captureAccess($calls)))->createFirewallGroup($payload);

        $this->assertSame('POST', $calls[0]['method']);
        $this->assertSame('cluster/firewall/groups', $calls[0]['path']);
        $this->assertSame($payload, $calls[0]['data']);
        $this->assertTrue($result['success']);
    }
}
