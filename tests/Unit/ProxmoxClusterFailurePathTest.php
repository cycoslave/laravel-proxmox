<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxCluster;

/**
 * Regression tests for SAST-004 (Medium, CWE-252, secondary CWE-754/CWE-393):
 *
 * Every failure branch in ProxmoxCluster called
 * `ResponseHelper::generate(false, ...)` WITHOUT `return`. The discarded
 * envelope meant execution fell through to the success path below,
 * returning `['success' => true, 'data' => null]` (plus a PHP warning
 * for reading the undefined `$response['data']`) instead of surfacing
 * the failure — including on destructive operations such as
 * deleteBackup(), removeFirewallGroupPos(), deleteFirewallIpsetName(),
 * and deleteReplication().
 *
 * These tests stub ProxmoxAccess so the underlying HTTP call returns an
 * envelope with no 'data' key (simulating an upstream failure) and
 * assert the wrapper now returns success => false immediately, never
 * reaching the success-path return.
 */
class ProxmoxClusterFailurePathTest extends TestCase
{
    private function clusterWithFailingClient(): ProxmoxCluster
    {
        $client = new class('127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret') extends ProxmoxAccess {
            public function get(string $path, array $params = []): array
            {
                // Simulate an upstream failure: no 'data' key present.
                return ['no_data_here' => true];
            }

            public function post(string $path, array $data = []): array
            {
                return ['no_data_here' => true];
            }

            public function put(string $path, array $data = []): array
            {
                return ['no_data_here' => true];
            }

            public function delete(string $path, array $params = []): array
            {
                return ['no_data_here' => true];
            }
        };

        return new ProxmoxCluster($client);
    }

    #[Test]
    public function cluster_read_returns_failure_envelope_when_data_missing(): void
    {
        $result = $this->clusterWithFailingClient()->cluster();

        $this->assertIsArray($result);
        $this->assertFalse($result['success'], 'cluster() must report success=>false on missing data, not fall through to success=>true');
        $this->assertSame('Cluster fail.', $result['message']);
        $this->assertArrayNotHasKey('data', $result);
    }

    #[Test]
    public function delete_backup_destructive_op_returns_failure_envelope_when_data_missing(): void
    {
        $result = $this->clusterWithFailingClient()->deleteBackup('100-0');

        $this->assertFalse($result['success'], 'deleteBackup() must not silently report success on a failed destructive operation');
        $this->assertSame('Cluster backup job delete fail.', $result['message']);
    }

    #[Test]
    public function delete_replication_destructive_op_returns_failure_envelope_when_data_missing(): void
    {
        $result = $this->clusterWithFailingClient()->deleteReplication('100-0');

        $this->assertFalse($result['success'], 'deleteReplication() must not silently report success on a failed destructive operation');
        $this->assertSame('Cluster replication delete fail.', $result['message']);
    }

    #[Test]
    public function remove_firewall_group_pos_destructive_op_returns_failure_envelope_when_data_missing(): void
    {
        $result = $this->clusterWithFailingClient()->removeFirewallGroupPos('mygroup', 0);

        $this->assertFalse($result['success'], 'removeFirewallGroupPos() must not silently report success on a failed destructive operation');
        $this->assertSame('Cluster firewall group position delete fail.', $result['message']);
    }

    #[Test]
    public function delete_firewall_ipset_name_destructive_op_returns_failure_envelope_when_data_missing(): void
    {
        $result = $this->clusterWithFailingClient()->deleteFirewallIpsetName('myset');

        $this->assertFalse($result['success'], 'deleteFirewallIpsetName() must not silently report success on a failed destructive operation');
        $this->assertSame('Cluster firewall ip delete fail.', $result['message']);
    }

    #[Test]
    public function successful_response_still_returns_data(): void
    {
        $client = new class('127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret') extends ProxmoxAccess {
            public function get(string $path, array $params = []): array
            {
                return ['data' => ['ok' => true]];
            }
        };

        $result = (new ProxmoxCluster($client))->cluster();

        $this->assertTrue($result['success']);
        $this->assertSame(['ok' => true], $result['data']);
    }
}
