<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxCluster;
use Cycoslave\Proxmox\ProxmoxNode;

/**
 * Regression tests for SAST-002 (CWE-20, secondary CWE-22/CWE-918):
 * four URL-building methods skipped validateSegment(), letting a
 * caller-controlled segment containing ".." (or other unsafe chars)
 * survive into the request path unvalidated. libcurl normalises
 * "x/../../cluster/firewall/rules/1" style segments, so an
 * authenticated PUT/DELETE could be redirected to a different API
 * resource (path traversal / SSRF-adjacent).
 *
 * These tests exercise ProxmoxNode::setCephFlags(), ::listService(),
 * ::configureVMCloudInitNetwork(), and ProxmoxCluster::deleteFirewallRulesPos()
 * to confirm each now rejects traversal / unsafe segments via
 * validateSegment() before any request is built, and still accepts
 * well-formed input.
 *
 * Uses PHPUnit 12 #[Test] attributes (see SAST-001/SAST-009 precedent —
 * bare /** @test *\/ docblocks are not discovered by PHPUnit 12).
 */
class ValidateSegmentCoverageTest extends TestCase
{
    private ProxmoxNode $node;
    private ProxmoxCluster $cluster;

    protected function setUp(): void
    {
        parent::setUp();
        $client        = new ProxmoxAccess(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
        $this->node    = new ProxmoxNode($client);
        $this->cluster = new ProxmoxCluster($client);
    }

    // -------------------------------------------------------------------
    // ProxmoxNode::setCephFlags($node, $flag, $data)
    // -------------------------------------------------------------------

    #[Test]
    public function set_ceph_flags_rejects_traversal_in_node(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->node->setCephFlags('pve1/../../cluster/firewall/rules/1', 'nobackfill', []);
    }

    #[Test]
    public function set_ceph_flags_rejects_traversal_in_flag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->node->setCephFlags('pve1', '../../cluster/firewall/rules/1', []);
    }

    #[Test]
    public function set_ceph_flags_rejects_slash_in_flag(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->node->setCephFlags('pve1', 'nobackfill/../nodown', []);
    }

    // -------------------------------------------------------------------
    // ProxmoxNode::listService($node, $service)
    // -------------------------------------------------------------------

    #[Test]
    public function list_service_rejects_traversal_in_node(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->node->listService('pve1/../../cluster/firewall/rules/1', 'sshd');
    }

    #[Test]
    public function list_service_rejects_traversal_in_service(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->node->listService('pve1', '../../cluster/firewall/rules/1');
    }

    // -------------------------------------------------------------------
    // ProxmoxNode::configureVMCloudInitNetwork($node, $vmid, ...)
    // -------------------------------------------------------------------

    #[Test]
    public function configure_vm_cloud_init_network_rejects_traversal_in_node(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->node->configureVMCloudInitNetwork('pve1/../../cluster/firewall/rules', 100, '10.0.0.5', '10.0.0.1', '24');
    }

    #[Test]
    public function configure_vm_cloud_init_network_rejects_empty_node(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->node->configureVMCloudInitNetwork('', 100, '10.0.0.5', '10.0.0.1', '24');
    }

    // -------------------------------------------------------------------
    // ProxmoxCluster::deleteFirewallRulesPos($pos)
    // -------------------------------------------------------------------

    #[Test]
    public function delete_firewall_rules_pos_is_typed_as_int(): void
    {
        $ref    = new \ReflectionMethod(ProxmoxCluster::class, 'deleteFirewallRulesPos');
        $params = $ref->getParameters();

        $this->assertCount(1, $params);
        $this->assertNotNull($params[0]->getType(), 'deleteFirewallRulesPos($pos) must be type-hinted.');
        $this->assertSame('int', (string) $params[0]->getType(), 'deleteFirewallRulesPos($pos) must be typed as int so traversal strings cannot be passed at all.');
    }

    #[Test]
    public function delete_firewall_rules_pos_rejects_non_numeric_traversal_string(): void
    {
        $this->expectException(\TypeError::class);
        // @phpstan-ignore-next-line intentional type violation under test
        $this->cluster->deleteFirewallRulesPos('1/../../nodes/pve1/qemu/100/config');
    }
}
