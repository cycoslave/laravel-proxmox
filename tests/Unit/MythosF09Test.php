<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Illuminate\Support\Facades\Facade;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for mythos F-09: ProxmoxNode::safeErrorMessage() called the
 * Log facade unguarded, so without a booted app ("A facade root has not been
 * set.") the original error was replaced by a RuntimeException and
 * deleteMultipleVMs() aborted on the first failure.
 */
class MythosF09Test extends TestCase
{
    private function node(): ProxmoxNode
    {
        $access = $this->createStub(ProxmoxAccess::class);

        return new class($access) extends ProxmoxNode {
            public function deleteVM(string $node, int $vmid, bool $force = false, bool $purge = true)
            {
                throw new \Exception("boom {$vmid}");
            }
        };
    }

    protected function setUp(): void
    {
        parent::setUp();
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
    }

    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        parent::tearDown();
    }

    #[Test]
    public function delete_multiple_vms_collects_every_error_without_a_facade_root(): void
    {
        $result = $this->node()->deleteMultipleVMs('pve1', [101, 102, 103]);

        $this->assertSame([], $result['success']);
        $this->assertSame([
            101 => 'Failed to delete VM 101.',
            102 => 'Failed to delete VM 102.',
            103 => 'Failed to delete VM 103.',
        ], $result['errors']);
    }

    #[Test]
    public function safe_error_message_returns_generic_message_without_a_facade_root(): void
    {
        $m = new \ReflectionMethod(ProxmoxNode::class, 'safeErrorMessage');

        $this->assertSame(
            'Failed to rename VM.',
            $m->invoke($this->node(), new \Exception('secret host 10.0.0.9'), 'Failed to rename VM')
        );
    }
}
