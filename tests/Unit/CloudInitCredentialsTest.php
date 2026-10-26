<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;

/**
 * Regression tests for SAST-005 (CWE-476/CWE-628):
 *
 *   - injectSSHCredentials() and rebuildCloudInit() referenced an undefined
 *     $this->baseUrl property on ProxmoxNode (Reflection confirmed no such
 *     property exists — ProxmoxAccess::baseUrl() is a protected method on a
 *     *different* class and was never assigned to a ProxmoxNode property).
 *     Under Laravel's default error handler, the resulting "Undefined
 *     property" warning is escalated to a fatal ErrorException the first
 *     time either method is invoked (CWE-476 null/undefined dereference).
 *
 *   - createUbuntuVMWithSSH()'s auto-generate-key branch called
 *     generateSSHKey($keyName) with 1 of the (then) 2 required parameters,
 *     an ArgumentCountError (CWE-628, wrong function-call arity). SAST-001
 *     already changed generateSSHKey()'s signature to
 *     (?string $name = null, ?string $passphrase = null) — both optional —
 *     so a 1-arg call is valid post-fix; this suite asserts the call site
 *     stays reconciled against that signature.
 *
 * Uses PHPUnit 12 #[Test] attributes (see SAST-009).
 */
class CloudInitCredentialsTest extends TestCase
{
    /**
     * ProxmoxAccess subclass that never touches the network: it records
     * every dispatched request and returns a canned success envelope.
     */
    private function captureAccess(array &$calls): ProxmoxAccess
    {
        return new class($calls) extends ProxmoxAccess {
            public function __construct(private array &$calls)
            {
                parent::__construct(
                    host: '127.0.0.1',
                    tokenId: 'root@pam!tok',
                    tokenSecret: 'uuid-secret',
                );
            }

            public function post(string $path, array $data = []): array
            {
                $this->calls[] = ['method' => 'POST', 'path' => $path, 'data' => $data];
                return ['data' => null];
            }

            // LPX-004: createVM() now (correctly) treats a data:null POST as
            // success and goes on to PUT the CPU config; stub that too so
            // the suite never touches the network.
            public function put(string $path, array $data = []): array
            {
                return ['data' => null];
            }
        };
    }

    private function nodeUnderTest(array &$calls): ProxmoxNode
    {
        return new ProxmoxNode($this->captureAccess($calls));
    }

    // -------------------------------------------------------------------------
    // injectSSHCredentials() / rebuildCloudInit() — no undefined property
    // -------------------------------------------------------------------------

    #[Test]
    public function inject_ssh_credentials_does_not_reference_an_undefined_property(): void
    {
        $calls = [];
        $node  = $this->nodeUnderTest($calls);

        // Prior to the fix this threw "Undefined property:
        // Cycoslave\Proxmox\ProxmoxNode::$baseUrl" under a strict/Laravel
        // error handler. Simply not throwing is the regression check.
        $response = $node->injectSSHCredentials('pve1', 100, 'ubuntu', 'secret-pw', 'ssh-rsa AAAA...');

        $this->assertIsArray($response);
        $this->assertCount(1, $calls);
    }

    #[Test]
    public function inject_ssh_credentials_posts_to_the_correct_config_endpoint(): void
    {
        $calls = [];
        $node  = $this->nodeUnderTest($calls);

        $node->injectSSHCredentials('pve1', 100, 'ubuntu', 'secret-pw', 'ssh-rsa AAAA... comment');

        $this->assertSame('/nodes/pve1/qemu/100/config', $calls[0]['path']);
        $this->assertSame('ubuntu', $calls[0]['data']['ciuser']);
        $this->assertSame('secret-pw', $calls[0]['data']['cipassword']);
        $this->assertSame('ssh-rsa AAAA... comment', $calls[0]['data']['sshkeys']);
    }

    #[Test]
    public function inject_ssh_credentials_omits_sshkeys_when_no_key_supplied(): void
    {
        $calls = [];
        $node  = $this->nodeUnderTest($calls);

        $node->injectSSHCredentials('pve1', 100, 'ubuntu', 'secret-pw');

        $this->assertArrayNotHasKey('sshkeys', $calls[0]['data']);
    }

    #[Test]
    public function inject_ssh_credentials_rejects_a_malicious_node_segment(): void
    {
        $calls = [];
        $node  = $this->nodeUnderTest($calls);

        $this->expectException(\InvalidArgumentException::class);
        $node->injectSSHCredentials("pve1/../../etc", 100, 'ubuntu', 'secret-pw');
    }

    #[Test]
    public function rebuild_cloud_init_does_not_reference_an_undefined_property(): void
    {
        $calls = [];
        $node  = $this->nodeUnderTest($calls);

        $response = $node->rebuildCloudInit('pve1', 100);

        $this->assertIsArray($response);
        $this->assertCount(1, $calls);
    }

    #[Test]
    public function rebuild_cloud_init_posts_to_the_correct_cloudinit_endpoint(): void
    {
        $calls = [];
        $node  = $this->nodeUnderTest($calls);

        $node->rebuildCloudInit('pve1', 100);

        $this->assertSame('/nodes/pve1/qemu/100/cloudinit', $calls[0]['path']);
    }

    // -------------------------------------------------------------------------
    // createUbuntuVMWithSSH() auto-key branch — generateSSHKey() call arity
    // -------------------------------------------------------------------------

    #[Test]
    public function create_ubuntu_vm_with_ssh_auto_generates_a_key_without_argument_count_error(): void
    {
        $calls = [];
        $node  = $this->nodeUnderTest($calls);

        // Prior to SAST-001's reconciliation this threw ArgumentCountError:
        // "Too few arguments to function generateSSHKey(), 1 passed and
        // exactly 2 expected". generateSSHKey() is now (?string, ?string),
        // both optional, so a 1-arg call must succeed.
        $result = $node->createUbuntuVMWithSSH('pve1', ['name' => 'test-vm', 'vmid' => 200]);

        $this->assertArrayHasKey('ssh_key', $result);
        $this->assertStringStartsWith('ssh-rsa ', $result['ssh_key']);

        // Cleanup the key material generateSSHKey() wrote to disk.
        $keyDir = rtrim(sys_get_temp_dir(), '/') . '/proxmox-ssh-keys';
        foreach (glob($keyDir . '/test_vm*') ?: [] as $path) {
            @unlink($path);
        }
    }
}
