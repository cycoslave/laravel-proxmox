<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;

/**
 * Regression tests for SAST-001 (CWE-78): ProxmoxNode::generateSSHKey() must
 * never shell out, must never leak the private key, must use a fixed storage
 * root regardless of caller input, and must always produce a usable key pair.
 *
 * Uses PHPUnit 12 #[Test] attributes (docblock-only /** @test *\/ discovery
 * was removed in PHPUnit 12, see SAST-009).
 */
class GenerateSSHKeyTest extends TestCase
{
    private ProxmoxNode $node;
    private array $cleanupPaths = [];

    protected function setUp(): void
    {
        parent::setUp();
        $client = new ProxmoxAccess(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
        $this->node = new ProxmoxNode($client);
    }

    protected function tearDown(): void
    {
        foreach ($this->cleanupPaths as $path) {
            if (is_string($path) && $path !== '' && file_exists($path)) {
                @unlink($path);
            }
        }
        $this->cleanupPaths = [];
        parent::tearDown();
    }

    private function track(array $data): array
    {
        $this->cleanupPaths[] = $data['private_key_path'] ?? null;
        $this->cleanupPaths[] = $data['public_key_path'] ?? null;
        return $data;
    }

    // -------------------------------------------------------------------------
    // Response envelope shape
    // -------------------------------------------------------------------------

    #[Test]
    public function it_returns_a_successful_response_envelope(): void
    {
        $response = $this->node->generateSSHKey('unit_test_key_1');
        $this->track($response['data']);

        $this->assertTrue($response['success']);
        $this->assertSame('SSH key generated successfully', $response['message']);
        $this->assertArrayHasKey('data', $response);
    }

    #[Test]
    public function it_never_returns_the_private_key_material(): void
    {
        $response = $this->node->generateSSHKey('unit_test_key_2');
        $data = $this->track($response['data']);

        $this->assertArrayNotHasKey('private_key', $data, 'Private key content must never be returned (CWE-522).');
    }

    #[Test]
    public function it_returns_a_usable_openssh_public_key_line(): void
    {
        $response = $this->node->generateSSHKey('unit_test_key_3');
        $data = $this->track($response['data']);

        $this->assertArrayHasKey('public_key', $data);
        $this->assertStringStartsWith('ssh-rsa ', $data['public_key']);

        // The middle field must be valid base64 SSH wire-format data.
        $parts = explode(' ', $data['public_key']);
        $this->assertGreaterThanOrEqual(2, count($parts));
        $decoded = base64_decode($parts[1], true);
        $this->assertNotFalse($decoded, 'Public key blob must be valid base64.');
        $this->assertStringStartsWith("\x00\x00\x00\x07ssh-rsa", $decoded);
    }

    // -------------------------------------------------------------------------
    // No OS-command execution / no hard-coded passphrase
    // -------------------------------------------------------------------------

    #[Test]
    public function generated_private_key_is_encrypted_pem_not_plaintext(): void
    {
        $response = $this->node->generateSSHKey('unit_test_key_4');
        $data = $this->track($response['data']);

        $pem = file_get_contents($data['private_key_path']);
        $this->assertIsString($pem);
        $this->assertStringContainsString('ENCRYPTED', $pem, 'Private key must be passphrase-encrypted (CWE-321 fix).');
    }

    #[Test]
    public function a_random_passphrase_is_generated_and_returned_when_none_supplied(): void
    {
        $response = $this->node->generateSSHKey('unit_test_key_5');
        $data = $this->track($response['data']);

        $this->assertTrue($data['passphrase_generated']);
        $this->assertArrayHasKey('passphrase', $data);
        $this->assertNotSame('pass', $data['passphrase'], 'Passphrase must not be the old hard-coded value.');
        $this->assertGreaterThanOrEqual(16, strlen($data['passphrase']));
    }

    #[Test]
    public function two_calls_generate_different_random_passphrases(): void
    {
        $a = $this->track($this->node->generateSSHKey('unit_test_key_6a')['data']);
        $b = $this->track($this->node->generateSSHKey('unit_test_key_6b')['data']);

        $this->assertNotSame($a['passphrase'], $b['passphrase']);
    }

    #[Test]
    public function caller_supplied_passphrase_is_used_and_not_echoed_back(): void
    {
        $response = $this->node->generateSSHKey('unit_test_key_7', 'caller-chosen-passphrase-123');
        $data = $this->track($response['data']);

        $this->assertFalse($data['passphrase_generated']);
        $this->assertArrayNotHasKey('passphrase', $data, 'A caller-supplied passphrase must not be echoed back.');

        $privateKeyPem = file_get_contents($data['private_key_path']);
        $resource = openssl_pkey_get_private($privateKeyPem, 'caller-chosen-passphrase-123');
        $this->assertNotFalse($resource, 'The caller-supplied passphrase must actually decrypt the private key.');
    }

    // -------------------------------------------------------------------------
    // Fixed storage root — path is never caller-controlled
    // -------------------------------------------------------------------------

    #[Test]
    public function key_name_is_sanitised_and_cannot_escape_the_storage_root(): void
    {
        $response = $this->node->generateSSHKey('../../etc/passwd_pwn');
        $data = $this->track($response['data']);

        $storageDir = dirname($data['private_key_path']);
        $this->assertDirectoryExists($storageDir);
        $this->assertStringNotContainsString('..', $data['private_key_path']);
        $this->assertStringNotContainsString('/etc/passwd', $data['private_key_path']);
    }

    #[Test]
    public function empty_name_generates_a_random_safe_key_name(): void
    {
        $response = $this->node->generateSSHKey('');
        $data = $this->track($response['data']);

        $this->assertFileExists($data['private_key_path']);
        $this->assertMatchesRegularExpression('/key_[0-9a-f]{16}$/', $data['private_key_path']);
    }

    #[Test]
    public function two_calls_with_the_same_name_use_the_same_fixed_storage_root(): void
    {
        $a = $this->track($this->node->generateSSHKey('same_root_key_a')['data']);
        $b = $this->track($this->node->generateSSHKey('same_root_key_b')['data']);

        $this->assertSame(dirname($a['private_key_path']), dirname($b['private_key_path']));
    }

    // -------------------------------------------------------------------------
    // Files are actually written with safe permissions
    // -------------------------------------------------------------------------

    #[Test]
    public function private_key_file_is_written_with_owner_only_permissions(): void
    {
        $response = $this->node->generateSSHKey('unit_test_key_perm');
        $data = $this->track($response['data']);

        $this->assertFileExists($data['private_key_path']);
        $this->assertSame('0600', substr(sprintf('%o', fileperms($data['private_key_path'])), -4));
    }

    #[Test]
    public function public_key_file_on_disk_matches_returned_public_key(): void
    {
        $response = $this->node->generateSSHKey('unit_test_key_pub_match');
        $data = $this->track($response['data']);

        $onDisk = trim(file_get_contents($data['public_key_path']));
        $this->assertSame($data['public_key'], $onDisk);
    }

    // -------------------------------------------------------------------------
    // LPX-005: never overwrite an existing key pair
    // -------------------------------------------------------------------------

    #[Test]
    public function repeated_name_fails_closed_and_leaves_the_existing_pair_untouched(): void
    {
        $first = $this->track($this->node->generateSSHKey('lpx005_repeat')['data']);
        $privateBefore = file_get_contents($first['private_key_path']);
        $publicBefore  = file_get_contents($first['public_key_path']);

        try {
            $this->node->generateSSHKey('lpx005_repeat');
            $this->fail('A second key with the same name must be refused, not silently overwrite the first.');
        } catch (\Exception $e) {
            $this->assertStringContainsString('already exists', $e->getMessage());
        }

        $this->assertSame($privateBefore, file_get_contents($first['private_key_path']));
        $this->assertSame($publicBefore, file_get_contents($first['public_key_path']));
    }

    #[Test]
    public function names_that_sanitise_to_the_same_basename_do_not_collide_silently(): void
    {
        // "LPX005 Collide" and "lpx005-collide" both sanitise to "lpx005_collide".
        $first = $this->track($this->node->generateSSHKey('LPX005 Collide')['data']);
        $privateBefore = file_get_contents($first['private_key_path']);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('already exists');

        try {
            $this->node->generateSSHKey('lpx005-collide');
        } finally {
            $this->assertSame($privateBefore, file_get_contents($first['private_key_path']));
        }
    }

    #[Test]
    public function an_orphaned_public_key_also_blocks_generation_and_is_not_overwritten(): void
    {
        $first = $this->track($this->node->generateSSHKey('lpx005_orphan')['data']);
        unlink($first['private_key_path']);
        $publicBefore = file_get_contents($first['public_key_path']);

        try {
            $this->node->generateSSHKey('lpx005_orphan');
            $this->fail('An existing public key file must block generation.');
        } catch (\Exception $e) {
            $this->assertStringContainsString('already exists', $e->getMessage());
        }

        $this->assertFileDoesNotExist($first['private_key_path'], 'No half-written private key may be left behind.');
        $this->assertSame($publicBefore, file_get_contents($first['public_key_path']));
    }

    #[Test]
    public function a_planted_symlink_at_the_key_path_is_refused(): void
    {
        $probe = $this->track($this->node->generateSSHKey('lpx005_probe')['data']);
        $dir   = dirname($probe['private_key_path']);
        $target = $dir . '/lpx005_symlink_target';
        $link   = $dir . '/lpx005_symlink';
        $this->cleanupPaths[] = $link;
        @unlink($link);
        symlink($target, $link); // dangling on purpose

        try {
            $this->node->generateSSHKey('lpx005_symlink');
            $this->fail('A symlink at the private-key path must be refused.');
        } catch (\Exception $e) {
            $this->assertStringContainsString('already exists', $e->getMessage());
        }

        $this->assertFileDoesNotExist($target, 'Key material must never be written through a symlink.');
        @unlink($link); // dangling symlinks are invisible to file_exists() in tearDown()
    }

    #[Test]
    public function auto_named_vm_keys_do_not_collide_across_repeated_vm_names(): void
    {
        $calls  = [];
        $client = new class($calls) extends ProxmoxAccess {
            public function __construct(private array &$calls)
            {
                parent::__construct(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            public function post(string $path, array $data = []): array
            {
                $this->calls[] = $data;
                return ['data' => null];
            }

            public function put(string $path, array $data = []): array
            {
                return ['data' => null];
            }
        };
        $node = new ProxmoxNode($client);

        $a = $node->createUbuntuVMWithSSH('pve1', ['name' => 'lpx005-vm', 'vmid' => 301]);
        $b = $node->createUbuntuVMWithSSH('pve1', ['name' => 'lpx005-vm', 'vmid' => 302]);

        $this->assertNotSame($a['ssh_key'], $b['ssh_key']);

        $keyDir = rtrim(sys_get_temp_dir(), '/') . '/proxmox-ssh-keys';
        foreach (glob($keyDir . '/lpx005_vm*') ?: [] as $path) {
            $this->cleanupPaths[] = $path;
        }
        $this->assertCount(4, glob($keyDir . '/lpx005_vm*') ?: [], 'Each VM must get its own key pair on disk');
    }
}
