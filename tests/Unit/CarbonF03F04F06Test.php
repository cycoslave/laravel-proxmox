<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for carbon F-03 / F-04 / F-06 (ProxmoxNode input validation).
 *
 *  F-03 (CWE-88): detachDisk() forwarded $disk unvalidated into PVE's
 *        comma/space separated `delete` list.
 *  F-04 (CWE-88): cloud-init helpers interpolated unvalidated values into the
 *        `ipconfig0` property string and sent `sshkeys` raw.
 *  F-06 (CWE-20): attachDisk() stripped non-digits from `size`
 *        ('10.5G' -> '105', '-20G' -> '20').
 */
class CarbonF03F04F06Test extends TestCase
{
    private const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkYn0lUe1hAbCdEfGhIjKlMnOpQrStUvWxYz012345 user@host';

    protected function setUp(): void
    {
        parent::setUp();
        // safeErrorMessage() logs through the facade; keep the suite independent of an app container.
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
    private function node(array &$calls, array|\Closure $responder = ['data' => null]): ProxmoxNode
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

    /** @param array<int, array<string, mixed>> $calls */
    private function writes(array $calls): array
    {
        return array_values(array_filter($calls, fn ($c) => $c['method'] !== 'GET'));
    }

    // ---------------------------------------------------------------- F-03

    /** @return array<string, array{string}> */
    public static function goodSlots(): array
    {
        $out = [];
        foreach (['scsi0', 'scsi12', 'sata1', 'ide2', 'virtio3', 'efidisk0', 'tpmstate0', 'unused4'] as $s) {
            $out[$s] = [$s];
        }
        return $out;
    }

    /** @return array<string, array{string}> */
    public static function badSlots(): array
    {
        return [
            'comma list'       => ['scsi1,protection'],
            'comma net0'       => ['scsi1,protection,net0,sshkeys'],
            'space list'       => ['scsi1 net0'],
            'semicolon'        => ['scsi1;net0'],
            'trailing comma'   => ['scsi0,'],
            'non-disk key'     => ['protection'],
            'net0'             => ['net0'],
            'sshkeys'          => ['sshkeys'],
            'no index'         => ['scsi'],
            'negative index'   => ['scsi-1'],
            'uppercase'        => ['SCSI0'],
            'empty'            => [''],
            'trailing newline' => ["scsi0\n"],
            'leading space'    => [' scsi0'],
            'embedded newline' => ["scsi0\nnet0"],
            'nul'              => ["scsi0\0"],
            'unicode digit'    => ["scsi\u{0663}"],
        ];
    }

    #[Test]
    #[DataProvider('goodSlots')]
    public function detach_disk_accepts_a_single_disk_slot(string $slot): void
    {
        $calls = [];
        $r = $this->node($calls)->detachDisk('pve1', 100, $slot);

        $this->assertTrue($r['success']);
        $this->assertSame(['delete' => $slot, 'force' => false], $calls[0]['data']);
        $this->assertSame($slot, $r['data']['disk']);
    }

    #[Test]
    #[DataProvider('badSlots')]
    public function detach_disk_rejects_anything_but_a_single_disk_slot(string $bad): void
    {
        $calls = [];
        try {
            $this->node($calls)->detachDisk('pve1', 100, $bad, true);
            $this->fail('Expected InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringNotContainsString('protection', $e->getMessage());
        }
        $this->assertSame([], $calls, 'Nothing may reach the API');
    }

    // ---------------------------------------------------------------- F-04

    /** @return array<string, array{string}> */
    public static function badCloudInitValues(): array
    {
        return [
            'comma'     => ['24,ip6=dhcp'],
            'equals'    => ['24=1'],
            'lf'        => ["24\nipconfig1=x"],
            'cr'        => ["24\r"],
            'crlf'      => ["24\r\n"],
            'nul'       => ["24\0"],
            'gw inject' => ['24,gw=10.9.9.9'],
        ];
    }

    #[Test]
    #[DataProvider('badCloudInitValues')]
    public function configure_network_rejects_delimiters_in_subnet_mask(string $bad): void
    {
        $calls = [];
        try {
            $this->node($calls)->configureNetwork('pve1', 100, [
                'ip' => '10.0.0.5', 'gateway' => '10.0.0.1', 'subnet_mask' => $bad,
            ]);
            $this->fail('Expected exception');
        } catch (\Exception $e) {
            $this->assertSame('Failed to configure network.', $e->getMessage());
            $this->assertInstanceOf(\InvalidArgumentException::class, $e->getPrevious());
        }
        $this->assertSame([], $calls);
    }

    #[Test]
    public function configure_network_still_builds_the_same_ipconfig(): void
    {
        $calls = [];
        $r = $this->node($calls)->configureNetwork('pve1', 100, [
            'ip' => '10.0.0.5', 'gateway' => '10.0.0.1', 'subnet_mask' => '16',
            'nameserver' => '1.1.1.1', 'searchdomain' => 'example.test',
        ]);

        $this->assertTrue($r['success']);
        $this->assertSame([
            'ipconfig0'    => 'ip=10.0.0.5/16,gw=10.0.0.1',
            'nameserver'   => '1.1.1.1',
            'searchdomain' => 'example.test',
        ], $calls[0]['data']);

        $calls = [];
        $this->node($calls)->configureNetwork('pve1', 100, ['ip' => '10.0.0.5', 'gateway' => '10.0.0.1']);
        $this->assertSame('ip=10.0.0.5/24,gw=10.0.0.1', $calls[0]['data']['ipconfig0']);
    }

    #[Test]
    public function configure_network_rejects_line_breaks_in_dns_fields(): void
    {
        foreach (['nameserver', 'searchdomain'] as $field) {
            $calls = [];
            try {
                $this->node($calls)->configureNetwork('pve1', 100, [
                    'ip' => '10.0.0.5', 'gateway' => '10.0.0.1', $field => "1.1.1.1\nciuser=root",
                ]);
                $this->fail("Expected exception for {$field}");
            } catch (\Exception $e) {
                $this->assertSame('Failed to configure network.', $e->getMessage());
            }
            $this->assertSame([], $calls);
        }
    }

    /** @return array<string, array{mixed, mixed, mixed}> */
    public static function badIpconfigArgs(): array
    {
        return [
            'netmask comma'   => ['10.0.0.5', '10.0.0.1', '24,ip6=dhcp'],
            'netmask equals'  => ['10.0.0.5', '10.0.0.1', 'x=1'],
            'netmask newline' => ['10.0.0.5', '10.0.0.1', "24\n"],
            'gateway comma'   => ['10.0.0.5', '10.0.0.1,ip6=auto', '24'],
            'gateway equals'  => ['10.0.0.5', 'gw=1', '24'],
            'gateway newline' => ['10.0.0.5', "10.0.0.1\r\nx", '24'],
            'ip comma'        => ['10.0.0.5,ip6=dhcp', '10.0.0.1', '24'],
            'ip equals'       => ['ip=1', '10.0.0.1', '24'],
            'ip crlf'         => ["10.0.0.5\r\n", '10.0.0.1', '24'],
            'array netmask'   => ['10.0.0.5', '10.0.0.1', ['24']],
            'null gateway'    => ['10.0.0.5', null, '24'],
        ];
    }

    #[Test]
    #[DataProvider('badIpconfigArgs')]
    public function configure_vm_cloud_init_network_rejects_delimiters(mixed $ip, mixed $gw, mixed $mask): void
    {
        $calls = [];
        try {
            $this->node($calls)->configureVMCloudInitNetwork('pve1', 100, $ip, $gw, $mask);
            $this->fail('Expected InvalidArgumentException');
        } catch (\InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
        $this->assertSame([], $calls);
    }

    #[Test]
    public function configure_vm_cloud_init_network_accepts_string_and_int_values(): void
    {
        $calls = [];
        $r = $this->node($calls)->configureVMCloudInitNetwork('pve1', 100, '10.0.0.5', '10.0.0.1', 24);
        $this->assertTrue($r['success']);
        $this->assertSame('ip=10.0.0.5/24,gw=10.0.0.1', $calls[0]['data']['ipconfig0']);
    }

    #[Test]
    public function attach_ssh_key_sends_the_key_percent_encoded(): void
    {
        $calls = [];
        $this->node($calls, fn ($m, $p) => ['data' => ['name' => 'vm']])
            ->attachSSHKey('pve1', 100, '  ' . self::KEY . "\n");

        $post = $this->writes($calls)[0];
        $this->assertSame(rawurlencode(self::KEY), $post['data']['sshkeys']);
        $this->assertStringNotContainsString(' ', $post['data']['sshkeys']);
        $this->assertStringNotContainsString('+', $post['data']['sshkeys']);
    }

    /** @return array<string, array{string}> */
    public static function badSshKeys(): array
    {
        return [
            'second key via LF'   => [self::KEY . "\n" . self::KEY],
            'second key via CRLF' => [self::KEY . "\r\n" . self::KEY],
            'embedded CR'         => ["ssh-ed25519 AAAA\rssh-rsa BBBB"],
            'nul'                 => ["ssh-ed25519 AAAA\0x"],
            'leading option'      => ['command="echo pwned" ' . self::KEY],
            'leading from='       => ['from="*",no-pty ' . self::KEY],
            'not a key'           => ['hello world'],
        ];
    }

    #[Test]
    #[DataProvider('badSshKeys')]
    public function attach_ssh_key_rejects_multi_line_or_option_prefixed_keys(string $bad): void
    {
        $calls = [];
        try {
            $this->node($calls)->attachSSHKey('pve1', 100, $bad);
            $this->fail('Expected InvalidArgumentException');
        } catch (\InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
        $this->assertSame([], $calls);
    }

    #[Test]
    public function attach_ssh_key_rejects_an_empty_key(): void
    {
        $calls = [];
        $this->expectException(\InvalidArgumentException::class);
        try {
            $this->node($calls)->attachSSHKey('pve1', 100, "  \n ");
        } finally {
            $this->assertSame([], $calls);
        }
    }

    #[Test]
    public function inject_ssh_credentials_percent_encodes_the_key(): void
    {
        $calls = [];
        $this->node($calls)->injectSSHCredentials('pve1', 100, 'ubuntu', 'pw,with=delims', self::KEY);

        $this->assertSame(rawurlencode(self::KEY), $calls[0]['data']['sshkeys']);
        // Not a property string: the password keeps its characters verbatim.
        $this->assertSame('pw,with=delims', $calls[0]['data']['cipassword']);
    }

    #[Test]
    #[DataProvider('badSshKeys')]
    public function inject_ssh_credentials_rejects_multi_line_or_option_prefixed_keys(string $bad): void
    {
        $calls = [];
        try {
            $this->node($calls)->injectSSHCredentials('pve1', 100, 'ubuntu', 'pw', $bad);
            $this->fail('Expected InvalidArgumentException');
        } catch (\InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
        $this->assertSame([], $calls);
    }

    #[Test]
    public function inject_ssh_credentials_without_a_key_is_unchanged(): void
    {
        $calls = [];
        $this->node($calls)->injectSSHCredentials('pve1', 100, 'ubuntu', 'pw');
        $this->assertArrayNotHasKey('sshkeys', $calls[0]['data']);
    }

    #[Test]
    public function create_ubuntu_vm_with_ssh_encodes_and_validates_a_supplied_key(): void
    {
        $calls = [];
        $r = $this->node($calls)->createUbuntuVMWithSSH('pve1', ['vmid' => 400, 'name' => 'vm'], self::KEY);
        $this->assertSame(rawurlencode(self::KEY), $calls[0]['data']['sshkeys']);
        $this->assertSame(self::KEY, $r['ssh_key']);

        $calls = [];
        try {
            $this->node($calls)->createUbuntuVMWithSSH('pve1', ['vmid' => 401], self::KEY . "\nssh-rsa EVIL");
            $this->fail('Expected InvalidArgumentException');
        } catch (\InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
        $this->assertSame([], $calls);
    }

    // ---------------------------------------------------------------- F-06

    private function attach(array &$calls, mixed $size): array
    {
        $responder = fn (string $m, string $p) => $m === 'GET'
            ? ['data' => ['scsi0' => 'local-lvm:vm-100-disk-0']]
            : ['data' => null];

        return $this->node($calls, $responder)->attachDisk('pve1', 100, ['storage' => 'local-lvm', 'size' => $size]);
    }

    /** @return array<string, array{mixed, string}> */
    public static function goodSizes(): array
    {
        return [
            '10G'      => ['10G', '10'],
            '10 (GiB)' => ['10', '10'],
            'int 10'   => [10, '10'],
            '10g'      => ['10g', '10'],
            '2T'       => ['2T', '2048'],
            '2048M'    => ['2048M', '2'],
            '1048576K' => ['1048576K', '1'],
            '1G'       => ['1G', '1'],
        ];
    }

    #[Test]
    #[DataProvider('goodSizes')]
    public function attach_disk_accepts_whole_number_sizes(mixed $size, string $expectedGiB): void
    {
        $calls = [];
        $r = $this->attach($calls, $size);

        $this->assertTrue($r['success'], json_encode($r));
        $post = $this->writes($calls)[0];
        $this->assertSame(['scsi1' => "local-lvm:{$expectedGiB}"], $post['data']);
    }

    /** @return array<string, array{mixed}> */
    public static function badSizes(): array
    {
        return [
            'fractional'       => ['10.5G'],
            'negative'         => ['-20G'],
            'plus'             => ['+5G'],
            'plus no unit'     => ['+5'],
            'zero'             => ['0'],
            'zero G'           => ['0G'],
            'int zero'         => [0],
            'int negative'     => [-5],
            'letters'          => ['abc'],
            'empty'            => [''],
            'bad unit'         => ['10GB'],
            'bad unit P'       => ['10P'],
            'leading space'    => [' 10G'],
            'trailing newline' => ["10G\n"],
            'exponent'         => ['1e3'],
            'comma'            => ['1,5G'],
            'option injection' => ['10G,net0=virtio'],
            'embedded junk'    => ['1x0G'],
            'sub-GiB M'        => ['1500M'],
            'sub-GiB K'        => ['1024K'],
            'float'            => [10.5],
            'float whole'      => [10.0],
            'bool'             => [true],
            'array'            => [['10G']],
            'huge'             => ['99999999999999999999999G'],
            'unicode digits'   => ["\u{0661}\u{0660}G"],
        ];
    }

    #[Test]
    #[DataProvider('badSizes')]
    public function attach_disk_rejects_invalid_sizes_instead_of_stripping_them(mixed $size): void
    {
        $calls = [];
        $r = $this->attach($calls, $size);

        $this->assertFalse($r['success']);
        $this->assertSame([], $this->writes($calls), 'No POST may be sent with a mangled size');
    }
}
