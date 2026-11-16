<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxManager;
use InvalidArgumentException;
use Orchestra\Testbench\TestCase as TestbenchTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * Regression tests for carbon F-02 (CWE-918): host/port were interpolated
 * into "https://{host}:{port}/api2/json" unvalidated, so
 * "attacker.example/collect?" redirected authenticated traffic elsewhere.
 */
class CarbonF02Test extends TestbenchTestCase
{
    protected function tearDown(): void
    {
        parent::tearDown();

        // Do not leak the booted Testbench container as the global app()
        // instance: GenerateSSHKeyTest (plain TestCase, runs later) derives
        // its key directory from app() when one is present.
        \Illuminate\Container\Container::setInstance(null);
    }
    private function make(string $host, int $port = 8006): object
    {
        return new class($host, $port) extends ProxmoxAccess {
            public function __construct(string $host, int $port)
            {
                parent::__construct(host: $host, port: $port, tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            public function url(): string
            {
                return $this->baseUrl();
            }
        };
    }

    /** @return array<string, array{string}> */
    public static function badHosts(): array
    {
        return [
            'path + query'      => ['attacker.example/collect?'],
            'path'              => ['attacker.example/x'],
            'query'             => ['attacker.example?x=1'],
            'fragment'          => ['attacker.example#frag'],
            'userinfo'          => ['user@attacker.example'],
            'userinfo+password' => ['user:pw@attacker.example'],
            'scheme'            => ['http://pve.example'],
            'https scheme'      => ['https://pve.example'],
            'embedded port'     => ['pve.example:8006'],
            'backslash'         => ['attacker.example\\@pve.example'],
            'space'             => ['pve example'],
            'trailing space'    => ['pve.example '],
            'newline'           => ["pve.example\nX: 1"],
            'NUL'               => ["pve.example\0"],
            'empty'             => [''],
            'underscore'        => ['pve_01.example'],
            'leading hyphen'    => ['-pve.example'],
            'trailing hyphen'   => ['pve-.example'],
            'empty label'       => ['pve..example'],
            'leading dot'       => ['.pve.example'],
            'trailing dot'      => ['pve.example.'],
            'unicode'           => ["pv\u{00e9}.example"],
            'label too long'    => [str_repeat('a', 64) . '.example'],
            'host too long'     => [str_repeat('a.', 130) . 'com'],
            'abbreviated ipv4'  => ['10.1'],
            'ipv4 out of range' => ['999.1.1.1'],
            'ipv6 with zone'    => ['[fe80::1%eth0]'],
            'ipv6 + port'       => ['[2001:db8::10]:8006'],
            'unbalanced ipv6'   => ['[2001:db8::10'],
            'bracket garbage'   => ['[attacker.example]'],
            'ipv6 + path'       => ['[2001:db8::10]/x'],
        ];
    }

    #[Test]
    #[DataProvider('badHosts')]
    public function malformed_hosts_are_rejected_at_construction(string $host): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->make($host);
    }

    /** @return array<string, array{string, string}> */
    public static function goodHosts(): array
    {
        return [
            'hostname'        => ['pve.example.com', 'pve.example.com'],
            'short hostname'  => ['pve1', 'pve1'],
            'hyphenated'      => ['pve-master-01.internal.lan', 'pve-master-01.internal.lan'],
            'mixed case'      => ['PVE.Example.COM', 'PVE.Example.COM'],
            'numeric label'   => ['10.example.com', '10.example.com'],
            'ipv4'            => ['192.168.1.10', '192.168.1.10'],
            'loopback'        => ['127.0.0.1', '127.0.0.1'],
            'bare ipv6'       => ['2001:db8::10', '[2001:db8::10]'],
            'bracketed ipv6'  => ['[2001:db8::10]', '[2001:db8::10]'],
            'ipv6 loopback'   => ['::1', '[::1]'],
        ];
    }

    #[Test]
    #[DataProvider('goodHosts')]
    public function legitimate_hosts_are_accepted_and_build_the_expected_authority(string $host, string $authority): void
    {
        $url = $this->make($host, 8443)->url();

        $this->assertSame("https://{$authority}:8443/api2/json", $url);

        $parts = parse_url($url);
        $this->assertSame('https', $parts['scheme']);
        $this->assertSame(8443, $parts['port']);
        $this->assertSame('/api2/json', $parts['path']);
        $this->assertArrayNotHasKey('query', $parts);
        $this->assertArrayNotHasKey('user', $parts);
    }

    /** @return array<string, array{int}> */
    public static function badPorts(): array
    {
        return [
            'zero'      => [0],
            'negative'  => [-1],
            'too large' => [65536],
            'huge'      => [99999],
        ];
    }

    #[Test]
    #[DataProvider('badPorts')]
    public function out_of_range_ports_are_rejected(int $port): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->make('pve.example.com', $port);
    }

    #[Test]
    public function boundary_ports_are_accepted(): void
    {
        $this->assertSame('https://pve.example.com:1/api2/json', $this->make('pve.example.com', 1)->url());
        $this->assertSame('https://pve.example.com:65535/api2/json', $this->make('pve.example.com', 65535)->url());
    }

    #[Test]
    public function the_exception_message_does_not_echo_the_rejected_host(): void
    {
        try {
            $this->make('attacker.example/collect?');
            $this->fail('Expected InvalidArgumentException');
        } catch (InvalidArgumentException $e) {
            $this->assertStringNotContainsString('attacker', $e->getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Manager-level: bad config yields InvalidArgumentException from resolve(),
    // including missing host/username (previously an undefined-key warning /
    // TypeError).
    // -------------------------------------------------------------------------

    /** @param array<string, mixed> $connection */
    private function manager(array $connection): ProxmoxManager
    {
        $this->app['config']->set('proxmox', [
            'default'     => 'primary',
            'connections' => ['primary' => $connection],
        ]);

        return new ProxmoxManager($this->app);
    }

    /** @return array<string, mixed> */
    private function base(array $override = []): array
    {
        return array_merge([
            'host' => '10.0.0.1', 'port' => 8006, 'username' => 'root',
            'token_id' => 'root@pam!t', 'token_secret' => 's',
        ], $override);
    }

    #[Test]
    public function a_valid_connection_still_resolves(): void
    {
        $this->assertInstanceOf(ProxmoxAccess::class, $this->manager($this->base())->connection());
        $this->assertInstanceOf(ProxmoxAccess::class, $this->manager($this->base(['port' => '8443']))->connection());
    }

    #[Test]
    public function an_injected_host_in_config_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->manager($this->base(['host' => 'attacker.example/collect?']))->connection();
    }

    #[Test]
    public function an_invalid_port_in_config_is_rejected(): void
    {
        foreach ([0, 70000, 'evil', '8006/x', -5, [8006]] as $port) {
            try {
                $this->manager($this->base(['port' => $port]))->connection();
                $this->fail('Port ' . json_encode($port) . ' should have been rejected');
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    #[Test]
    public function missing_or_non_string_host_and_username_are_rejected(): void
    {
        foreach ([['host' => null], ['host' => ''], ['host' => ['x']], ['username' => null], ['username' => '']] as $override) {
            try {
                $this->manager($this->base($override))->connection();
                $this->fail('Config ' . json_encode($override) . ' should have been rejected');
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
