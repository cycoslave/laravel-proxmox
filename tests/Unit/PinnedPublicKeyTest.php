<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxManager;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * H2: SPKI public-key pinning (`pinned_public_key` -> CURLOPT_PINNEDPUBLICKEY).
 *
 * No network: option assertions go through the production buildCurlOptions(),
 * and the manager path is checked via config -> resolved ProxmoxAccess.
 */
class PinnedPublicKeyTest extends TestCase
{
    private const URL = 'https://127.0.0.1:8006/api2/json/nodes';

    private function pin(string $seed = 'node-a'): string
    {
        return 'sha256//' . base64_encode(hash('sha256', $seed, true));
    }

    private function access(
        string $host,
        bool $verifyTls = true,
        ?string $pin = null,
    ): ProxmoxAccess {
        return new class($host, $verifyTls, $pin) extends ProxmoxAccess {
            public function __construct(string $host, bool $verifyTls, ?string $pin)
            {
                parent::__construct(
                    host: $host,
                    tokenId: 'root@pam!tok',
                    tokenSecret: 'uuid-secret',
                    verifyTls: $verifyTls,
                    pinnedPublicKey: $pin,
                );
            }

            public function opts(): array
            {
                return $this->buildCurlOptions('GET', 'https://127.0.0.1:8006/api2/json/nodes');
            }
        };
    }

    #[Test]
    public function pin_reaches_curlopt_pinnedpublickey(): void
    {
        $pin  = $this->pin();
        $opts = $this->access('pin-1.test', true, $pin)->opts();

        $this->assertSame($pin, $opts[CURLOPT_PINNEDPUBLICKEY]);
        $this->assertTrue($opts[CURLOPT_SSL_VERIFYPEER]);
        $this->assertSame(2, $opts[CURLOPT_SSL_VERIFYHOST]);
    }

    #[Test]
    public function no_pin_leaves_pinnedpublickey_unset(): void
    {
        $opts = $this->access('pin-2.test')->opts();

        $this->assertArrayNotHasKey(CURLOPT_PINNEDPUBLICKEY, $opts);
    }

    #[Test]
    public function empty_pin_is_treated_as_no_pin(): void
    {
        $this->assertArrayNotHasKey(CURLOPT_PINNEDPUBLICKEY, $this->access('pin-3.test', true, '')->opts());
        $this->assertArrayNotHasKey(CURLOPT_PINNEDPUBLICKEY, $this->access('pin-3b.test', true, '  ')->opts());
    }

    #[Test]
    public function multiple_pins_are_accepted(): void
    {
        $pins = $this->pin('a') . ';' . $this->pin('b');

        $this->assertSame($pins, $this->access('pin-4.test', true, $pins)->opts()[CURLOPT_PINNEDPUBLICKEY]);
    }

    #[Test]
    public function pin_with_verify_off_is_allowed_and_does_not_warn(): void
    {
        Log::shouldReceive('warning')->never();

        $pin  = $this->pin();
        $opts = $this->access('pin-5.test', false, $pin)->opts();

        $this->assertSame($pin, $opts[CURLOPT_PINNEDPUBLICKEY]);
        $this->assertFalse($opts[CURLOPT_SSL_VERIFYPEER]);
        $this->assertSame(0, $opts[CURLOPT_SSL_VERIFYHOST]);
    }

    #[Test]
    public function no_pin_with_verify_off_still_warns(): void
    {
        Log::shouldReceive('warning')
            ->once()
            ->with('Proxmox: TLS verification disabled. Do not use in production.', [
                'endpoint' => \Cycoslave\Proxmox\Support\LogRedactor::endpointId('nopin-warn.test', 8006),
            ]);

        $opts = $this->access('nopin-warn.test', false)->opts();

        $this->assertFalse($opts[CURLOPT_SSL_VERIFYPEER]);
        $this->assertArrayNotHasKey(CURLOPT_PINNEDPUBLICKEY, $opts);
    }

    #[Test]
    public function malformed_pin_is_rejected(): void
    {
        foreach (['abc', 'sha1//' . base64_encode(hash('sha1', 'x', true)), 'sha256//short', $this->pin() . ';bad'] as $bad) {
            try {
                $this->access('pin-6.test', true, $bad);
                $this->fail("Pin [$bad] should have been rejected.");
            } catch (InvalidArgumentException $e) {
                $this->assertStringContainsString('pinned_public_key', $e->getMessage());
            }
        }
    }

    #[Test]
    public function debug_info_exposes_pin_but_not_secrets(): void
    {
        $info = $this->access('pin-7.test', true, $this->pin())->__debugInfo();

        $this->assertSame($this->pin(), $info['pinnedPublicKey']);
        $this->assertSame('[REDACTED]', $info['tokenSecret']);
    }

    #[Test]
    public function manager_passes_pinned_public_key_from_connection_config(): void
    {
        $pin = $this->pin('manager');
        $this->app['config']->set('proxmox', [
            'default'     => 'pinned',
            'connections' => [
                'pinned' => [
                    'host'              => 'mgr-pinned.test',
                    'username'          => 'root',
                    'token_id'          => 'root@pam!t',
                    'token_secret'      => 'secret',
                    'verify_tls'        => false,
                    'pinned_public_key' => $pin,
                ],
                'plain' => [
                    'host'         => 'mgr-plain.test',
                    'username'     => 'root',
                    'token_id'     => 'root@pam!t',
                    'token_secret' => 'secret',
                    'verify_tls'   => true,
                ],
            ],
        ]);

        $manager = new ProxmoxManager($this->app);

        $this->assertSame($pin, $this->curlOptionsOf($manager->connection('pinned'))[CURLOPT_PINNEDPUBLICKEY]);
        $this->assertArrayNotHasKey(CURLOPT_PINNEDPUBLICKEY, $this->curlOptionsOf($manager->connection('plain')));
    }

    private function curlOptionsOf(ProxmoxAccess $access): array
    {
        $url = self::URL;

        return (fn () => $this->buildCurlOptions('GET', $url))->call($access);
    }
}
