<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\Exceptions\AuthenticationException;
use Cycoslave\Proxmox\Exceptions\ProxmoxException;
use Cycoslave\Proxmox\ProxmoxAccess;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for carbon F-05 (CWE-113): CR/LF/NUL must never reach
 * CURLOPT_HTTPHEADER, and a ticket response without CSRFPreventionToken
 * must fail with AuthenticationException instead of a PHP warning.
 */
class CarbonF05Test extends TestCase
{
    /** @param array<string, mixed> $fixture */
    private function access(array $fixture = [], ?string $tokenId = null, ?string $tokenSecret = null): object
    {
        return new class('127.0.0.1', $fixture, $tokenId, $tokenSecret) extends ProxmoxAccess {
            public int $sent = 0;

            /** @param array<string, mixed> $fixture */
            public function __construct(string $host, private array $fixture, ?string $tokenId, ?string $tokenSecret)
            {
                parent::__construct(
                    host: $host,
                    password: 'pw',
                    tokenId: $tokenId,
                    tokenSecret: $tokenSecret,
                );
            }

            protected function sendRequest(
                string $method,
                string $url,
                array  $params = [],
                array  $headers = [],
            ): array {
                $this->sent++;
                return $this->fixture;
            }

            /** @return string[] */
            public function headers(): array
            {
                return $this->authHeaders();
            }
        };
    }

    /** @return array<string, array{string}> */
    public static function badValues(): array
    {
        return [
            'LF'   => ["abc\nX-Evil: 1"],
            'CR'   => ["abc\rX-Evil: 1"],
            'CRLF' => ["abc\r\nX-Evil-Injected: pwned\r\n\r\nPOST /api2/json/x HTTP/1.1"],
            'NUL'  => ["abc\0def"],
        ];
    }

    #[Test]
    #[DataProvider('badValues')]
    public function token_secret_with_control_bytes_is_rejected(string $bad): void
    {
        $access = $this->access([], 'root@pam!t', $bad);

        $this->expectException(ProxmoxException::class);
        $access->headers();
    }

    #[Test]
    #[DataProvider('badValues')]
    public function token_id_with_control_bytes_is_rejected(string $bad): void
    {
        $access = $this->access([], $bad, 'uuid');

        $this->expectException(ProxmoxException::class);
        $access->headers();
    }

    #[Test]
    #[DataProvider('badValues')]
    public function ticket_with_control_bytes_is_rejected_and_not_cached(string $bad): void
    {
        $access = $this->access(['data' => ['ticket' => $bad, 'CSRFPreventionToken' => 'ok']]);

        try {
            $access->headers();
            $this->fail('expected ProxmoxException');
        } catch (ProxmoxException $e) {
            $this->assertStringNotContainsString('X-Evil', $e->getMessage());
        }

        // Not cached: a second attempt re-authenticates rather than reusing the bad value.
        try {
            $access->headers();
        } catch (ProxmoxException) {
        }
        $this->assertSame(2, $access->sent);
    }

    #[Test]
    #[DataProvider('badValues')]
    public function csrf_token_with_control_bytes_is_rejected(string $bad): void
    {
        $access = $this->access(['data' => ['ticket' => 'PVE:root@pam:ABC', 'CSRFPreventionToken' => $bad]]);

        $this->expectException(ProxmoxException::class);
        $access->headers();
    }

    #[Test]
    public function missing_csrf_token_throws_authentication_exception_without_warning(): void
    {
        $access = $this->access(['data' => ['ticket' => 'PVE:root@pam:ABC']]);

        $warnings = [];
        set_error_handler(function (int $no, string $str) use (&$warnings): bool {
            $warnings[] = $str;
            return true;
        });

        try {
            $access->headers();
            $this->fail('expected AuthenticationException');
        } catch (AuthenticationException $e) {
            $this->assertStringContainsString('CSRF', $e->getMessage());
        } finally {
            restore_error_handler();
        }

        $this->assertSame([], $warnings, 'no PHP warning for the missing CSRFPreventionToken key');
    }

    #[Test]
    public function non_string_csrf_token_is_rejected(): void
    {
        $access = $this->access(['data' => ['ticket' => 'PVE:root@pam:ABC', 'CSRFPreventionToken' => ['x']]]);

        $this->expectException(AuthenticationException::class);
        $access->headers();
    }

    #[Test]
    public function clean_values_still_produce_the_same_headers(): void
    {
        $token = $this->access([], 'root@pam!t', 'uuid-1234');
        $this->assertSame(['Authorization: PVEAPIToken=root@pam!t=uuid-1234'], $token->headers());

        $ticket = $this->access(['data' => ['ticket' => 'PVE:root@pam:ABC', 'CSRFPreventionToken' => 'CSRF-1']]);
        $this->assertSame(
            ['Cookie: PVEAuthCookie=PVE:root@pam:ABC', 'CSRFPreventionToken: CSRF-1'],
            $ticket->headers()
        );
    }
}
