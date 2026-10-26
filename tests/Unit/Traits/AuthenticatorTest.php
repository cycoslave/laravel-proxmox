<?php

namespace Cycoslave\Proxmox\Tests\Unit\Traits;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\Exceptions\AuthenticationException;

/**
 * Tests for Traits\Authenticator (exercised via ProxmoxAccess).
 *
 * Strategy: subclass ProxmoxAccess and override sendRequest() so no real
 * network calls are made. This lets us unit-test auth logic in isolation.
 */
class AuthenticatorTest extends TestCase
{
    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function makeAccess(array $fixture, array &$captured = []): ProxmoxAccess
    {
        return new class(
            host: '127.0.0.1',
            fixture: $fixture,
            captured: $captured,
        ) extends ProxmoxAccess {
            public function __construct(
                string $host,
                private readonly array $fixture,
                private array &$captured,
                int $port = 8006,
                string $username = 'root',
                string $realm = 'pam',
                ?string $password = 'secret',
                ?string $tokenId = null,
                ?string $tokenSecret = null,
                bool $verifyTls = true,
                int $timeout = 10,
            ) {
                parent::__construct(
                    host: $host,
                    port: $port,
                    username: $username,
                    realm: $realm,
                    password: $password,
                    tokenId: $tokenId,
                    tokenSecret: $tokenSecret,
                    verifyTls: $verifyTls,
                    timeout: $timeout,
                );
            }

            protected function sendRequest(
                string $method,
                string $url,
                array  $params  = [],
                array  $headers = [],
            ): array {
                $this->captured[] = compact('method', 'url', 'params', 'headers');
                return $this->fixture;
            }
        };
    }

    private function ticketFixture(): array
    {
        return [
            'data' => [
                'ticket'              => 'PVE:root@pam:DEADBEEF',
                'CSRFPreventionToken' => 'CSRF-TOKEN-123',
            ],
        ];
    }

    // -------------------------------------------------------------------------
    // API token auth
    // -------------------------------------------------------------------------

    #[Test]
    public function it_uses_api_token_header_when_token_credentials_are_set(): void
    {
        $captured = [];

        $access = new class(
            host: '127.0.0.1',
            captured: $captured,
        ) extends ProxmoxAccess {
            public function __construct(string $host, private array &$captured) {
                parent::__construct(
                    host: $host,
                    tokenId: 'root@pam!mytoken',
                    tokenSecret: 'aaaabbbb-cccc-dddd-eeee-ffffffffffff',
                );
            }

            protected function sendRequest(
                string $method, string $url, array $params = [], array $headers = []
            ): array {
                $this->captured[] = compact('method', 'url', 'params', 'headers');
                return ['data' => ['nodes' => []]];
            }
        };

        $access->get('nodes');

        $this->assertCount(1, $captured);

        $authHeader = collect($captured[0]['headers'])->first(
            fn($h) => str_starts_with($h, 'Authorization:')
        );

        $this->assertNotNull($authHeader, 'No Authorization header found');
        $this->assertStringContainsString('PVEAPIToken=', $authHeader);
        $this->assertStringContainsString('root@pam!mytoken=', $authHeader);
        $this->assertStringContainsString('aaaabbbb-cccc-dddd-eeee-ffffffffffff', $authHeader);
    }

    #[Test]
    public function it_does_not_call_login_when_using_token_auth(): void
    {
        $captured = [];

        $access = new class(
            host: '127.0.0.1',
            captured: $captured,
        ) extends ProxmoxAccess {
            public function __construct(string $host, private array &$captured) {
                parent::__construct(
                    host: $host,
                    tokenId: 'root@pam!tok',
                    tokenSecret: 'secret-uuid',
                );
            }

            protected function sendRequest(
                string $method, string $url, array $params = [], array $headers = []
            ): array {
                $this->captured[] = compact('url');
                return ['data' => []];
            }
        };

        $access->get('nodes');

        $this->assertCount(1, $captured);
        $this->assertStringNotContainsString('/access/ticket', $captured[0]['url']);
    }

    // -------------------------------------------------------------------------
    // Ticket auth
    // -------------------------------------------------------------------------

    #[Test]
    public function it_sends_ticket_login_request_on_first_call_with_password_auth(): void
    {
        $captured = [];
        $access   = $this->makeAccess($this->ticketFixture(), $captured);

        $access->get('nodes');

        $this->assertCount(2, $captured);
        $this->assertSame('POST', $captured[0]['method']);
        $this->assertStringEndsWith('/access/ticket', $captured[0]['url']);
    }

    #[Test]
    public function ticket_login_payload_uses_username_at_realm_format(): void
    {
        $captured = [];

        $access = new class(
            host: '127.0.0.1',
            captured: $captured,
        ) extends ProxmoxAccess {
            public function __construct(string $host, private array &$captured) {
                parent::__construct(
                    host: $host,
                    username: 'admin',
                    realm: 'pve',
                    password: 'hunter2',
                );
            }

            protected function sendRequest(
                string $method, string $url, array $params = [], array $headers = []
            ): array {
                $this->captured[] = compact('method', 'url', 'params');
                return [
                    'data' => [
                        'ticket'              => 'PVE:admin@pve:DEADBEEF',
                        'CSRFPreventionToken' => 'CSRF-XYZ',
                    ],
                ];
            }
        };

        $access->get('nodes');

        $this->assertSame('admin@pve', $captured[0]['params']['username']);
        $this->assertSame('hunter2',  $captured[0]['params']['password']);
    }

    #[Test]
    public function ticket_is_cached_and_not_re_requested_on_subsequent_calls(): void
    {
        $captured = [];
        $access   = $this->makeAccess($this->ticketFixture(), $captured);

        $access->get('nodes');
        $access->get('version');

        $this->assertCount(3, $captured);

        $loginCalls = array_filter(
            $captured,
            fn($c) => str_ends_with($c['url'], '/access/ticket'),
        );
        $this->assertCount(1, $loginCalls, 'Ticket should only be fetched once');
    }

    #[Test]
    public function expired_ticket_triggers_re_authentication(): void
    {
        $captured = [];

        $access = new class(
            host: '127.0.0.1',
            captured: $captured,
        ) extends ProxmoxAccess {
            public function __construct(string $host, private array &$captured) {
                parent::__construct(host: $host, password: 'secret');
            }

            protected function sendRequest(
                string $method, string $url, array $params = [], array $headers = []
            ): array {
                $this->captured[] = compact('url');
                return [
                    'data' => [
                        'ticket'              => 'PVE:root@pam:FRESH',
                        'CSRFPreventionToken' => 'NEW-CSRF',
                    ],
                ];
            }

            // PLG-R2-01 harness fix: $ticket/$csrf/$ticketExpiry are private
            // properties compiled into ProxmoxAccess by the Authenticator
            // trait, so this anonymous subclass cannot see them by name --
            // `$this->ticket = ...` here would silently create unrelated
            // dynamic properties on the subclass instead of mutating the
            // real state, and authHeaders() (running in ProxmoxAccess's own
            // scope) would keep reading the untouched, still-valid ticket.
            // Reflection reaches the actual private storage declared on
            // ProxmoxAccess so the test genuinely forces expiry.
            public function expireTicket(): void
            {
                foreach (['ticket' => 'PVE:root@pam:OLD', 'csrf' => 'OLD-CSRF', 'ticketExpiry' => time() - 1] as $prop => $value) {
                    $ref = new \ReflectionProperty(ProxmoxAccess::class, $prop);
                    $ref->setAccessible(true);
                    $ref->setValue($this, $value);
                }
            }
        };

        $access->get('nodes');    // login + GET
        $access->expireTicket();
        $access->get('version');  // re-login + GET

        $loginCalls = array_filter(
            $captured,
            fn($c) => str_ends_with($c['url'], '/access/ticket'),
        );
        $this->assertCount(2, $loginCalls, 'Should re-authenticate after expiry');
    }

    #[Test]
    public function it_sends_cookie_and_csrf_headers_for_ticket_auth(): void
    {
        $captured = [];
        $access   = $this->makeAccess($this->ticketFixture(), $captured);

        $access->get('nodes');

        $headers = $captured[1]['headers'];

        $cookieHeader = collect($headers)->first(fn($h) => str_starts_with($h, 'Cookie:'));
        $csrfHeader   = collect($headers)->first(fn($h) => str_starts_with($h, 'CSRFPreventionToken:'));

        $this->assertNotNull($cookieHeader, 'Cookie header missing');
        $this->assertStringContainsString('PVEAuthCookie=PVE:root@pam:DEADBEEF', $cookieHeader);
        $this->assertNotNull($csrfHeader, 'CSRF header missing');
        $this->assertStringContainsString('CSRF-TOKEN-123', $csrfHeader);
    }

    // -------------------------------------------------------------------------
    // Null-password guard
    // -------------------------------------------------------------------------

    #[Test]
    public function it_throws_authentication_exception_when_password_is_null_and_no_token(): void
    {
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessageMatches('/password/i');

        $access = new class(host: '127.0.0.1') extends ProxmoxAccess {
            public function __construct(string $host) {
                parent::__construct(host: $host, password: null);
            }

            protected function sendRequest(
                string $method, string $url, array $params = [], array $headers = []
            ): array {
                return [];
            }
        };

        $access->get('nodes');
    }

    #[Test]
    public function it_throws_authentication_exception_when_ticket_response_has_no_ticket(): void
    {
        $this->expectException(AuthenticationException::class);

        $access = new class(host: '127.0.0.1') extends ProxmoxAccess {
            public function __construct(string $host) {
                parent::__construct(host: $host, password: 'pw');
            }

            protected function sendRequest(
                string $method, string $url, array $params = [], array $headers = []
            ): array {
                return ['data' => []];
            }
        };

        $access->get('nodes');
    }
}