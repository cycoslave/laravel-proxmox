<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Illuminate\Support\Facades\Log;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\Exceptions\ApiException;
use Cycoslave\Proxmox\Exceptions\ConnectionException;

/**
 * Regression tests for the SAST-006 + SAST-007 + SAST-008 (Low) batch.
 *
 * SAST-006 (CWE-209): raw $e->getMessage() (curl diagnostics, hostnames)
 * was concatenated straight into caller-facing `message` envelopes across
 * ProxmoxNode.php and Authenticator::loginWithTicket(). Fixed via
 * ProxmoxNode::safeErrorMessage(), which logs the raw detail and returns a
 * generic, context-only string; Authenticator now does the equivalent
 * inline before throwing AuthenticationException.
 *
 * SAST-007 (CWE-393, secondary CWE-532):
 *   - ProxmoxAccess::__construct() logged the TLS-disabled warning (with
 *     hostname) on every construction — log-noise DoS. Now once-guarded
 *     per host for the process lifetime.
 *   - ProxmoxNode::configureVMCloudInitNetwork() inverted the success
 *     predicate (`!isset($response['data'])` treated as SUCCESS). Fixed to
 *     `array_key_exists('data', $response)`, matching every other call
 *     site (e.g. ProxmoxStorage::deleteStorage()).
 *
 * SAST-008 (CWE-613): the ticket TTL was a hard-coded 7200-60s local timer
 * with no way to detect server-side early invalidation, and no retry path.
 * ProxmoxAccess::request() now catches a 401 ApiException, discards the
 * cached ticket via Authenticator::invalidateTicket(), and retries once
 * with a freshly issued ticket (API-token auth is excluded — nothing to
 * refresh there).
 */
class SastLowBatchTest extends TestCase
{
    protected function tearDown(): void
    {
        Log::clearResolvedInstance();
        parent::tearDown();
    }

    /**
     * Minimal fake logger bound behind the Log facade so Log::warning()
     * calls made deep inside the package resolve without needing a full
     * booted Laravel application / container.
     */
    private function fakeLogger(): object
    {
        return new class {
            public array $warnings = [];

            public function warning($message, array $context = [])
            {
                $this->warnings[] = compact('message', 'context');
            }
        };
    }

    // -------------------------------------------------------------------------
    // SAST-006: exception-message leakage (CWE-209)
    // -------------------------------------------------------------------------

    #[Test]
    public function delete_vm_does_not_leak_raw_exception_message_to_caller(): void
    {
        $logger = $this->fakeLogger();
        Log::swap($logger);

        $client = new class('127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret') extends ProxmoxAccess {
            public function get(string $path, array $params = []): array
            {
                return ['data' => ['status' => 'stopped']];
            }

            public function delete(string $path, array $params = []): array
            {
                throw new ConnectionException('Proxmox cURL error: Could not resolve host: internal-pve-07.corp.example (Domain name not found)');
            }
        };

        $result = (new ProxmoxNode($client))->deleteVM('pve1', 100, force: false, purge: true);

        $this->assertFalse($result['success']);
        $this->assertStringNotContainsString('internal-pve-07.corp.example', $result['message']);
        $this->assertStringNotContainsString('cURL', $result['message']);
        $this->assertSame('Failed to delete VM 100.', $result['message']);

        // LPX-006: the log entry is categorised and never carries the raw
        // diagnostic (hostnames / IPs) either.
        $this->assertCount(1, $logger->warnings);
        $this->assertSame('network', $logger->warnings[0]['context']['category']);
        $this->assertSame('ConnectionException', $logger->warnings[0]['context']['error_class']);
        $this->assertStringNotContainsString('internal-pve-07.corp.example', json_encode($logger->warnings[0]));
    }

    #[Test]
    public function delete_multiple_vms_does_not_leak_raw_exception_message_per_vmid(): void
    {
        Log::swap($this->fakeLogger());

        $client = new class('127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret') extends ProxmoxAccess {
            public function get(string $path, array $params = []): array
            {
                throw new ConnectionException('Proxmox cURL error: Failed to connect to 10.0.0.55 port 8006: Connection refused');
            }
        };

        $result = (new ProxmoxNode($client))->deleteMultipleVMs('pve1', [101]);

        $this->assertArrayHasKey(101, $result['errors']);
        $this->assertStringNotContainsString('10.0.0.55', $result['errors'][101]);
        $this->assertSame('Failed to delete VM 101.', $result['errors'][101]);
    }

    #[Test]
    public function fix_guest_agent_thrown_exception_does_not_leak_raw_message(): void
    {
        Log::swap($this->fakeLogger());

        $client = new class('127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret') extends ProxmoxAccess {
            public function post(string $path, array $data = []): array
            {
                throw new ConnectionException('Proxmox cURL error: SSL certificate problem for host 172.16.4.9');
            }
        };

        try {
            (new ProxmoxNode($client))->fixGuestAgent('pve1', 100);
            $this->fail('Expected Exception');
        } catch (\Exception $e) {
            $this->assertStringNotContainsString('172.16.4.9', $e->getMessage());
            $this->assertSame('Failed to fix guest agent.', $e->getMessage());
            $this->assertInstanceOf(ConnectionException::class, $e->getPrevious());
        }
    }

    #[Test]
    public function authenticator_ticket_login_failure_does_not_leak_raw_exception_message(): void
    {
        Log::swap($this->fakeLogger());

        $access = new class(host: '127.0.0.1') extends ProxmoxAccess {
            public function __construct(string $host)
            {
                parent::__construct(host: $host, password: 'secret');
            }

            protected function sendRequest(string $method, string $url, array $params = [], array $headers = []): array
            {
                throw new ConnectionException('Proxmox cURL error: Could not resolve host: pve-master-01.internal.lan');
            }
        };

        try {
            $access->get('nodes');
            $this->fail('Expected AuthenticationException');
        } catch (\Cycoslave\Proxmox\Exceptions\AuthenticationException $e) {
            $this->assertStringNotContainsString('pve-master-01.internal.lan', $e->getMessage());
            $this->assertSame(
                'Proxmox ticket authentication failed: unable to reach the Proxmox API.',
                $e->getMessage(),
            );
        }
    }

    // -------------------------------------------------------------------------
    // SAST-007a: configureVMCloudInitNetwork() success-predicate inversion
    // -------------------------------------------------------------------------

    #[Test]
    public function configure_vm_cloud_init_network_reports_success_when_data_key_present(): void
    {
        $client = new class('127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret') extends ProxmoxAccess {
            public function put(string $path, array $data = []): array
            {
                // Proxmox returns 'data' => null for this endpoint on success.
                return ['data' => null];
            }
        };

        $result = (new ProxmoxNode($client))->configureVMCloudInitNetwork('pve1', 100, '10.0.0.5', '10.0.0.1', '24');

        $this->assertTrue($result['success'], 'A response carrying a data key (even null) must be treated as success');
        $this->assertSame('Network configured successfully', $result['message']);
    }

    #[Test]
    public function configure_vm_cloud_init_network_reports_failure_when_data_key_absent(): void
    {
        $client = new class('127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret') extends ProxmoxAccess {
            public function put(string $path, array $data = []): array
            {
                return ['no_data_here' => true];
            }
        };

        $result = (new ProxmoxNode($client))->configureVMCloudInitNetwork('pve1', 100, '10.0.0.5', '10.0.0.1', '24');

        $this->assertFalse($result['success'], 'A response with no data key must be treated as failure, not success');
        $this->assertSame('Network configure fail!', $result['message']);
    }

    // -------------------------------------------------------------------------
    // SAST-007b: TLS-disabled warning once-guard
    // -------------------------------------------------------------------------

    #[Test]
    public function tls_disabled_warning_is_logged_only_once_per_host(): void
    {
        $logger = $this->fakeLogger();
        Log::swap($logger);

        new ProxmoxAccess(host: '198.51.100.9', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret', verifyTls: false);
        new ProxmoxAccess(host: '198.51.100.9', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret', verifyTls: false);
        new ProxmoxAccess(host: '198.51.100.9', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret', verifyTls: false);

        $this->assertCount(
            1,
            $logger->warnings,
            'Constructing multiple ProxmoxAccess instances for the same host with verifyTls=false must log the warning only once',
        );
        $this->assertSame(
            \Cycoslave\Proxmox\Support\LogRedactor::endpointId('198.51.100.9', 8006),
            $logger->warnings[0]['context']['endpoint'],
        );
        $this->assertArrayNotHasKey('host', $logger->warnings[0]['context']);
        $this->assertStringNotContainsString('198.51.100.9', json_encode($logger->warnings[0]));
    }

    #[Test]
    public function tls_disabled_warning_is_logged_again_for_a_different_host(): void
    {
        $logger = $this->fakeLogger();
        Log::swap($logger);

        new ProxmoxAccess(host: '198.51.100.10', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret', verifyTls: false);
        new ProxmoxAccess(host: '198.51.100.11', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret', verifyTls: false);

        $this->assertCount(2, $logger->warnings);
    }

    #[Test]
    public function tls_disabled_warning_is_not_logged_when_tls_verification_is_enabled(): void
    {
        $logger = $this->fakeLogger();
        Log::swap($logger);

        new ProxmoxAccess(host: '198.51.100.12', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret', verifyTls: true);

        $this->assertCount(0, $logger->warnings);
    }

    // -------------------------------------------------------------------------
    // SAST-008: 401 triggers ticket invalidation + single retry
    // -------------------------------------------------------------------------

    #[Test]
    public function a_401_response_invalidates_the_ticket_and_retries_once_with_a_fresh_one(): void
    {
        $access = new class(host: '127.0.0.1') extends ProxmoxAccess {
            public array $captured = [];
            public int $apiCallCount = 0;

            public function __construct(string $host)
            {
                parent::__construct(host: $host, password: 'secret');
            }

            protected function sendRequest(string $method, string $url, array $params = [], array $headers = []): array
            {
                $this->captured[] = $url;

                if (str_ends_with($url, '/access/ticket')) {
                    return [
                        'data' => [
                            'ticket'              => 'PVE:root@pam:TICKET-' . count(array_filter($this->captured, fn($u) => str_ends_with($u, '/access/ticket'))),
                            'CSRFPreventionToken' => 'CSRF-TOKEN',
                        ],
                    ];
                }

                $this->apiCallCount++;

                if ($this->apiCallCount === 1) {
                    // Server-side ticket revocation despite a locally-unexpired ticket.
                    throw new ApiException('Proxmox API HTTP 401 for: ' . $url, 401);
                }

                return ['data' => ['nodes' => []]];
            }
        };

        $result = $access->get('nodes');

        $this->assertSame(['data' => ['nodes' => []]], $result);

        $ticketCalls = array_filter($access->captured, fn($u) => str_ends_with($u, '/access/ticket'));
        $this->assertCount(2, $ticketCalls, 'Expected an initial login plus one re-login after the 401');
        $this->assertSame(2, $access->apiCallCount, 'Expected the failed call plus exactly one retry');
    }

    #[Test]
    public function a_non_401_api_exception_is_not_retried(): void
    {
        $access = new class(host: '127.0.0.1') extends ProxmoxAccess {
            public int $ticketLogins = 0;
            public int $apiCalls = 0;

            public function __construct(string $host)
            {
                parent::__construct(host: $host, password: 'secret');
            }

            protected function sendRequest(string $method, string $url, array $params = [], array $headers = []): array
            {
                if (str_ends_with($url, '/access/ticket')) {
                    $this->ticketLogins++;

                    return [
                        'data' => ['ticket' => 'PVE:root@pam:T', 'CSRFPreventionToken' => 'CSRF'],
                    ];
                }

                $this->apiCalls++;
                throw new ApiException('Proxmox API HTTP 500 for: ' . $url, 500);
            }
        };

        $this->expectException(ApiException::class);

        try {
            $access->get('nodes');
        } finally {
            $this->assertSame(1, $access->ticketLogins, 'A 500 must not trigger a ticket re-login');
            $this->assertSame(1, $access->apiCalls, 'A non-401 failure must not be retried');
        }
    }

    #[Test]
    public function a_401_with_token_auth_is_not_retried_since_nothing_can_be_refreshed(): void
    {
        $access = new class(host: '127.0.0.1') extends ProxmoxAccess {
            public int $apiCalls = 0;

            public function __construct(string $host)
            {
                parent::__construct(host: $host, tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            protected function sendRequest(string $method, string $url, array $params = [], array $headers = []): array
            {
                $this->apiCalls++;
                throw new ApiException('Proxmox API HTTP 401 for: ' . $url, 401);
            }
        };

        $this->expectException(ApiException::class);

        try {
            $access->get('nodes');
        } finally {
            $this->assertSame(1, $access->apiCalls, 'Token auth has nothing to refresh, so a 401 must not be retried');
        }
    }
}
