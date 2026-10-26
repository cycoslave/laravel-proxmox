<?php

namespace Cycoslave\Proxmox\Tests\Unit\Traits;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Illuminate\Support\Facades\Log;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\Exceptions\ApiException;
use Cycoslave\Proxmox\Exceptions\ConnectionException;

/**
 * Tests for Traits\HttpClient.
 *
 * Option-building tests (timeout floors/caps, TLS mapping, GET/POST URL
 * handling) call the production buildCurlOptions() method directly via
 * exposeOptions(), instead of testing a duplicated copy of the logic
 * (SAST-009 fix — the old suite re-implemented sendRequest() in the
 * anonymous test double, so it verified the test's own code, not the
 * trait's).
 *
 * Network-boundary tests (cURL error / HTTP status / JSON decode
 * mapping) still override sendRequest(), since exercising curl_exec()
 * itself would require a real or mocked network call; there is no way
 * to unit-test that boundary against the production method without a
 * curl-handle abstraction, which is out of scope here.
 *
 * PLG-R2-01 harness fix: this is a plain PHPUnit\TestCase (no booted
 * Laravel app), but ProxmoxAccess::__construct() calls the Log facade
 * when verifyTls is false (tls_verify_is_disabled_when_verify_tls_is_false
 * below). With no facade application bound, that previously errored with
 * "A facade root has not been set." Swap in a minimal fake logger for the
 * duration of this test class so the facade resolves without needing a
 * full container, and clear it afterwards so it can't leak into other
 * test files that run in the same process.
 */
class HttpClientTest extends TestCase
{
    protected function tearDown(): void
    {
        Log::clearResolvedInstance();
        parent::tearDown();
    }

    private function swapFakeLogger(): void
    {
        Log::swap(new class {
            public function warning($message, array $context = []): void
            {
                // no-op — this test only needs the facade to resolve.
            }
        });
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Anonymous ProxmoxAccess subclass that exposes the protected
     * buildCurlOptions() production method for direct testing.
     */
    private function exposeOptions(bool $verifyTls = true, int $timeout = 10): ProxmoxAccess
    {
        return new class(
            host: '127.0.0.1',
            verifyTls: $verifyTls,
            timeout: $timeout,
        ) extends ProxmoxAccess {
            public function __construct(string $host, bool $verifyTls, int $timeout)
            {
                parent::__construct(
                    host: $host,
                    tokenId: 'root@pam!tok',
                    tokenSecret: 'uuid-secret',
                    verifyTls: $verifyTls,
                    timeout: $timeout,
                );
            }

            public function publicBuildCurlOptions(
                string $method,
                string $url,
                array  $params  = [],
                array  $headers = [],
            ): array {
                return $this->buildCurlOptions($method, $url, $params, $headers);
            }
        };
    }

    private function makeCaptureAccess(
        string $responseBody,
        int $httpCode,
        string $curlError = '',
        bool $verifyTls = true,
        int $timeout = 10,
    ): ProxmoxAccess {
        return new class(
            host: '127.0.0.1',
            verifyTls: $verifyTls,
            timeout: $timeout,
            responseBody: $responseBody,
            httpCode: $httpCode,
            curlError: $curlError,
        ) extends ProxmoxAccess {
            public function __construct(
                string $host,
                bool $verifyTls,
                int $timeout,
                private readonly string $responseBody,
                private readonly int $httpCode,
                private readonly string $curlError,
            ) {
                parent::__construct(
                    host: $host,
                    tokenId: 'root@pam!tok',
                    tokenSecret: 'uuid-secret',
                    verifyTls: $verifyTls,
                    timeout: $timeout,
                );
            }

            // Simulates the curl_exec/curl_getinfo/curl_error boundary that
            // sendRequest() sits on top of; option-building itself is the
            // real buildCurlOptions() from the HttpClient trait.
            protected function sendRequest(
                string $method,
                string $url,
                array  $params  = [],
                array  $headers = [],
            ): array {
                $this->buildCurlOptions($method, $url, $params, $headers);

                if ($this->curlError !== '') {
                    throw new ConnectionException("Proxmox cURL error: {$this->curlError}");
                }

                if ($this->httpCode >= 400) {
                    $safeUrl = strtok($url, '?');
                    throw new ApiException(
                        "Proxmox API HTTP {$this->httpCode} for: {$safeUrl}",
                        $this->httpCode,
                    );
                }

                $decoded = json_decode($this->responseBody, true);

                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new ApiException(
                        'Proxmox API returned invalid JSON: ' . json_last_error_msg(),
                    );
                }

                return $decoded ?? [];
            }
        };
    }

    private function okBody(array $data = []): string
    {
        return json_encode(['data' => $data]);
    }

    // -------------------------------------------------------------------------
    // Timeout floor / cap (production buildCurlOptions())
    // -------------------------------------------------------------------------

    #[Test]
    public function connect_timeout_is_at_least_1_when_timeout_is_zero(): void
    {
        $access = $this->exposeOptions(true, 0);
        $opts   = $access->publicBuildCurlOptions('GET', 'https://127.0.0.1:8006/api2/json/nodes');
        $this->assertSame(1, $opts[CURLOPT_CONNECTTIMEOUT]);
    }

    #[Test]
    public function total_timeout_is_at_least_1_when_timeout_is_zero(): void
    {
        $access = $this->exposeOptions(true, 0);
        $opts   = $access->publicBuildCurlOptions('GET', 'https://127.0.0.1:8006/api2/json/nodes');
        $this->assertSame(1, $opts[CURLOPT_TIMEOUT]);
    }

    #[Test]
    public function connect_timeout_is_capped_at_5_when_total_timeout_is_large(): void
    {
        $access = $this->exposeOptions(true, 30);
        $opts   = $access->publicBuildCurlOptions('GET', 'https://127.0.0.1:8006/api2/json/nodes');
        $this->assertSame(5, $opts[CURLOPT_CONNECTTIMEOUT]);
    }

    #[Test]
    public function total_timeout_reflects_configured_value(): void
    {
        $access = $this->exposeOptions(true, 15);
        $opts   = $access->publicBuildCurlOptions('GET', 'https://127.0.0.1:8006/api2/json/nodes');
        $this->assertSame(15, $opts[CURLOPT_TIMEOUT]);
    }

    // -------------------------------------------------------------------------
    // TLS option mapping (production buildCurlOptions())
    // -------------------------------------------------------------------------

    #[Test]
    public function tls_verify_peer_is_true_when_verify_tls_is_enabled(): void
    {
        $access = $this->exposeOptions(true);
        $opts   = $access->publicBuildCurlOptions('GET', 'https://127.0.0.1:8006/api2/json/nodes');
        $this->assertTrue($opts[CURLOPT_SSL_VERIFYPEER]);
        $this->assertSame(2, $opts[CURLOPT_SSL_VERIFYHOST]);
    }

    #[Test]
    public function tls_verify_is_disabled_when_verify_tls_is_false(): void
    {
        $this->swapFakeLogger();

        $access = $this->exposeOptions(false);
        $opts   = $access->publicBuildCurlOptions('GET', 'https://127.0.0.1:8006/api2/json/nodes');
        $this->assertFalse($opts[CURLOPT_SSL_VERIFYPEER]);
        $this->assertSame(0, $opts[CURLOPT_SSL_VERIFYHOST]);
    }

    // -------------------------------------------------------------------------
    // GET / POST URL + param handling (production buildCurlOptions())
    // -------------------------------------------------------------------------

    #[Test]
    public function get_appends_params_as_query_string(): void
    {
        $access = $this->exposeOptions();
        $opts   = $access->publicBuildCurlOptions(
            'GET',
            'https://127.0.0.1:8006/api2/json/nodes',
            ['foo' => 'bar', 'baz' => '1'],
        );
        $this->assertStringContainsString('?foo=bar&baz=1', $opts[CURLOPT_URL]);
    }

    #[Test]
    public function get_with_no_params_has_no_query_string(): void
    {
        $access = $this->exposeOptions();
        $opts   = $access->publicBuildCurlOptions('GET', 'https://127.0.0.1:8006/api2/json/nodes');
        $this->assertStringNotContainsString('?', $opts[CURLOPT_URL]);
    }

    #[Test]
    public function post_sends_params_as_body_not_query_string(): void
    {
        $access = $this->exposeOptions();
        $opts   = $access->publicBuildCurlOptions(
            'POST',
            'https://127.0.0.1:8006/api2/json/nodes/pve1/qemu',
            ['vmid' => 100, 'name' => 'test'],
        );
        $this->assertStringNotContainsString('?', $opts[CURLOPT_URL]);
        $this->assertStringContainsString('vmid=100', $opts[CURLOPT_POSTFIELDS]);
        $this->assertStringContainsString('name=test', $opts[CURLOPT_POSTFIELDS]);
    }

    // -------------------------------------------------------------------------
    // Error → exception mapping
    // -------------------------------------------------------------------------

    #[Test]
    public function curl_error_throws_connection_exception(): void
    {
        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessageMatches('/cURL error/i');

        $access = $this->makeCaptureAccess('', 0, 'Could not resolve host');
        $access->get('nodes');
    }

    #[Test]
    public function http_400_throws_api_exception_with_correct_status_code(): void
    {
        $this->expectException(ApiException::class);

        $access = $this->makeCaptureAccess('{"errors":{"vmid":"400 bad"}}', 400);

        try {
            $access->get('nodes');
        } catch (ApiException $e) {
            $this->assertSame(400, $e->getStatusCode());
            throw $e;
        }
    }

    #[Test]
    public function http_403_throws_api_exception(): void
    {
        $this->expectException(ApiException::class);
        $access = $this->makeCaptureAccess('{"errors":{"permission":"403 forbidden"}}', 403);
        $access->get('nodes');
    }

    #[Test]
    public function http_500_throws_api_exception(): void
    {
        $this->expectException(ApiException::class);
        $access = $this->makeCaptureAccess('internal error', 500);
        $access->get('nodes');
    }

    #[Test]
    public function invalid_json_response_throws_api_exception(): void
    {
        $this->expectException(ApiException::class);
        $this->expectExceptionMessageMatches('/invalid JSON/i');

        $access = $this->makeCaptureAccess('NOT_VALID_JSON{{{', 200);
        $access->get('nodes');
    }

    #[Test]
    public function http_4xx_error_message_does_not_contain_query_string_params(): void
    {
        $access = $this->makeCaptureAccess('', 404);
        $secret = 'supersecretvalue';

        try {
            $access->get('nodes', ['secret' => $secret]);
            $this->fail('Expected ApiException');
        } catch (ApiException $e) {
            $this->assertStringNotContainsString($secret, $e->getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Successful response
    // -------------------------------------------------------------------------

    #[Test]
    public function successful_response_returns_decoded_array(): void
    {
        $payload = ['id' => 'pve1', 'type' => 'node'];
        $access  = $this->makeCaptureAccess(json_encode(['data' => $payload]), 200);
        $result  = $access->get('nodes');
        $this->assertSame(['data' => $payload], $result);
    }
}
