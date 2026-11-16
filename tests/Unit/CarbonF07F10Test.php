<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for carbon F-07 / F-10.
 *
 *  F-07 (CWE-400): HttpClient encoded every body with http_build_query(), so a
 *        CURLFile in storageUpload()'s payload was serialised as
 *        "filename[name]=/local/path&filename[mimetype]=..." (local path leaked,
 *        no file ever uploaded).
 *  F-10 (CWE-459): createUbuntuVMWithSSH() left the generated private key on
 *        disk when VM creation failed, and the temp-dir fallback root was the
 *        fixed, predictable /tmp/proxmox-ssh-keys.
 */
class CarbonF07F10Test extends TestCase
{
    private const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHkYn0lUe1hAbCdEfGhIjKlMnOpQrStUvWxYz012345 user@host';

    /** @var string[] */
    private array $cleanup = [];

    protected function setUp(): void
    {
        parent::setUp();
        Log::swap(new class {
            public function warning($message, array $context = []) {}
            public function error($message, array $context = []) {}
        });
    }

    protected function tearDown(): void
    {
        foreach ($this->cleanup as $path) {
            if (is_file($path) || is_link($path)) {
                @unlink($path);
            } elseif (is_dir($path)) {
                foreach (glob($path . '/*') ?: [] as $f) {
                    @unlink($f);
                }
                @rmdir($path);
            }
        }
        $this->cleanup = [];
        Log::clearResolvedInstance();
        parent::tearDown();
    }

    // ------------------------------------------------------------------ helpers

    private function tmpFile(string $contents = 'ISO-BYTES'): string
    {
        $path = tempnam(sys_get_temp_dir(), 'f07_');
        file_put_contents($path, $contents);
        $this->cleanup[] = $path;
        return $path;
    }

    /** ProxmoxAccess exposing buildCurlOptions() and recording what request() hands to sendRequest(). */
    private function access(): object
    {
        return new class('127.0.0.1') extends ProxmoxAccess {
            /** @var array<int, array{0:string,1:string,2:array}> */
            public array $sent = [];

            public function __construct(string $host)
            {
                parent::__construct(host: $host, tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            protected function sendRequest(string $method, string $url, array $params = [], array $headers = []): array
            {
                $this->sent[] = [$method, $url, $params];
                return ['data' => 'UPID:pve1:0001'];
            }

            public function options(string $method, array $params): array
            {
                return $this->buildCurlOptions($method, 'https://127.0.0.1:8006/api2/json/x', $params, []);
            }
        };
    }

    /** @param array<string, array<string, mixed>> $responses  e.g. ['POST nodes/pve1/qemu' => [...]] */
    private function node(array &$calls, array $responses = [], ?\Closure $postHook = null): ProxmoxNode
    {
        $access = new class($calls, $responses, $postHook) extends ProxmoxAccess {
            public function __construct(private array &$calls, private array $responses, private ?\Closure $postHook)
            {
                parent::__construct(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
            }

            private function record(string $method, string $path, array $data): array
            {
                $this->calls[] = ['method' => $method, 'path' => $path, 'data' => $data];
                if ($method === 'POST' && $this->postHook !== null) {
                    return ($this->postHook)($path, $data);
                }
                return $this->responses["$method $path"] ?? ['data' => null];
            }

            public function get(string $path, array $params = []): array { return $this->record('GET', $path, $params); }
            public function post(string $path, array $data = []): array { return $this->record('POST', $path, $data); }
            public function put(string $path, array $data = []): array { return $this->record('PUT', $path, $data); }
        };

        return new ProxmoxNode($access);
    }

    // ------------------------------------------------------------------ F-07

    #[Test]
    public function curlfile_payload_is_sent_as_array_postfields_not_a_query_string(): void
    {
        $path   = $this->tmpFile();
        $file   = new \CURLFile($path, 'application/octet-stream', 'debian.iso');
        $opts   = $this->access()->options('POST', ['content' => 'iso', 'filename' => $file]);
        $fields = $opts[CURLOPT_POSTFIELDS];

        $this->assertIsArray($fields, 'multipart needs array POSTFIELDS');
        $this->assertSame('iso', $fields['content']);
        $this->assertSame($file, $fields['filename']);
    }

    #[Test]
    public function local_path_is_never_serialised_into_a_string_body(): void
    {
        $path = $this->tmpFile();
        $opts = $this->access()->options('POST', ['filename' => new \CURLFile($path)]);

        foreach ((array) $opts[CURLOPT_POSTFIELDS] as $value) {
            if (is_string($value)) {
                $this->assertStringNotContainsString($path, $value);
            }
        }
        $this->assertIsNotString($opts[CURLOPT_POSTFIELDS]);
    }

    #[Test]
    public function curlstringfile_is_also_sent_as_multipart(): void
    {
        $file = new \CURLStringFile('bytes', 'a.iso', 'application/octet-stream');
        $opts = $this->access()->options('POST', ['content' => 'iso', 'filename' => $file]);

        $this->assertIsArray($opts[CURLOPT_POSTFIELDS]);
        $this->assertSame($file, $opts[CURLOPT_POSTFIELDS]['filename']);
    }

    #[Test]
    public function put_with_a_file_is_also_multipart(): void
    {
        $opts = $this->access()->options('PUT', ['filename' => new \CURLFile($this->tmpFile())]);

        $this->assertIsArray($opts[CURLOPT_POSTFIELDS]);
        $this->assertSame('PUT', $opts[CURLOPT_CUSTOMREQUEST]);
    }

    #[Test]
    public function scalar_fields_next_to_a_file_are_normalised_like_http_build_query(): void
    {
        $opts = $this->access()->options('POST', [
            'content'  => 'iso',
            'int'      => 5,
            'yes'      => true,
            'no'       => false,
            'skipped'  => null,
            'nested'   => ['a' => 'x', 'b' => ['c' => 2]],
            'filename' => new \CURLFile($this->tmpFile()),
        ]);
        $f = $opts[CURLOPT_POSTFIELDS];

        $this->assertSame('5', $f['int']);
        $this->assertSame('1', $f['yes']);
        $this->assertSame('0', $f['no']);
        $this->assertArrayNotHasKey('skipped', $f);
        $this->assertSame('x', $f['nested[a]']);
        $this->assertSame('2', $f['nested[b][c]']);
        $this->assertInstanceOf(\CURLFile::class, $f['filename']);
    }

    #[Test]
    public function a_file_nested_in_an_array_is_still_detected(): void
    {
        $file = new \CURLFile($this->tmpFile());
        $opts = $this->access()->options('POST', ['wrap' => ['filename' => $file]]);

        $this->assertIsArray($opts[CURLOPT_POSTFIELDS]);
        $this->assertSame($file, $opts[CURLOPT_POSTFIELDS]['wrap[filename]']);
    }

    #[Test]
    public function payloads_without_files_keep_the_urlencoded_string_body(): void
    {
        $params = ['a' => 'b c', 'n' => 1, 'flag' => true, 'list' => ['x', 'y']];
        $opts   = $this->access()->options('POST', $params);

        $this->assertSame(http_build_query($params), $opts[CURLOPT_POSTFIELDS]);
    }

    #[Test]
    public function a_file_in_a_get_query_is_rejected_instead_of_leaking_its_path(): void
    {
        $path = $this->tmpFile();

        try {
            $this->access()->options('GET', ['filename' => new \CURLFile($path)]);
            $this->fail('A CURLFile must not be put into a query string.');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringNotContainsString($path, $e->getMessage());
        }
    }

    #[Test]
    public function unsupported_objects_in_a_multipart_payload_are_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->access()->options('POST', ['x' => new \stdClass(), 'filename' => new \CURLFile($this->tmpFile())]);
    }

    #[Test]
    public function storage_upload_hands_the_curlfile_to_the_transport_untouched(): void
    {
        $access = $this->access();
        $file   = new \CURLFile($this->tmpFile(), 'application/octet-stream', 'x.iso');
        $node   = new ProxmoxNode($access);

        $result = $node->storageUpload('pve1', 'local', ['content' => 'iso', 'filename' => $file]);

        $this->assertTrue($result['success']);
        [$method, $url, $params] = $access->sent[0];
        $this->assertSame('POST', $method);
        $this->assertStringEndsWith('/nodes/pve1/storage/local/upload', $url);
        $this->assertSame($file, $params['filename']);

        $opts = $access->options($method, $params);
        $this->assertIsArray($opts[CURLOPT_POSTFIELDS]);
        $this->assertSame($file, $opts[CURLOPT_POSTFIELDS]['filename']);
    }

    // ------------------------------------------------------------------ F-10

    private const CREATE = ['vmid' => 500, 'name' => 'f10vm', 'ostype' => 'l26', 'memory' => 512, 'cores' => 1];

    /** Collect every generated key path by hooking generateSSHKey() on the node under test. */
    private function spyNode(array &$calls, array &$generated, ?\Closure $postHook): ProxmoxNode
    {
        $access = $this->node($calls, [], $postHook);
        $client = (fn () => $this->client)->call($access);

        return new class($client, $generated) extends ProxmoxNode {
            public function __construct($client, private array &$generated)
            {
                parent::__construct($client);
            }

            public function generateSSHKey(?string $name = null, ?string $passphrase = null): array
            {
                $r = parent::generateSSHKey($name, $passphrase);
                $this->generated[] = $r['data'];
                return $r;
            }
        };
    }

    #[Test]
    public function failed_vm_creation_by_exception_removes_the_generated_key_files(): void
    {
        $calls = []; $generated = [];
        $node  = $this->spyNode($calls, $generated, fn () => throw new \RuntimeException('boom'));

        try {
            $node->createUbuntuVMWithSSH('pve1', self::CREATE);
            $this->fail('expected exception');
        } catch (\RuntimeException $e) {
            $this->assertSame('boom', $e->getMessage());
        }

        $this->assertCount(1, $generated);
        $this->cleanup[] = $generated[0]['private_key_path'];
        $this->cleanup[] = $generated[0]['public_key_path'];
        $this->cleanup[] = dirname($generated[0]['private_key_path']);
        $this->assertFileDoesNotExist($generated[0]['private_key_path']);
        $this->assertFileDoesNotExist($generated[0]['public_key_path']);
        $this->assertDirectoryDoesNotExist(dirname($generated[0]['private_key_path']), 'per-call dir is removed too');
    }

    #[Test]
    public function failed_vm_creation_by_failure_envelope_removes_keys_and_drops_generated_key(): void
    {
        $calls = []; $generated = [];
        $node  = $this->spyNode($calls, $generated, fn () => []); // no 'data' => createVM() returns success=false

        $result = $node->createUbuntuVMWithSSH('pve1', self::CREATE);

        $this->cleanup[] = $generated[0]['private_key_path'];
        $this->cleanup[] = $generated[0]['public_key_path'];
        $this->cleanup[] = dirname($generated[0]['private_key_path']);
        $this->assertFalse($result['success']);
        $this->assertArrayNotHasKey('generated_key', $result, 'files are gone, so no dangling paths are advertised');
        $this->assertFileDoesNotExist($generated[0]['private_key_path']);
        $this->assertFileDoesNotExist($generated[0]['public_key_path']);
    }

    #[Test]
    public function successful_creation_keeps_the_key_pair_and_returns_generated_key_as_before(): void
    {
        $calls = []; $generated = [];
        $node  = $this->spyNode($calls, $generated, fn () => ['data' => 'UPID:x']);

        $result = $node->createUbuntuVMWithSSH('pve1', self::CREATE);

        $gk = $result['generated_key'];
        $this->cleanup[] = $gk['private_key_path'];
        $this->cleanup[] = $gk['public_key_path'];
        $this->cleanup[] = dirname($gk['private_key_path']);

        $this->assertTrue($result['success']);
        $this->assertSame(['private_key_path', 'public_key_path', 'passphrase_generated', 'passphrase'], array_keys($gk));
        $this->assertTrue($gk['passphrase_generated']);
        $this->assertNotEmpty($gk['passphrase']);
        $this->assertFileExists($gk['private_key_path']);
        $this->assertFileExists($gk['public_key_path']);
        $this->assertSame(0600, fileperms($gk['private_key_path']) & 0777);
        $this->assertStringStartsWith('ssh-rsa ', $result['ssh_key']);
    }

    #[Test]
    public function key_directory_is_private_random_and_not_the_fixed_shared_path(): void
    {
        $calls = []; $generated = [];
        $node  = $this->spyNode($calls, $generated, fn () => ['data' => 'UPID:x']);

        $a = $node->createUbuntuVMWithSSH('pve1', self::CREATE)['generated_key'];
        $b = $node->createUbuntuVMWithSSH('pve1', self::CREATE)['generated_key'];
        foreach ([$a, $b] as $gk) {
            $this->cleanup[] = $gk['private_key_path'];
            $this->cleanup[] = $gk['public_key_path'];
            $this->cleanup[] = dirname($gk['private_key_path']);
        }

        $dirA = dirname($a['private_key_path']);
        $dirB = dirname($b['private_key_path']);
        $fixed = rtrim(sys_get_temp_dir(), '/') . '/proxmox-ssh-keys';

        $this->assertNotSame($fixed, $dirA);
        $this->assertNotSame($dirA, $dirB, 'each call gets its own directory');
        $this->assertMatchesRegularExpression('#/proxmox-ssh-keys-[0-9a-f]{32}$#', $dirA);
        $this->assertSame(0700, fileperms($dirA) & 0777);
        $this->assertFalse(is_link($dirA));
    }

    #[Test]
    public function standalone_generate_ssh_key_also_avoids_the_fixed_shared_path(): void
    {
        $calls = [];
        $node  = $this->node($calls);
        $data  = $node->generateSSHKey('f10_standalone')['data'];
        $this->cleanup[] = $data['private_key_path'];
        $this->cleanup[] = $data['public_key_path'];
        $this->cleanup[] = dirname($data['private_key_path']);

        $dir = dirname($data['private_key_path']);
        $this->assertNotSame(rtrim(sys_get_temp_dir(), '/') . '/proxmox-ssh-keys', $dir);
        $this->assertSame(0700, fileperms($dir) & 0777);

        // Same instance + same name still fails closed (LPX-005).
        $this->expectExceptionMessage('already exists');
        $node->generateSSHKey('f10_standalone');
    }

    #[Test]
    public function a_caller_supplied_key_never_creates_key_files_even_when_creation_fails(): void
    {
        $before = glob(rtrim(sys_get_temp_dir(), '/') . '/proxmox-ssh-keys-*') ?: [];
        $calls  = [];
        $node   = $this->node($calls, [], fn () => throw new \RuntimeException('boom'));

        try {
            $node->createUbuntuVMWithSSH('pve1', self::CREATE, self::KEY);
            $this->fail('expected exception');
        } catch (\RuntimeException) {
        }

        $this->assertSame($before, glob(rtrim(sys_get_temp_dir(), '/') . '/proxmox-ssh-keys-*') ?: []);
    }

    #[Test]
    public function an_invalid_supplied_key_fails_before_any_request_or_file(): void
    {
        $calls = [];
        $node  = $this->node($calls);

        $this->expectException(\InvalidArgumentException::class);
        try {
            $node->createUbuntuVMWithSSH('pve1', self::CREATE, "bad\nkey");
        } finally {
            $this->assertSame([], $calls);
        }
    }
}
