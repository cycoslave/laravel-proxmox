<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\Exceptions\ConnectionException;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\ProxmoxStorage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionParameter;
use SensitiveParameter;

/**
 * Regression tests for carbon F-01 (CWE-532): #[\SensitiveParameter] only
 * masks the frame it is declared on, so every inner transport frame that
 * carries a secret (URL, params/body, auth headers) must be annotated too.
 */
class CarbonF01Test extends TestCase
{
    private const SECRET_TOKEN = 'DEMO_F01_TOKEN_SECRET';
    private const SECRET_BODY  = 'DEMO_F01_CIFS_SHARE_PASSWORD';

    /** @return array<string, array{class-string, string, string}> */
    public static function sensitiveParams(): array
    {
        $trait = ProxmoxAccess::class; // HttpClient / Authenticator traits are mixed in here

        return [
            'sendRequest.url'            => [$trait, 'sendRequest', 'url'],
            'sendRequest.params'         => [$trait, 'sendRequest', 'params'],
            'sendRequest.headers'        => [$trait, 'sendRequest', 'headers'],
            'buildCurlOptions.url'       => [$trait, 'buildCurlOptions', 'url'],
            'buildCurlOptions.params'    => [$trait, 'buildCurlOptions', 'params'],
            'buildCurlOptions.headers'   => [$trait, 'buildCurlOptions', 'headers'],
            'ProxmoxAccess::get'         => [ProxmoxAccess::class, 'get', 'params'],
            'ProxmoxAccess::post'        => [ProxmoxAccess::class, 'post', 'data'],
            'ProxmoxAccess::put'         => [ProxmoxAccess::class, 'put', 'data'],
            'ProxmoxAccess::delete'      => [ProxmoxAccess::class, 'delete', 'params'],
            'ProxmoxAccess::request'     => [ProxmoxAccess::class, 'request', 'payload'],
            'ProxmoxStorage::createStorage' => [ProxmoxStorage::class, 'createStorage', 'params'],
            'ProxmoxNode::createStorage'    => [ProxmoxNode::class, 'createStorage', 'params'],
            'ProxmoxNode::setVMConfig'      => [ProxmoxNode::class, 'setVMConfig', 'params'],
            'ProxmoxNode::writeNewKeyFile'  => [ProxmoxNode::class, 'writeNewKeyFile', 'contents'],
        ];
    }

    #[Test]
    #[DataProvider('sensitiveParams')]
    public function secret_carrying_parameter_is_marked_sensitive(string $class, string $method, string $param): void
    {
        $parameter = null;
        foreach ((new ReflectionMethod($class, $method))->getParameters() as $p) {
            if ($p->getName() === $param) {
                $parameter = $p;
            }
        }

        $this->assertInstanceOf(ReflectionParameter::class, $parameter, "{$method}() has no \${$param}");
        $this->assertNotEmpty(
            $parameter->getAttributes(SensitiveParameter::class),
            "{$class}::{$method}(\${$param}) must carry #[\\SensitiveParameter]"
        );
    }

    #[Test]
    public function failed_request_trace_contains_no_cleartext_secret_in_any_frame(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');

        try {
            // 127.0.0.1:1 refuses the connection -> ConnectionException from sendRequest().
            $access = new ProxmoxAccess(
                host: '127.0.0.1',
                port: 1,
                tokenId: 'root@pam!demo',
                tokenSecret: self::SECRET_TOKEN,
                timeout: 1,
            );

            $caught = null;
            try {
                (new ProxmoxStorage($access))->createStorage([
                    'storage'  => 'demo',
                    'type'     => 'cifs',
                    'password' => self::SECRET_BODY,
                ]);
            } catch (ConnectionException $e) {
                $caught = $e;
            }
        } finally {
            if ($previous !== false) {
                ini_set('zend.exception_ignore_args', $previous);
            }
        }

        $this->assertInstanceOf(ConnectionException::class, $caught);

        $frames = $caught->getTrace();
        $this->assertNotEmpty($frames);

        $dump = print_r($frames, true);
        $this->assertStringNotContainsString(self::SECRET_TOKEN, $dump);
        $this->assertStringNotContainsString(self::SECRET_BODY, $dump);
        $this->assertStringNotContainsString('/api2/json/storage', $dump, 'target URL must not appear in frames');
        $this->assertStringNotContainsString('127.0.0.1', $dump, 'hypervisor host must not appear in frames');
    }
}
