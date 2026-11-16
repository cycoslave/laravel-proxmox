<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Closure;
use Cycoslave\Proxmox\Exceptions\ConnectionException;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxAccessApi;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\ProxmoxStorage;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionParameter;
use SensitiveParameter;
use Throwable;

/**
 * Regression tests for mythos F-01 (CWE-532): secret-bearing arguments of the
 * public resource methods must not appear in getTrace() frames of a failed
 * request. #[\SensitiveParameter] masks only the frame it is declared on, so
 * every public method that forwards a secret payload / vncticket needs it.
 */
class MythosF01Test extends TestCase
{
    private const SECRET = 'DEMO_MYTHOS_F01_SECRET_VALUE';

    /** @return array<string, array{class-string, string, string}> */
    public static function sensitiveParams(): array
    {
        $n = ProxmoxNode::class;

        return [
            'Node::createLxc.data'             => [$n, 'createLxc', 'data'],
            'Node::setLxcConfig.data'          => [$n, 'setLxcConfig', 'data'],
            'Node::createQemu.data'            => [$n, 'createQemu', 'data'],
            'Node::createQemuConfig.data'      => [$n, 'createQemuConfig', 'data'],
            'Node::setQemuConfig.data'         => [$n, 'setQemuConfig', 'data'],
            'Node::createVM.params'            => [$n, 'createVM', 'params'],
            'Node::createUbuntuVMWithSSH.params' => [$n, 'createUbuntuVMWithSSH', 'params'],
            'Node::updateVmConfig.params'      => [$n, 'updateVmConfig', 'params'],
            'Node::setSubscription.data'       => [$n, 'setSubscription', 'data'],
            'Node::lxcVncwebsocket.vncticket'  => [$n, 'lxcVncwebsocket', 'vncticket'],
            'Node::qemuVncwebsocket.vncticket' => [$n, 'qemuVncwebsocket', 'vncticket'],
            'Node::vNCWebSocket.vncticket'     => [$n, 'vNCWebSocket', 'vncticket'],
            'AccessApi::addDomain.data'        => [ProxmoxAccessApi::class, 'addDomain', 'data'],
            'AccessApi::updateDomain.data'     => [ProxmoxAccessApi::class, 'updateDomain', 'data'],
            'Storage::updateStorage.params'    => [ProxmoxStorage::class, 'updateStorage', 'params'],
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

    /** @return array<string, array{Closure(ProxmoxNode, ProxmoxAccessApi, ProxmoxStorage): mixed}> */
    public static function failingCalls(): array
    {

        return [
            'createLxc'         => [fn ($n) => $n->createLxc('pve', ['password' => self::SECRET])],
            'setLxcConfig'      => [fn ($n) => $n->setLxcConfig('pve', 100, ['password' => self::SECRET])],
            'createQemu'        => [fn ($n) => $n->createQemu('pve', ['cipassword' => self::SECRET])],
            'createQemuConfig'  => [fn ($n) => $n->createQemuConfig('pve', 100, ['cipassword' => self::SECRET])],
            'setQemuConfig'     => [fn ($n) => $n->setQemuConfig('pve', 100, ['cipassword' => self::SECRET])],
            'createVM'          => [fn ($n) => $n->createVM('pve', ['cipassword' => self::SECRET])],
            'updateVmConfig'    => [fn ($n) => $n->updateVmConfig('pve', 100, ['cipassword' => self::SECRET])],
            'setSubscription'   => [fn ($n) => $n->setSubscription('pve', ['key' => self::SECRET])],
            'lxcVncwebsocket'   => [fn ($n) => $n->lxcVncwebsocket('pve', 100, 5900, self::SECRET)],
            'qemuVncwebsocket'  => [fn ($n) => $n->qemuVncwebsocket('pve', 100, 5900, self::SECRET)],
            'vNCWebSocket'      => [fn ($n) => $n->vNCWebSocket('pve', 5900, self::SECRET)],
            'addDomain'         => [fn ($n, $a) => $a->addDomain(['realm' => 'demo', 'password' => self::SECRET])],
            'updateDomain'      => [fn ($n, $a) => $a->updateDomain('demo', ['password' => self::SECRET])],
            'updateStorage'     => [fn ($n, $a, $st) => $st->updateStorage('demo', ['password' => self::SECRET])],
        ];
    }

    #[Test]
    #[DataProvider('failingCalls')]
    public function failed_request_trace_contains_no_cleartext_secret(Closure $call): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');

        $caught = null;
        try {
            // 127.0.0.1:1 refuses the connection -> ConnectionException from the transport.
            $access = new ProxmoxAccess(
                host: '127.0.0.1',
                port: 1,
                tokenId: 'root@pam!demo',
                tokenSecret: 'DEMO_MYTHOS_F01_TOKEN',
                timeout: 1,
            );

            try {
                $call(new ProxmoxNode($access), new ProxmoxAccessApi($access), new ProxmoxStorage($access));
            } catch (Throwable $e) {
                $caught = $e;
            }
        } finally {
            if ($previous !== false) {
                ini_set('zend.exception_ignore_args', $previous);
            }
        }

        $this->assertInstanceOf(
            ConnectionException::class,
            $caught,
            'call must reach the transport and fail there: ' . ($caught ? get_class($caught) . ': ' . $caught->getMessage() : 'no exception')
        );

        $frames = $caught->getTrace();
        $this->assertNotEmpty($frames);

        // Only library frames: the test harness' own frames are not under test.
        $leaking = [];
        foreach ($frames as $frame) {
            $class = $frame['class'] ?? '';
            if (!str_starts_with($class, 'Cycoslave\\Proxmox\\') || str_contains($class, '\\Tests\\')) {
                continue;
            }
            if (str_contains(print_r($frame['args'] ?? [], true), self::SECRET)) {
                $leaking[] = $class . '::' . ($frame['function'] ?? '?');
            }
        }

        $this->assertSame([], $leaking, 'secret visible in getTrace() args of: ' . implode(', ', $leaking));
    }
}
