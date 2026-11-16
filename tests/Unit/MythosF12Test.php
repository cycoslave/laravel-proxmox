<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxNode;
use Cycoslave\Proxmox\Traits\ValidatesPathSegments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for mythos F-12: the rejected raw value was echoed into the
 * InvalidArgumentException message of validateSegment() and
 * validateIdentifierSegment(). The rejection itself must be unchanged.
 */
class MythosF12Test extends TestCase
{
    /** @return array<string, array{string}> */
    public static function badValues(): array
    {
        return [
            'traversal'  => ['../../etc/passwd'],
            'markup'     => ['<script>alert(1)</script>'],
            'newline'    => ["pve1\nINJECTED log line"],
            'secretish'  => ['tok3n-SECRET-VALUE/x'],
            'long'       => [str_repeat('A/', 500)],
        ];
    }

    private function harness(): object
    {
        return new class {
            use ValidatesPathSegments;

            public function seg(string $v): void { $this->validateSegment($v, 'node'); }
            public function ident(string $v): void { $this->validateIdentifierSegment($v, 'user'); }
        };
    }

    #[Test]
    #[DataProvider('badValues')]
    public function validate_segment_message_omits_raw_value(string $bad): void
    {
        try {
            $this->harness()->seg($bad);
            $this->fail('expected rejection');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('[node]', $e->getMessage());
            $this->assertStringNotContainsString($bad, $e->getMessage());
            $this->assertStringNotContainsString('SECRET', $e->getMessage());
            $this->assertStringNotContainsString('INJECTED', $e->getMessage());
            $this->assertStringNotContainsString('<script>', $e->getMessage());
        }
    }

    #[Test]
    #[DataProvider('badValues')]
    public function validate_identifier_segment_message_omits_raw_value(string $bad): void
    {
        // '@', '!' and ':' are legal here; use a value with chars that are not.
        $bad .= ' /#?';
        try {
            $this->harness()->ident($bad);
            $this->fail('expected rejection');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('[user]', $e->getMessage());
            $this->assertStringNotContainsString($bad, $e->getMessage());
            $this->assertStringNotContainsString('SECRET', $e->getMessage());
            $this->assertStringNotContainsString('INJECTED', $e->getMessage());
            $this->assertStringNotContainsString('<script>', $e->getMessage());
        }
    }

    #[Test]
    public function public_api_still_rejects_and_valid_values_still_pass(): void
    {
        $node = new ProxmoxNode($this->createStub(ProxmoxAccess::class));

        $this->expectException(\InvalidArgumentException::class);
        $node->deleteVM('../evil', 100);
    }

    #[Test]
    public function valid_segments_are_accepted(): void
    {
        $h = $this->harness();
        $h->seg('pve-1.local_x');
        $h->ident('root@pam!automation');
        $this->addToAssertionCount(1);
    }
}
