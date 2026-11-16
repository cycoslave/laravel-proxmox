<?php

namespace Cycoslave\Proxmox\Tests\Unit;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * LPM-002: a bare `vendor/bin/phpunit` must execute the suite on machines without a
 * coverage driver. Coverage reports (which need Xdebug/PCOV and, with failOnWarning,
 * abort the whole run) belong only in the opt-in phpunit-coverage.xml.dist.
 */
class PhpunitDefaultConfigTest extends TestCase
{
    private function root(): string
    {
        return dirname(__DIR__, 2);
    }

    private function load(string $file): \SimpleXMLElement
    {
        $xml = simplexml_load_file($this->root().'/'.$file);
        $this->assertNotFalse($xml, "$file must be valid XML");

        return $xml;
    }

    #[Test]
    public function default_phpunit_config_does_not_request_coverage_reports(): void
    {
        $xml = $this->load('phpunit.xml');

        $this->assertCount(0, $xml->xpath('//coverage/report'), 'phpunit.xml must not configure coverage reports');
        $this->assertCount(0, $xml->xpath('//report'));
    }

    #[Test]
    public function default_phpunit_config_still_fails_on_empty_suite_and_warnings(): void
    {
        $xml = $this->load('phpunit.xml');

        $this->assertSame('true', (string) $xml['failOnEmptyTestSuite'], 'a run that executes no tests must fail');
        $this->assertSame('true', (string) $xml['failOnWarning']);
        $this->assertSame('true', (string) $xml['failOnRisky']);
    }

    #[Test]
    public function coverage_reports_live_in_the_opt_in_config(): void
    {
        $xml = $this->load('phpunit-coverage.xml.dist');

        $this->assertNotEmpty($xml->xpath('//coverage/report'));
    }

    #[Test]
    public function composer_test_script_skips_coverage_and_coverage_script_is_separate(): void
    {
        $composer = json_decode(file_get_contents($this->root().'/composer.json'), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame('phpunit --no-coverage', $composer['scripts']['test']);
        $this->assertStringContainsString('phpunit-coverage.xml.dist', $composer['scripts']['coverage']);
        $this->assertStringNotContainsString('--no-coverage', $composer['scripts']['coverage']);
    }
}
