<?php

namespace Cycoslave\Proxmox\Tests\Unit\Traits;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Cycoslave\Proxmox\ProxmoxAccess;
use Cycoslave\Proxmox\ProxmoxAccessApi;
use Cycoslave\Proxmox\ProxmoxNode;

/**
 * Regression tests for SAST-003 (Medium, CWE-20, secondary CWE-625):
 *
 * 1. validateSegment()'s original `/^[\w\-\.]+$/` used `^`/`$` anchors.
 *    PCRE's `$` matches immediately before a trailing "\n" even without
 *    the `m` modifier, so a caller-supplied "pve1\n" passed validation
 *    it should have failed. The request was then built with the
 *    embedded newline and rejected downstream by libcurl (malformed
 *    URL, CURLE_URL_MALFORMAT / errno 3) — a mis-classified failure
 *    (opaque cURL error) rather than a clean, intention-revealing
 *    InvalidArgumentException at the validation boundary.
 *
 * 2. The same character class also rejected legitimate Proxmox user/
 *    token identifiers containing "@" or "!" (e.g. "root@pam",
 *    "root@pam!automation"), breaking every /access/users/* endpoint
 *    for real-world input.
 *
 * Uses PHPUnit 12 #[Test] attributes (see SAST-001/SAST-009 precedent).
 */
class ValidatesPathSegmentsAnchorTest extends TestCase
{
    private ProxmoxNode $node;
    private ProxmoxAccessApi $accessApi;

    protected function setUp(): void
    {
        parent::setUp();
        $client          = new ProxmoxAccess(host: '127.0.0.1', tokenId: 'root@pam!tok', tokenSecret: 'uuid-secret');
        $this->node       = new ProxmoxNode($client);
        $this->accessApi  = new ProxmoxAccessApi($client);
    }

    // -------------------------------------------------------------------
    // validateSegment(): \A...\z anchoring (trailing-newline rejection)
    // -------------------------------------------------------------------

    #[Test]
    public function set_ceph_flags_rejects_node_with_trailing_newline(): void
    {
        $this->expectException(InvalidArgumentException::class);
        // Previously passed the ^...$ regex (PCRE $ matches before a
        // final \n) and was only caught later by libcurl.
        $this->node->setCephFlags("pve1\n", 'nobackfill', []);
    }

    #[Test]
    public function set_ceph_flags_rejects_flag_with_trailing_newline(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->node->setCephFlags('pve1', "nobackfill\n", []);
    }

    #[Test]
    public function set_ceph_flags_rejects_embedded_newline_followed_by_more_text(): void
    {
        $this->expectException(InvalidArgumentException::class);
        // \z (unlike $) also rejects "pve1\nmalicious", which a naive
        // \A...$ fix would not catch if PCRE's $ ever matched mid-string.
        $this->node->setCephFlags("pve1\nmalicious", 'nobackfill', []);
    }

    #[Test]
    public function set_ceph_flags_still_accepts_well_formed_node(): void
    {
        // No exception expected: a valid node name must keep working.
        $this->expectNotToPerformAssertions();

        try {
            $this->node->setCephFlags('pve1', 'nobackfill', []);
        } catch (InvalidArgumentException $e) {
            $this->fail('Well-formed segment must not raise InvalidArgumentException: '.$e->getMessage());
        } catch (\Throwable $e) {
            // Expected: it will fail later trying to actually reach the
            // network (no live Proxmox host in this test), which proves
            // validation passed and execution moved past it.
        }
    }

    // -------------------------------------------------------------------
    // validateIdentifierSegment(): @ / ! / : allowed for user & token IDs
    // -------------------------------------------------------------------

    #[Test]
    public function get_user_accepts_realm_qualified_user_id(): void
    {
        $this->expectNotToPerformAssertions();

        try {
            $this->accessApi->getUser('root@pam');
        } catch (InvalidArgumentException $e) {
            $this->fail('Legitimate Proxmox user id "root@pam" must not be rejected: '.$e->getMessage());
        } catch (\Throwable $e) {
            // Expected: fails later attempting network I/O, which is
            // fine — it proves validateIdentifierSegment() let it through.
        }
    }

    #[Test]
    public function get_user_accepts_api_token_id(): void
    {
        $this->expectNotToPerformAssertions();

        try {
            $this->accessApi->getUser('root@pam!automation');
        } catch (InvalidArgumentException $e) {
            $this->fail('Legitimate Proxmox token id "root@pam!automation" must not be rejected: '.$e->getMessage());
        } catch (\Throwable $e) {
            // Network-layer failure is expected/fine here.
        }
    }

    #[Test]
    public function get_user_still_rejects_traversal(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->accessApi->getUser('root@pam/../../cluster/firewall/rules/1');
    }

    #[Test]
    public function get_user_still_rejects_trailing_newline(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->accessApi->getUser("root@pam!automation\n");
    }

    #[Test]
    public function get_user_still_rejects_empty_string(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->accessApi->getUser('');
    }

    #[Test]
    public function update_user_accepts_token_id_with_colon_separator(): void
    {
        $this->expectNotToPerformAssertions();

        try {
            // Some Proxmox tooling emits ":" as the token separator.
            $this->accessApi->updateUser('root@pam:automation', ['comment' => 'x']);
        } catch (InvalidArgumentException $e) {
            $this->fail('Legitimate token id with ":" separator must not be rejected: '.$e->getMessage());
        } catch (\Throwable $e) {
            // Network-layer failure is expected/fine here.
        }
    }

    #[Test]
    public function delete_user_still_rejects_slash(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->accessApi->deleteUser('root@pam/etc');
    }
}
