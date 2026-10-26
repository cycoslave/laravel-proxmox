<?php

namespace Cycoslave\Proxmox;

use Cycoslave\Proxmox\Support\ResponseHelper;
use Cycoslave\Proxmox\Traits\ValidatesPathSegments;

/**
 * ProxmoxAccessApi
 *
 * Wraps the Proxmox /access/* REST endpoints:
 * domains, groups, roles, users, ACLs, tickets, and passwords.
 *
 * Renamed from ProxmoxAccess to eliminate the naming collision with the
 * ProxmoxAccess HTTP connection layer (see ProxmoxAccess.php).
 *
 * Instantiated via ProxmoxManager::accessApi().
 * Receives a ProxmoxAccess (HTTP layer) instance via constructor injection.
 */
class ProxmoxAccessApi
{
    use ValidatesPathSegments;

    public function __construct(
        protected ProxmoxAccess $client
    ) {}

    // -------------------------------------------------------------------------
    // Directory
    // -------------------------------------------------------------------------

    /**
     * Directory index. Accessible by all authenticated users.
     *
     * @throws \Exception
     */
    public function access(): array
    {
        $response = $this->client->get('access');

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access fail.');
        }

        return ResponseHelper::generate(true, 'Access List', $response['data']);
    }

    // -------------------------------------------------------------------------
    // Domains
    // -------------------------------------------------------------------------

    /** @throws \Exception */
    public function domains(): array
    {
        $response = $this->client->get('access/domains');

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access Domains fail.');
        }

        return ResponseHelper::generate(true, 'Access Domains List', $response['data']);
    }

    /** @throws \Exception */
    public function addDomain(array $data): array
    {
        $response = $this->client->post('access/domains', $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access add fail.');
        }

        return ResponseHelper::generate(true, 'Access add successfully', $response['data']);
    }

    /** @throws \Exception */
    public function domainsRealm(string $realm): array
    {
        $this->validateSegment($realm, 'realm');
        $response = $this->client->get("access/domains/{$realm}");

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access Domain fail.');
        }

        return ResponseHelper::generate(true, 'Access Domain details', $response['data']);
    }

    /** @throws \Exception */
    public function updateDomain(string $realm, array $data): array
    {
        $this->validateSegment($realm, 'realm');
        $response = $this->client->put("access/domains/{$realm}", $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access domain update fail.');
        }

        return ResponseHelper::generate(true, 'Access domain update successfully', $response['data']);
    }

    /** @throws \Exception */
    public function deleteDomain(string $realm): array
    {
        $this->validateSegment($realm, 'realm');
        $response = $this->client->delete("access/domains/{$realm}");

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access domain delete fail.');
        }

        return ResponseHelper::generate(true, 'Access domain deleted successfully', $response['data']);
    }

    // -------------------------------------------------------------------------
    // Groups
    // -------------------------------------------------------------------------

    /** @throws \Exception */
    public function groups(): array
    {
        $response = $this->client->get('access/groups');

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access groups fail.');
        }

        return ResponseHelper::generate(true, 'Access groups', $response['data']);
    }

    /** @throws \Exception */
    public function createGroup(array $data): array
    {
        $response = $this->client->post('access/groups', $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access group create fail.');
        }

        return ResponseHelper::generate(true, 'Access group created successfully', $response['data']);
    }

    /** @throws \Exception */
    public function groupId(string $groupid): array
    {
        $this->validateSegment($groupid, 'groupid');
        $response = $this->client->get("access/groups/{$groupid}");

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access group fail.');
        }

        return ResponseHelper::generate(true, 'Access group details', $response['data']);
    }

    /** @throws \Exception */
    public function updateGroup(string $groupid, array $data): array
    {
        $this->validateSegment($groupid, 'groupid');
        $response = $this->client->put("access/groups/{$groupid}", $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access group update fail.');
        }

        return ResponseHelper::generate(true, 'Access group updated successfully', $response['data']);
    }

    /** @throws \Exception */
    public function deleteGroup(string $groupid): array
    {
        $this->validateSegment($groupid, 'groupid');
        $response = $this->client->delete("access/groups/{$groupid}");

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access group delete fail.');
        }

        return ResponseHelper::generate(true, 'Access group deleted successfully', $response['data']);
    }

    // -------------------------------------------------------------------------
    // Roles
    // -------------------------------------------------------------------------

    /** @throws \Exception */
    public function roles(): array
    {
        $response = $this->client->get('access/roles');

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access roles fail.');
        }

        return ResponseHelper::generate(true, 'Access roles', $response['data']);
    }

    /** @throws \Exception */
    public function createRole(array $data): array
    {
        $response = $this->client->post('access/roles', $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access role create fail.');
        }

        return ResponseHelper::generate(true, 'Access role created successfully', $response['data']);
    }

    /** @throws \Exception */
    public function roleId(string $roleid): array
    {
        $this->validateSegment($roleid, 'roleid');
        $response = $this->client->get("access/roles/{$roleid}");

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access role fail.');
        }

        return ResponseHelper::generate(true, 'Access role details', $response['data']);
    }

    /** @throws \Exception */
    public function updateRole(string $roleid, array $data): array
    {
        $this->validateSegment($roleid, 'roleid');
        $response = $this->client->put("access/roles/{$roleid}", $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access role update fail.');
        }

        return ResponseHelper::generate(true, 'Access role updated successfully', $response['data']);
    }

    /** @throws \Exception */
    public function deleteRole(string $roleid): array
    {
        $this->validateSegment($roleid, 'roleid');
        $response = $this->client->delete("access/roles/{$roleid}");

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access role delete fail.');
        }

        return ResponseHelper::generate(true, 'Access role deleted successfully', $response['data']);
    }

    // -------------------------------------------------------------------------
    // Users
    // -------------------------------------------------------------------------

    /** @throws \Exception */
    public function users(): array
    {
        $response = $this->client->get('access/users');

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access users fail.');
        }

        return ResponseHelper::generate(true, 'Access users list', $response['data']);
    }

    /** @throws \Exception */
    public function createUser(array $data): array
    {
        $response = $this->client->post('access/users', $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access user create fail.');
        }

        return ResponseHelper::generate(true, 'Access user created successfully', $response['data']);
    }

    /** @throws \Exception */
    public function getUser(string $userid): array
    {
        $this->validateIdentifierSegment($userid, 'userid');
        $response = $this->client->get("access/users/{$userid}");

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access user fail.');
        }

        return ResponseHelper::generate(true, 'Access user details', $response['data']);
    }

    /** @throws \Exception */
    public function updateUser(string $userid, array $data): array
    {
        $this->validateIdentifierSegment($userid, 'userid');
        $response = $this->client->put("access/users/{$userid}", $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access user update fail.');
        }

        return ResponseHelper::generate(true, 'Access user updated successfully', $response['data']);
    }

    /** @throws \Exception */
    public function deleteUser(string $userid): array
    {
        $this->validateIdentifierSegment($userid, 'userid');
        $response = $this->client->delete("access/users/{$userid}");

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access user delete fail.');
        }

        return ResponseHelper::generate(true, 'Access user deleted successfully', $response['data']);
    }

    /** @throws \Exception */
    public function changeUserPassword(array $data): array
    {
        $response = $this->client->put('access/password', $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access user password update fail.');
        }

        return ResponseHelper::generate(true, 'Access user password updated successfully', $response['data']);
    }

    // -------------------------------------------------------------------------
    // ACL
    // -------------------------------------------------------------------------

    /** @throws \Exception */
    public function acl(): array
    {
        $response = $this->client->get('access/acl');

        if (! isset($response['data'])) {
            return ResponseHelper::generate(false, 'Access user acl fail.');
        }

        return ResponseHelper::generate(true, 'Access user acl', $response['data']);
    }

    /** @throws \Exception */
    public function updateAcl(array $data = []): array
    {
        $response = $this->client->put('access/acl', $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access user acl update fail.');
        }

        return ResponseHelper::generate(true, 'Access user acl updated successfully', $response['data']);
    }

    // -------------------------------------------------------------------------
    // Ticket
    // -------------------------------------------------------------------------

    /** @throws \Exception */
    public function createTicket(array $data): array
    {
        $response = $this->client->post('access/ticket', $data);

        if (! ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Access user authentication fail.');
        }

        return ResponseHelper::generate(true, 'Access user authentication successfully', $response['data']);
    }
}