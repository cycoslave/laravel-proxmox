<?php

namespace Cycoslave\Proxmox;

use Exception;
use Illuminate\Support\Facades\Log;
use Cycoslave\Proxmox\Support\ResponseHelper;
use Cycoslave\Proxmox\Support\LogRedactor;
use Cycoslave\Proxmox\Traits\ValidatesPathSegments;

class ProxmoxNode
{
    use ValidatesPathSegments;

    public function __construct(protected ProxmoxAccess $client) {}

    /**
     * SAST-006 (CWE-209): $e->getMessage() on a network/API exception can
     * carry curl diagnostics (resolved IPs, hostnames, local file paths).
     * Returns a generic, caller-safe message for the response envelope /
     * thrown exception.
     *
     * LPX-006 (CWE-532): the raw message is no longer logged either — only
     * a categorised, redacted context (see LogRedactor::exceptionContext()).
     * The original exception stays reachable via `previous` for callers
     * that rethrow.
     */
    private function safeErrorMessage(\Throwable $e, string $context): string
    {
        Log::warning("Proxmox: {$context}", LogRedactor::exceptionContext($e));

        return "{$context}.";
    }

    /**
     * API version details, including some parts of the global datacenter config.
     *
     * @return array
     * @throws Exception
     */
    public function version(): array
    {
        $response = $this->client->get('version');

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'version fetch fail!');
        }
        return ResponseHelper::generate(true, 'version!', $response['data']);
    }

    /**
     * Get list of nodes
     *
     * @return array
     * @throws Exception
     */
    public function getNodes(): array
    {
        $response = $this->client->get('nodes');

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'nodes fetch fail!');
        }
        return ResponseHelper::generate(true, 'nodes list!', $response['data']);
    }

    /**
     * Directory index for apt (Advanced Package Tool).
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function apt(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/apt");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'node apt fail!');
        }

        return ResponseHelper::generate(true, 'node apt', $response['data']);
    }

    /**
     * Directory index for apt (Advanced Package Tool).
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function updateApt(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/apt/update", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'apt update fail!');
        }

        return ResponseHelper::generate(true, 'Apt updated', $response['data']);
    }

    /**
     * Get package changelogs.
     * @param string $node The cluster node name.
     * @param string|null $name Package name.
     * @throws Exception
     */
    public function aptChangelog(string $node, ?string $name = null): array
    {
        $optional['name'] = ($name !== null && $name !== '') ? $name : null;
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/apt/changelog", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Apt changelog fail!');
        }

        return ResponseHelper::generate(true, 'Apt changelog', $response['data']);
    }

    /**
     * List available updates.
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function aptUpdate(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/apt/update");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List available updates fail!');
        }

        return ResponseHelper::generate(true, 'List available updates', $response['data']);
    }

    /**
     * This is used to resynchronize the package index files from their sources (apt-get update).
     * POST /api2/json/nodes/{node}/apt/update
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function createAptUpdate(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/apt/update", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create update fail!');
        }

        return ResponseHelper::generate(true, 'Create updates', $response['data']);
    }

    /**
     * Directory index.
     * GET /api2/json/nodes/{node}/ceph
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function ceph(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'ceph fail!');
        }

        return ResponseHelper::generate(true, 'ceph list', $response['data']);
    }

    /**
     * get all set ceph flags
     * GET /api2/json/nodes/{node}/ceph/flags
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function cephFlags(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/flags");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'get all set ceph flags fail!');
        }

        return ResponseHelper::generate(true, 'get all set ceph flags', $response['data']);
    }

    /**
     * Set a ceph flag
     * POST /api2/json/nodes/{node}/ceph/flags/{flag}
     * @param string $node The cluster node name.
     * @param enum $flag The ceph flag to set/unset
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function setCephFlags(string $node, $flag, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment((string) $flag, 'flag');
        $response = $this->client->post("nodes/$node/ceph/flags/$flag", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Set a ceph flag fail!');
        }

        return ResponseHelper::generate(true, 'Set a ceph flag', $response['data']);
    }

    /**
     * Unset a ceph flag
     * DELETE /api2/json/nodes/{node}/ceph/flags/{flag}
     * @param string $node The cluster node name.
     * @param enum $flag The ceph flag to set/unset
     * @throws Exception
     */
    public function unsetCephFlags(string $node, $flag): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment((string) $flag, 'flag');
        $response = $this->client->delete("nodes/$node/ceph/flags/$flag");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Unset ceph flag fail!');
        }

        return ResponseHelper::generate(true, 'Unset ceph flag', $response['data']);
    }

    /**
     * Create Ceph Manager
     * POST /api2/json/nodes/{node}/ceph/mgr
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function createCephMgr(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/ceph/mgr", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create Ceph Manager fail!');
        }

        return ResponseHelper::generate(true, 'Created Ceph Manager', $response['data']);
    }

    /**
     * Destroy Ceph Manager.
     * DELETE /api2/json/nodes/{node}/ceph/mgr/{id}
     * @param string $node The cluster node name.
     * @param string $id The ID of the manager
     * @throws Exception
     */
    public function destroyCephMgr(string $node, string $id): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($id, 'id');
        $response = $this->client->delete("nodes/$node/ceph/mgr/$id");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create Ceph Manager fail!');
        }

        return ResponseHelper::generate(true, 'Created Ceph Manager', $response['data']);
    }

    /**
     * Get Ceph monitor list.
     * GET /api2/json/nodes/{node}/ceph/mon
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function cephMon(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/mon");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get Ceph monitor list fail!');
        }

        return ResponseHelper::generate(true, 'Get Ceph monitor list', $response['data']);
    }

    /**
     * Create Ceph Monitor and Manager
     * POST /api2/json/nodes/{node}/ceph/mon
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function createCephMon(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/ceph/mon", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create Ceph Monitor and Manager fail!');
        }

        return ResponseHelper::generate(true, 'Create Ceph Monitor and Manager', $response['data']);
    }

    /**
     * Destroy Ceph Monitor and Manager.
     * DELETE /api2/json/nodes/{node}/ceph/mon/{monid}
     * @param string $node The cluster node name.
     * @param string $monid Monitor ID
     * @throws Exception
     */
    public function destroyCephMon(string $node, string $monid): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($monid, 'monid');
        // LPX-002 (CWE-706): was routed to ceph/mgr/{id} — a monitor delete
        // must never hit the manager endpoint.
        $response = $this->client->delete("nodes/$node/ceph/mon/$monid");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Destroy Ceph Monitor and Manager fail!');
        }

        return ResponseHelper::generate(true, 'Destroyed Ceph Monitor and Manager', $response['data']);
    }

    /**
     * Get Ceph osd list/tree.
     * GET /api2/json/nodes/{node}/ceph/osd
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function cephOsd(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/osd");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get Ceph osd list fail!');
        }

        return ResponseHelper::generate(true, 'Get Ceph osd list', $response['data']);
    }

    /**
     * Create OSD
     * POST /api2/json/nodes/{node}/ceph/osd
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function createCephOsd(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/ceph/osd", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create OSD fail!');
        }

        return ResponseHelper::generate(true, 'Created OSD', $response['data']);
    }

    /**
     * Destroy OSD
     * DELETE /api2/json/nodes/{node}/ceph/osd/{osdid}
     * @param string $node The cluster node name.
     * @param string $osdid OSD ID
     * @throws Exception
     */
    public function destroyCephOsd(string $node, string $osdid): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($osdid, 'osdid');
        $response = $this->client->delete("nodes/$node/ceph/osd/$osdid");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Destroy OSD fail!');
        }

        return ResponseHelper::generate(true, 'Destroyed OSD', $response['data']);
    }

    /**
     * ceph osd in
     * POST /api2/json/nodes/{node}/ceph/osd/{osdid}/in
     * @param string $node The cluster node name.
     * @param string $osdid OSD ID
     * @param array $data
     * @throws Exception
     */
    public function cephOsdIn(string $node, string $osdid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($osdid, 'osdid');
        $response = $this->client->post("nodes/$node/ceph/osd/$osdid/in", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'ceph OSD in fail!');
        }

        return ResponseHelper::generate(true, 'ceph OSD in', $response['data']);
    }

    /**
     * ceph osd out
     * POST /api2/json/nodes/{node}/ceph/osd/{osdid}/out
     * @param string $node The cluster node name.
     * @param string $osdid OSD ID
     * @param array $data
     * @throws Exception
     */
    public function cephOsdOut(string $node, string $osdid, array $data = array()): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($osdid, 'osdid');
        $response = $this->client->post("nodes/$node/ceph/osd/$osdid/out", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'ceph OSD out fail!');
        }

        return ResponseHelper::generate(true, 'ceph OSD out', $response['data']);
    }

    /**
     * List all pools.
     * GET /api2/json/nodes/{node}/ceph/pools
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function getCephPools(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/pools");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List all pools!');
        }

        return ResponseHelper::generate(true, 'List all pools', $response['data']);
    }

    /**
     * Create POOL
     * POST /api2/json/nodes/{node}/ceph/pools
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function createCephPool(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/ceph/pools", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create POOL fail!');
        }

        return ResponseHelper::generate(true, 'Created POOL', $response['data']);
    }

    /**
     * Destroy POOL
     * DELETE /api2/json/nodes/{node}/ceph/pools
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function destroyCephPool(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("nodes/$node/ceph/pools");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Destroy POOL fail!');
        }

        return ResponseHelper::generate(true, 'Destroyed POOL', $response['data']);
    }

    /**
     * Get Ceph configuration.
     * GET /api2/json/nodes/{node}/ceph/config
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function cephConfig(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/config");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get Ceph configuration fail!');
        }

        return ResponseHelper::generate(true, 'Get Ceph configuration', $response['data']);
    }

    /**
     * Get OSD crush map
     * GET /api2/json/nodes/{node}/ceph/crush
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function cephCrush(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/crush");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get OSD crush map fail!');
        }

        return ResponseHelper::generate(true, 'Get OSD crush map', $response['data']);
    }

    /**
     * List local disks.
     * GET /api2/json/nodes/{node}/ceph/disks
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function cephDisks(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/disks");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List local disks fail!');
        }

        return ResponseHelper::generate(true, 'List local disks', $response['data']);
    }

    /**
     * Create initial ceph default configuration and setup symlinks.
     * POST /api2/json/nodes/{node}/ceph/init
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function createCephInit(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/ceph/init", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create initial ceph fail!');
        }

        return ResponseHelper::generate(true, 'Create initial ceph', $response['data']);
    }

    /**
     * Read ceph log
     * GET /api2/json/nodes/{node}/ceph/log
     * @param string $node The cluster node name.
     * @param integer|null $limit
     * @param integer|null $start
     * @throws Exception
     */
    public function cephLog(string $node, ?int $limit = null, ?int $start = null): array
    {
        $optional['limit'] = !empty($limit) ? $limit : 50;
        $optional['start'] = !empty($start) ? $start : 0;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/log", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read ceph log fail!');
        }

        return ResponseHelper::generate(true, 'Read ceph log', $response['data']);
    }

    /**
     * List ceph rules.
     * GET /api2/json/nodes/{node}/ceph/rules
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function cephRules(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/rules");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List ceph rules fail!');
        }

        return ResponseHelper::generate(true, 'List ceph rules', $response['data']);
    }

    /**
     * Start ceph services.
     * POST /api2/json/nodes/{node}/ceph/start
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function cephStart(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/ceph/start", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Start ceph services fail!');
        }

        return ResponseHelper::generate(true, 'Start ceph services', $response['data']);
    }

    /**
     * Stop ceph services.
     * POST /api2/json/nodes/{node}/ceph/stop
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function cephStop(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/ceph/stop", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Stop ceph services fail!');
        }

        return ResponseHelper::generate(true, 'Stop ceph services', $response['data']);
    }

    /**
     * Get ceph status.
     * GET /api2/json/nodes/{node}/ceph/status
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function cephStatus(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/ceph/status");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get ceph status fail!');
        }

        return ResponseHelper::generate(true, 'Get ceph status', $response['data']);
    }

    /**
     * Node index.
     * GET /api2/json/nodes/{node}/disks
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function getDisks(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/disks");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Disk list fail!');
        }

        return ResponseHelper::generate(true, 'Disk list', $response['data']);
    }

    /**
     * Initialize Disk with GPT
     * POST /api2/json/nodes/{node}/disks
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function disk(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/disks", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Initialize Disk with GPT fail!');
        }

        return ResponseHelper::generate(true, 'Initialize Disk with GPT', $response['data']);
    }

    /**
     * List local disks.
     * GET /api2/json/nodes/{node}/disks/list
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function disksList(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/disks/list");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List local disks fail!');
        }

        return ResponseHelper::generate(true, 'List local disks', $response['data']);
    }

    /**
     * Get SMART Health of a disk.
     * GET /api2/json/nodes/{node}/disks/smart
     * @param string $node The cluster node name.
     * @param string|null $disk Block device name
     * @throws Exception
     */
    public function disksSmart(string $node, ?string $disk = null): array
    {
        $optional['disk'] = !empty($disk) ? $disk : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/disks/smart", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get SMART Health of a disk fail!');
        }

        return ResponseHelper::generate(true, 'Get SMART Health of a disk', $response['data']);
    }

    /**
     * Directory index.
     * GET /api2/json/nodes/{node}/firewall
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function firewall(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/firewall");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Firewall list fail!');
        }

        return ResponseHelper::generate(true, 'Firewall list', $response['data']);
    }

    /**
     * List rules.
     * GET /api2/json/nodes/{node}/firewall/rules
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function firewallRules(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/firewall/rules");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Firewall list rules fail!');
        }

        return ResponseHelper::generate(true, 'Firewall list rules', $response['data']);
    }

    /**
     * Create new rule
     * POST /api2/json/nodes/{node}/firewall/rules
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function createFirewallRule(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/firewall/rules", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create new rule fail!');
        }

        return ResponseHelper::generate(true, 'Created new rule', $response['data']);
    }

    /**
     * Get single rule data.
     * GET /api2/json/nodes/{node}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $pos Update rule at position <pos>.
     * @throws Exception
     */
    public function firewallRulesPos(string $node, int $pos): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/firewall/rules/$pos");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get single rule data fail!');
        }

        return ResponseHelper::generate(true, 'Get single rule data', $response['data']);
    }

    /**
     * Modify rule data.
     * PUT /api2/json/nodes/{node}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $pos Update rule at position <pos>.
     * @param array $data
     * @throws Exception
     */
    public function setFirewallRulePos(string $node, int $pos, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/firewall/rules/$pos", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Modify rule data fail!');
        }

        return ResponseHelper::generate(true, 'Modify rule data', $response['data']);
    }

    /**
     * Delete rule.
     * DELETE /api2/json/nodes/{node}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $pos Update rule at position <pos>.
     * @throws Exception
     */
    public function deleteFirewallRulePos(string $node, int $pos): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("nodes/$node/firewall/rules/$pos");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Delete rule fail!');
        }

        return ResponseHelper::generate(true, 'Delete rule', $response['data']);
    }

    /**
     * Read firewall log
     * GET /api2/json/nodes/{node}/firewall/rules/log
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function firewallRulesLog(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/firewall/rules/log");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read firewall log fail!');
        }

        return ResponseHelper::generate(true, 'Read firewall log', $response['data']);
    }

    /**
     * Get host firewall options.
     * GET /api2/json/nodes/{node}/firewall/options
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function firewallRulesOptions(string $node): array
    {
        $this->validateSegment($node, 'node');
        // LPX-001: the Proxmox host-firewall options resource is
        // nodes/{node}/firewall/options; "firewall/rules/options" would be
        // parsed as rule position "options" and rejected.
        $response = $this->client->get("nodes/$node/firewall/options");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get host firewall options fail!');
        }

        return ResponseHelper::generate(true, 'Get host firewall options', $response['data']);
    }

    /**
     * Set host (node-scoped) firewall options.
     * PUT /api2/json/nodes/{node}/firewall/options
     * @param string $node The cluster node name.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function setFirewallRuleOptions(string $node, array $data): array
    {
        // LPX-001 (CWE-706): previously sent to cluster/firewall/options,
        // changing the firewall policy of the WHOLE cluster instead of the
        // one node the caller named. Always node-scoped now.
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/firewall/options", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Set firewall options fail!');
        }

        return ResponseHelper::generate(true, 'Set firewall options', $response['data']);
    }

    /**
     * Create new rule
     * from the Proxmox node's public interface to a VM/Container IP:Port.
     * @throws Exception
     */
    public function createQemuFirewallRule(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/firewall/rules", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(true, 'Created Firewall', $response['data']);
        }
        return ResponseHelper::generate(false, 'Create Firewall fail!');
    }

    /**
     * List of rule.
     * from the Proxmox node's public interface to a VM/Container IP:Port.
     * @throws Exception
     */
    public function listQemuFirewallRule(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/rules");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List Firewall fail!');
        }

        return ResponseHelper::generate(true, 'List Firewall', $response['data']);
    }

    /**
     * Removing of rule.
     * from the Proxmox node's public interface to a VM/Container IP:Port.
     * @throws Exception
     */
    public function removeQemuFirewallRule(string $node, int $vmid, int $pos): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("nodes/$node/qemu/$vmid/firewall/rules/$pos");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(true, 'Removed Firewall', $response['data']);
        }
        return ResponseHelper::generate(false, 'Remove Firewall fail!');
    }

    /**
     * LXC container index (per node).
     * GET /api2/json/nodes/{node}/lxc
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function lxc(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'LXC container fail!');
        }

        return ResponseHelper::generate(true, 'LXC containers', $response['data']);
    }

    /**
     * Create or restore a container.
     * POST /api2/json/nodes/{node}/lxc
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function createLxc(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create or restore a container fail!');
        }

        return ResponseHelper::generate(true, 'Created or restored a container', $response['data']);
    }

    /**
     * Directory index
     * GET /api2/json/nodes/{node}/lxc/{vmid}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcVmid(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Lxc list fail!');
        }

        return ResponseHelper::generate(true, 'Lxc list', $response['data']);
    }

    /**
     * Destroy the container (also delete all uses files).
     * DELETE /api2/json/nodes/{node}/lxc/{vmid}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function deleteLxc(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("nodes/$node/lxc/$vmid");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Destroy the container fail!');
        }

        return ResponseHelper::generate(true, 'Destroy the container', $response['data']);
    }

    /**
     * Directory index.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/aliases
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcFirewall(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Destroy the container fail!');
        }

        return ResponseHelper::generate(true, 'Destroy the container', $response['data']);
    }

    /**
     * List aliases
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/aliases
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcFirewallAliases(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall/aliases");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List aliases fail!');
        }

        return ResponseHelper::generate(true, 'List aliases', $response['data']);
    }

    /**
     * Create IP or Network Alias
     * POST /api2/json/nodes/{node}/lxc/{vmid}/firewall/aliases
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @return array
     * @throws Exception
     */
    public function createLxcFirewallAliase(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/firewall/aliases", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create IP or Network Alias fail!');
        }

        return ResponseHelper::generate(true, 'Created IP or Network Alias', $response['data']);
    }

    /**
     * Read alias.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/aliases/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name Alias name.
     * @throws Exception
     */
    public function lxcFirewallAliasesName(string $node, int $vmid, string $name): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall/aliases/$name");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read alias fail!');
        }

        return ResponseHelper::generate(true, 'Read Alias', $response['data']);
    }

    /**
     * Update IP or Network alias
     * PUT /api2/json/nodes/{node}/lxc/{vmid}/firewall/aliases/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name Alias name.
     * @param array $data
     * @throws Exception
     */
    public function updateLxcFirewallAliaseName(string $node, int $vmid, string $name, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->put("nodes/$node/lxc/$vmid/firewall/aliases/$name", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Update IP or Network alias fail!');
        }

        return ResponseHelper::generate(true, 'Updated IP or Network alias', $response['data']);
    }

    /**
     * Remove IP or Network alias.
     * DELETE /api2/json/nodes/{node}/lxc/{vmid}/firewall/aliases/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name Alias name.
     * @throws Exception
     */
    public function deleteLxcFirewallAliaseName(string $node, int $vmid, string $name): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->delete("nodes/$node/lxc/$vmid/firewall/aliases/$name");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Remove IP or Network alias fail!');
        }

        return ResponseHelper::generate(true, 'Removed IP or Network alias', $response['data']);
    }

    /**
     * List IPSets
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/ipset
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcFirewallIpset(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall/ipset");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List IPSets fail!');
        }

        return ResponseHelper::generate(true, 'List IPSets', $response['data']);
    }

    /**
     * Create new IPSet
     * POST /api2/json/nodes/{node}/lxc/{vmid}/firewall/ipset
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createLxcFirewallIpset(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/firewall/ipset", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create new IPSet fail!');
        }

        return ResponseHelper::generate(true, 'Create new IPSet', $response['data']);
    }

    /**
     * List IPSet content
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @throws Exception
     */
    public function lxcFirewallIpsetName(string $node, int $vmid, string $name): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall/ipset/$name");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List IPSet content fail!');
        }

        return ResponseHelper::generate(true, 'List IPSet content', $response['data']);
    }

    /**
     * Add IP or Network to IPSet.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @param array $data
     * @throws Exception
     */
    public function addLxcFirewallIpsetName(string $node, int $vmid, string $name, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->post("nodes/$node/lxc/$vmid/firewall/ipset/$name", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Add IP or Network to IPSet fail!');
        }

        return ResponseHelper::generate(true, 'Add IP or Network to IPSet', $response['data']);
    }

    /**
     * Delete IPSet
     * DELETE /api2/json/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @throws Exception
     */
    public function deleteLxcFirewallIpsetName(string $node, int $vmid, string $name): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->delete("/nodes/$node/lxc/$vmid/firewall/ipset/$name");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Delete IPSet fail!');
        }

        return ResponseHelper::generate(true, 'Deleted IPSet', $response['data']);
    }

    /**
     * Read IP or Network settings from IPSet.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @param string $cidr Network/IP specification in CIDR format.
     * @throws Exception
     */
    public function lxcFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $this->validateSegment($cidr, 'cidr');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall/ipset/$name/$cidr");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read IP or Network settings from IPSet fail!');
        }

        return ResponseHelper::generate(true, 'Read IP or Network settings from IPSet', $response['data']);
    }

    /**
     * Update IP or Network settings
     * PUT /api2/json/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @param string $cidr Network/IP specification in CIDR format.
     * @param array $data
     * @throws Exception
     */
    public function updateLxcFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $this->validateSegment($cidr, 'cidr');
        $response = $this->client->put("nodes/$node/lxc/$vmid/firewall/ipset/$name/$cidr", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Update IP or Network settings fail!');
        }

        return ResponseHelper::generate(true, 'Updated IP or Network settings', $response['data']);
    }

    /**
     * Remove IP or Network settings
     * DELETE /api2/json/nodes/{node}/lxc/{vmid}/firewall/ipset/{name}/{cidr}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @param string $cidr Network/IP specification in CIDR format.
     * @throws Exception
     */
    public function deleteLxcFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $this->validateSegment($cidr, 'cidr');
        $response = $this->client->delete("nodes/$node/lxc/$vmid/firewall/ipset/$name/$cidr");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Remove IP or Network settings fail!');
        }

        return ResponseHelper::generate(true, 'Removed IP or Network settings', $response['data']);
    }

    /**
     * List rules.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/rules
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcFirewallRules(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall/rules");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List rules fail!');
        }

        return ResponseHelper::generate(true, 'List rules', $response['data']);
    }

    /**
     * Create new rule.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/firewall/rules
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createLxcFirewallRules(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("/nodes/$node/lxc/$vmid/firewall/rules", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create new rule fail!');
        }

        return ResponseHelper::generate(true, 'Created new rule', $response['data']);
    }

    /**
     * Get single rule data.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcFirewallRulesPos(string $node, int $vmid, int $pos): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("/nodes/$node/lxc/$vmid/firewall/rules/$pos");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get single rule data fail!');
        }

        return ResponseHelper::generate(true, 'Get single rule data', $response['data']);
    }

    /**
     * Modify rule data.
     * PUT /api2/json/nodes/{node}/lxc/{vmid}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function setLxcFirewallRulesPos(string $node, int $vmid, int $pos, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/lxc/$vmid/firewall/rules/$pos", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Modify rule data fail!');
        }

        return ResponseHelper::generate(true, 'Modify rule data', $response['data']);
    }

    /**
     * Delete rule.
     * DELETE /api2/json/nodes/{node}/lxc/{vmid}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function deleteLxcFirewallRulesPos(string $node, int $vmid, int $pos): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("/nodes/$node/lxc/$vmid/firewall/rules/$pos");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Delete rule fail!');
        }

        return ResponseHelper::generate(true, 'Deleted rule', $response['data']);
    }

    /**
     * Read firewall log
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/log
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param integer|null $limit
     * @param integer|null $start
     * @throws Exception
     */
    public function lxcFirewallLog(string $node, int $vmid, ?int $limit = null, ?int $start = null): array
    {
        $optional['limit'] = !empty($limit) ? $limit : 50;
        $optional['start'] = !empty($start) ? $start : 0;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall/log", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read firewall log fail!');
        }

        return ResponseHelper::generate(true, 'Read firewall log', $response['data']);
    }

    /**
     * Get VM firewall options.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/firewall/options
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcFirewallOptions(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/firewall/options");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get VM firewall options fail!');
        }

        return ResponseHelper::generate(true, 'Get VM firewall options', $response['data']);
    }

    /**
     * Set Firewall options.
     * PUT /api2/json/nodes/{node}/lxc/{vmid}/firewall/options
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function setLxcFirewallOptions(string $node, int $vmid, array $data = array()): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("/nodes/$node/lxc/$vmid/firewall/options", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Set VM firewall options fail!');
        }

        return ResponseHelper::generate(true, 'Set VM firewall options', $response['data']);
    }

    /**
     * List all snapshots.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/snapshot
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcSnapshot(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/snapshot");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List all snapshots fail!');
        }

        return ResponseHelper::generate(true, 'List all snapshots', $response['data']);
    }

    /**
     * Snapshot a container.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/snapshot
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createLxcSnapshot(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/snapshot", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Snapshot a container fail!');
        }

        return ResponseHelper::generate(true, 'Snapshot a container', $response['data']);
    }

    /**
     * List all snapshots.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/snapshot/{snapname}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $snapname The name of the snapshot.
     * @throws Exception
     */
    public function lxcSnapname(string $node, int $vmid, string $snapname): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->get("nodes/$node/lxc/$vmid/snapshot/$snapname");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List all snapshots fail!');
        }

        return ResponseHelper::generate(true, 'List all snapshots', $response['data']);
    }

    /**
     * Delete a LXC snapshot.
     * DELETE /api2/json/nodes/{node}/lxc/{vmid}/snapshot/{snapname}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $snapname The name of the snapshot.
     * @throws Exception
     */
    public function deleteLxcSnapshot(string $node, int $vmid, string $snapname): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->delete("nodes/$node/lxc/$vmid/snapshot/$snapname");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'List all snapshots fail!');
        }

        return ResponseHelper::generate(true, 'List all snapshots', $response['data']);
    }

    /**
     * Get snapshot configuration
     * GET /api2/json/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $snapname The name of the snapshot.
     * @throws Exception
     */
    public function lxcSnapnameConfig(string $node, int $vmid, string $snapname): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->get("/nodes/$node/lxc/$vmid/snapshot/$snapname/config");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get snapshot configuration fail!');
        }

        return ResponseHelper::generate(true, 'Get snapshot configuration', $response['data']);
    }

    /**
     * Update snapshot metadata.
     * PUT /api2/json/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $snapname The name of the snapshot.
     * @param array $data
     * @throws Exception
     */
    public function lxcSnapshotConfig(string $node, int $vmid, string $snapname, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->put("/nodes/$node/lxc/$vmid/snapshot/$snapname/config", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Update snapshot metadata fail!');
        }

        return ResponseHelper::generate(true, 'Update snapshot metadata', $response['data']);
    }

    /**
     * Rollback LXC state to specified snapshot.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $snapname The name of the snapshot.
     * @param array $data
     * @throws Exception
     */
    public function lxcSnapshotRollback(string $node, int $vmid, string $snapname, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->post("nodes/$node/lxc/$vmid/snapshot/$snapname/rollback", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Update snapshot metadata fail!');
        }

        return ResponseHelper::generate(true, 'Update snapshot metadata', $response['data']);
    }

    /**
     * LXC Status
     * GET /api2/json/nodes/{node}/lxc/{vmid}/status
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcStatus(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/status");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'LXC status fail!');
        }

        return ResponseHelper::generate(true, 'LXC status', $response['data']);
    }

    /**
     * Get virtual machine status.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/status/current
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcCurrent(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/status/current");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get virtual machine status fail!');
        }

        return ResponseHelper::generate(true, 'Get virtual machine status', $response['data']);
    }

    /**
     * Resume the container.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/status/resume
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcResume(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/status/resume", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Resume the container fail!');
        }

        return ResponseHelper::generate(true, 'Resume the container', $response['data']);
    }

    /**
     * Shutdown the container. This will trigger a clean shutdown of the container, see lxc-stop(1) for details.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/status/shutdown
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcShutdown(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("/nodes/$node/lxc/$vmid/status/shutdown", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Shutdown the container fail!');
        }

        return ResponseHelper::generate(true, 'Shutdown the container', $response['data']);
    }

    /**
     * Start the container.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/status/start
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcStart(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/status/start", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Start the container fail!');
        }

        return ResponseHelper::generate(true, 'Start the container', $response['data']);
    }

    /**
     * Stop the container. This will abruptly stop all processes running in the container.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/status/stop
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcStop(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/status/stop", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Stop the container fail!');
        }

        return ResponseHelper::generate(true, 'Stop the container', $response['data']);
    }

    /**
     * Suspend the container.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/status/suspend
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     */
    public function lxcSuspend(string $node, int $vmid, array $data = array()): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/status/suspend", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Suspend the container fail!');
        }

        return ResponseHelper::generate(true, 'Suspend the container', $response['data']);
    }

    /**
     * Reboot the container.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/status/reboot
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcReboot(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/status/reboot", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Reboot the container fail!');
        }

        return ResponseHelper::generate(true, 'Reboot the container', $response['data']);
    }

    /**
     * Create a container clone/copy
     * POST /api2/json/nodes/{node}/lxc/{vmid}/clone
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcClone(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("/nodes/$node/lxc/$vmid/clone", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create a container clone fail!');
        }

        return ResponseHelper::generate(true, 'Create a container clone', $response['data']);
    }

    /**
     * Get container configuration.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcConfig(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/config");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get container configuration fail!');
        }

        return ResponseHelper::generate(true, 'Get container configuration', $response['data']);
    }

    /**
     * Set container options.
     * PUT /api2/json/nodes/{node}/lxc/{vmid}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function setLxcConfig(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/lxc/$vmid/config", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Set container configuration fail!');
        }

        return ResponseHelper::generate(true, 'Set container configuration', $response['data']);
    }

    /**
     * Check if feature for virtual machine is available.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/feature
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function lxcFeature(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/feature");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Check if feature for virtual machine is available fail!');
        }

        return ResponseHelper::generate(true, 'Check if feature for virtual machine is available', $response['data']);
    }

    /**
     * Migrate the container to another node. Creates a new migration task.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/migrate
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcMigrate(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/migrate", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Migrate the container to another node. Creates a new migration task fail!');
        }

        return ResponseHelper::generate(true, 'Migrate the container to another node. Creates a new migration task', $response['data']);
    }

    /**
     * Resize a container mount point.
     * PUT /api2/json/nodes/{node}/lxc/{vmid}/resize
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcResize(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("/nodes/$node/lxc/$vmid/resize", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Resize a container mount point fail!');
        }

        return ResponseHelper::generate(true, 'Resize a container mount point task', $response['data']);
    }

    /**
     * Read VM RRD statistics (returns PNG)
     * GET /api2/json/nodes/{node}/lxc/{vmid}/rrd
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string|null $ds The list of datasources you want to display.
     * @param enum $timeframe Specify the time frame you are interested in.
     * @throws Exception
     */
    public function lxcRrd(string $node, int $vmid, ?string $ds = null, $timeframe = null): array
    {
        $optional['ds'] = !empty($ds) ? $ds : null;
        $optional['timeframe'] = !empty($timeframe) ? $timeframe : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/rrd", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read VM RRD statistics fail!');
        }

        return ResponseHelper::generate(true, 'Read VM RRD statistics', $response['data']);
    }

    /**
     * Read VM RRD statistics
     * GET /api2/json/nodes/{node}/lxc/{vmid}/rrddata
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param enum $timeframe Specify the time frame you are interested in.
     * @throws Exception
     */
    public function lxcRrddata(string $node, int $vmid, $timeframe = null): array
    {
        $optional['timeframe'] = !empty($timeframe) ? $timeframe : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/lxc/$vmid/rrddata", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read VM RRD Data statistics fail!');
        }

        return ResponseHelper::generate(true, 'Read VM RRD Data statistics', $response['data']);
    }

    /**
     * Returns a SPICE configuration to connect to the CT.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/spiceproxy
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function lxcSpiceproxy(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("/nodes/$node/lxc/$vmid/spiceproxy", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Read VM RRD Data statistics fail!');
        }

        return ResponseHelper::generate(true, 'Read VM RRD Data statistics', $response['data']);
    }

    /**
     * Create a Template.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/template
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createLxcTemplate(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("/nodes/$node/lxc/$vmid/template", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create a Template fail!');
        }

        return ResponseHelper::generate(true, 'Created a Template', $response['data']);
    }

    /**
     * Creates a TCP VNC proxy connections.
     * POST /api2/json/nodes/{node}/lxc/{vmid}/vncproxy
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createLxcVncproxy(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/lxc/$vmid/vncproxy", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Creates a TCP VNC proxy connections fail!');
        }

        return ResponseHelper::generate(true, 'Created a TCP VNC proxy connections', $response['data']);
    }

    /**
     * Opens a weksocket for VNC traffic.
     * GET /api2/json/nodes/{node}/lxc/{vmid}/vncwebsocket
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param integer|null $port Port number returned by previous vncproxy call.
     * @param string|null $vncticket Ticket from previous call to vncproxy.
     * @throws Exception
     */
    public function lxcVncwebsocket(string $node, int $vmid, ?int $port = null, ?string $vncticket = null): array
    {
        $optional['port'] = !empty($port) ? $port : null;
        $optional['vncticket'] = !empty($vncticket) ? $vncticket : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("/nodes/$node/lxc/$vmid/vncwebsocket", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Opens a weksocket for VNC traffic fail!');
        }

        return ResponseHelper::generate(true, 'Opens a weksocket for VNC traffic', $response['data']);
    }

    /**
     * get List available networks
     * GET /api2/json/nodes/{node}/network
     * @param string $node The cluster node name.
     * @param enum|null $type Only list specific interface types.
     * @throws Exception
     */
    public function network(string $node, $type = null): array
    {
        $optional['type'] = !empty($type) ? $type : null;
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/network", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'get List available networks fail!');
        }

        return ResponseHelper::generate(true, 'get List available networks', $response['data']);
    }

    /**
     * Create network device configuration
     * POST /api2/json/nodes/{node}/network
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function createNetwork(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/network", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create network device configuration fail!');
        }

        return ResponseHelper::generate(true, 'Created network device configurations', $response['data']);
    }

    /**
     * Revert network configuration changes.
     * DELETE /api2/json/nodes/{node}/network
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function revertNetwork(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("nodes/$node/network");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Revert network configuration changes fail!');
        }

        return ResponseHelper::generate(true, 'Revert network configuration changes', $response['data']);
    }

    /**
     * Network interface name.
     * GET /api2/json/nodes/{node}/network/{iface}
     * @param string $node The cluster node name.
     * @param string $iface
     * @throws Exception
     */
    public function networkIface(string $node, string $iface): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($iface, 'iface');
        $response = $this->client->get("/nodes/$node/network/$iface");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Network interface name fail!');
        }

        return ResponseHelper::generate(true, 'Network interface name', $response['data']);
    }

    /**
     * Update network device configuration
     * PUT /api2/json/nodes/{node}/network/{iface}
     * @param string $node The cluster node name.
     * @param string $iface
     * @param array $data
     * @throws Exception
     */
    public function updateNetworkIface(string $node, string $iface, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($iface, 'iface');
        $response = $this->client->put("/nodes/$node/network/$iface", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Update network device configuration fail!');
        }

        return ResponseHelper::generate(true, 'Updated network device configuration', $response['data']);
    }

    /**
     * Delete network device configuration
     * DELETE /api2/json/nodes/{node}/network/{iface}
     * @param string $node The cluster node name.
     * @param string $iface
     * @throws Exception
     */
    public function deleteNetworkIface(string $node, string $iface): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($iface, 'iface');
        $response = $this->client->delete("/nodes/$node/network/$iface");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Delete network device configuration fail!');
        }

        return ResponseHelper::generate(true, 'Deleted network device configuration', $response['data']);
    }

    /**
     * Virtual machine index (per node).
     * GET /api2/json/nodes/{node}/qemu
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function qemu(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Virtual machine fail!');
        }

        return ResponseHelper::generate(true, 'Virtual machine', $response['data']);
    }

    /**
     * Create or restore a virtual machine.
     * POST /api2/json/nodes/{node}/qemu
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function createQemu(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create or restore a virtual machine fail!');
        }

        return ResponseHelper::generate(true, 'Create or restore a virtual machine', $response['data']);
    }

    /**
     * Directory index
     * GET /api2/json/nodes/{node}/qemu/{vmid}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuVmid(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'VM details fail!');
        }

        return ResponseHelper::generate(true, 'VM details', $response['data']);
    }

    /**
     * Destroy the vm (also delete all used/owned volumes)
     * DELETE /api2/json/nodes/{node}/qemu/{vmid}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function deleteQemu(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("nodes/$node/qemu/$vmid", $data);

        if (ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(true, 'Delete vm successfully', $response['data']);
        }

        return ResponseHelper::generate(false, 'Delete fail!');
    }

    /**
     * Directory index.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/aliases
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuFirewall(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'firewall aliases fail!');
        }
        return ResponseHelper::generate(true, 'firewall aliases!', $response['data']);
    }

    /**
     * List aliases
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/aliases
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuFirewallAliases(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/aliases");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'firewall aliases fail!');
        }
        return ResponseHelper::generate(true, 'firewall aliases!', $response['data']);
    }

    /**
     * Create IP or Network Alias
     * POST /api2/json/nodes/{node}/qemu/{vmid}/firewall/aliases
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createQemuFirewallAliase(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/firewall/aliases", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create IP or Network Alias fail!');
        }
        return ResponseHelper::generate(true, 'Created IP or Network Alias!', $response['data']);
    }

    /**
     * Read alias.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/aliases/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name Alias name.
     * @throws Exception
     */
    public function qemuFirewallAliasesName(string $node, int $vmid, string $name): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/aliases/$name");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read Alias fail!');
        }
        return ResponseHelper::generate(true, 'Read Alias!', $response['data']);
    }

    /**
     * Update IP or Network alias
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/firewall/aliases/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name Alias name.
     * @param array $data
     * @throws Exception
     */
    public function updateQemuFirewallAliaseName(string $node, int $vmid, string $name, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->put("nodes/$node/qemu/$vmid/firewall/aliases/$name", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Read Alias fail!');
        }
        return ResponseHelper::generate(true, 'Read Alias!', $response['data']);
    }

    /**
     * Remove IP or Network alias.
     * DELETE /api2/json/nodes/{node}/qemu/{vmid}/firewall/aliases/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name Alias name.
     * @throws Exception
     */
    public function deleteQemuFirewallAliaseName(string $node, int $vmid, string $name): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->delete("nodes/$node/qemu/$vmid/firewall/aliases/$name");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Remove IP or Network fail!');
        }
        return ResponseHelper::generate(true, 'Removed IP or Network!', $response['data']);
    }

    /**
     * List IPSets
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuFirewallIpset(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/ipset");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List IPSets fail!');
        }
        return ResponseHelper::generate(true, 'List IPSets!', $response['data']);
    }

    /**
     * Create new IPSet
     * POST /api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createQemuFirewallIpset(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/firewall/ipset", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'List IPSets fail!');
        }
        return ResponseHelper::generate(true, 'List IPSets!', $response['data']);
    }

    /**
     * List IPSet content
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @throws Exception
     */
    public function qemuFirewallIpsetName(string $node, int $vmid, string $name): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/ipset/$name");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List IPSet fail!');
        }
        return ResponseHelper::generate(true, 'List IPSet!', $response['data']);
    }

    /**
     * Add IP or Network to IPSet.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @param array $data
     * @throws Exception
     */
    public function addQemuFirewallIpsetName(string $node, int $vmid, string $name, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->post("nodes/$node/qemu/$vmid/firewall/ipset/$name", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Add IP or Network fail!');
        }
        return ResponseHelper::generate(true, 'Add IP or Network!', $response['data']);
    }

    /**
     * Delete IPSet
     * DELETE /api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @throws Exception
     */
    public function deleteQemuFirewallIpsetName(string $node, int $vmid, string $name): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $response = $this->client->delete("nodes/$node/qemu/$vmid/firewall/ipset/$name");

        if (ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(true, 'Delete successfully', $response['data']);
        }

        return ResponseHelper::generate(false, 'Delete fail!');
    }

    /**
     * Read IP or Network settings from IPSet.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @param string $cidr Network/IP specification in CIDR format.
     * @throws Exception
     */
    public function qemuFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $this->validateSegment($cidr, 'cidr');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/ipset/$name/$cidr");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read IP or Network settings from IPSet fail!');
        }
        return ResponseHelper::generate(true, 'Read IP or Network settings from IPSet!', $response['data']);
    }

    /**
     * Update IP or Network settings
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @param string $cidr Network/IP specification in CIDR format.
     * @param array $data
     * @throws Exception
     */
    public function updateQemuFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $this->validateSegment($cidr, 'cidr');
        $response = $this->client->put("nodes/$node/qemu/$vmid/firewall/ipset/$name/$cidr", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Update IP or Network fail!');
        }
        return ResponseHelper::generate(true, 'Update IP or Network!', $response['data']);
    }

    /**
     * Remove IP or Network settings
     * DELETE /api2/json/nodes/{node}/qemu/{vmid}/firewall/ipset/{name}/{cidr}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $name IP set name.
     * @param string $cidr Network/IP specification in CIDR format.
     * @throws Exception
     */
    public function deleteQemuFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($name, 'name');
        $this->validateSegment($cidr, 'cidr');
        $response = $this->client->delete("nodes/$node/qemu/$vmid/firewall/ipset/$name/$cidr");

        if (ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(true, 'Delete successfully', $response['data']);
        }

        return ResponseHelper::generate(false, 'Delete fail!');
    }

    /**
     * List rules.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/rules
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuFirewallRules(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/rules");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'node vms fail!');
        }
        return ResponseHelper::generate(true, 'node vm list!', $response['data']);
    }

    /**
     * Create new rule.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/firewall/rules
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createQemuFirewallRules(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/firewall/rules", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create new rule fail!');
        }
        return ResponseHelper::generate(true, 'Create new rule!', $response['data']);
    }

    /**
     * Get single rule data.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuFirewallRulesPos(string $node, int $vmid, int $pos): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/rules/$pos");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get single rule fail!');
        }
        return ResponseHelper::generate(true, 'Get single rule!', $response['data']);
    }

    /**
     * Modify rule data.
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function updateQemuFirewallRulesPos(string $node, int $vmid, int $pos, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/qemu/$vmid/firewall/rules/$pos", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Modify rule fail!');
        }
        return ResponseHelper::generate(true, 'Modify rule!', $response['data']);
    }

    /**
     * Delete rule.
     * DELETE /api2/json/nodes/{node}/qemu/{vmid}/firewall/rules/{pos}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function deleteQemuFirewallRulesPos(string $node, int $vmid, int $pos): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("nodes/$node/qemu/$vmid/firewall/rules/$pos");

        if (ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(true, 'Delete successfully', $response['data']);
        }

        return ResponseHelper::generate(false, 'Delete fail!');
    }

    /**
     * Read firewall log
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/log
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param integer|null $limit
     * @param integer|null $start
     */
    public function qemuFirewallLog(string $node, int $vmid, ?int $limit = null, ?int $start = null): array
    {
        $optional['limit'] = !empty($limit) ? $limit : 50;
        $optional['start'] = !empty($start) ? $start : 0;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/log", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read firewalls fail!');
        }
        return ResponseHelper::generate(true, 'Read firewall!', $response['data']);
    }

    /**
     * Get VM firewall options.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/options
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuFirewallOptions(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/options");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get VM firewall options fail!');
        }
        return ResponseHelper::generate(true, 'Get VM firewall options!', $response['data']);
    }

    /**
     * Set Firewall options.
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/firewall/options
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function setQemuFirewallOptions(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("/nodes/$node/qemu/$vmid/firewall/options", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Set firewall options fail!');
        }
        return ResponseHelper::generate(true, 'Set firewall options!', $response['data']);
    }

    /**
     * Lists possible IPSet/Alias reference which are allowed in source/dest properties.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/firewall/refs
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuFirewallRefs(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/firewall/refs");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Lists possible IPSet/Alias fail!');
        }
        return ResponseHelper::generate(true, 'Lists possible IPSet/Alias!', $response['data']);
    }

    /**
     * List all snapshots.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/snapshot
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuSnapshot(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/snapshot");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List all snapshots fail!');
        }
        return ResponseHelper::generate(true, 'List all snapshots!', $response['data']);
    }

    /**
     * Snapshot a VM.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/snapshot
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createQemuSnapshot(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/snapshot", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Snapshot a VM fail!');
        }
        return ResponseHelper::generate(true, 'Snapshot a VM!', $response['data']);
    }

    /**
     * Get a snapshot by name.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/snapshot/{snapname}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string $snapname snapname The name of the snapshot.
     * @throws Exception
     */
    public function qemuSnapname(string $node, int $vmid, string $snapname): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->get("nodes/$node/qemu/$vmid/snapshot/$snapname");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Snapshot fail!');
        }
        return ResponseHelper::generate(true, 'Snapshot!', $response['data']);
    }

    /**
     * Delete a VM snapshot.
     * DELETE /api2/json/nodes/{node}/qemu/{vmid}/snapshot/{snapname}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string   snapname The name of the snapshot.
     * @throws Exception
     */
    public function deleteQemuSnapshot(string $node, int $vmid, string $snapname): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->delete("nodes/$node/qemu/$vmid/snapshot/$snapname");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Delete fail!');
        }
        return ResponseHelper::generate(true, 'Delete Successfully!', $response['data']);
    }

    /**
     * Get snapshot configuration
     * GET /api2/json/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string   snapname The name of the snapshot.
     * @throws Exception
     */
    public function qemuSnapnameConfig(string $node, int $vmid, string $snapname): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->get("nodes/$node/qemu/$vmid/snapshot/$snapname/config");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get snapshot configuration fail!');
        }
        return ResponseHelper::generate(true, 'Get snapshot configuration Successfully!', $response['data']);
    }

    /**
     * Update snapshot metadata.
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string   snapname The name of the snapshot.
     * @param array $data
     * @throws Exception
     */
    public function updateQemuSnapshotConfig(string $node, int $vmid, string $snapname, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->put("/nodes/$node/qemu/$vmid/snapshot/$snapname/config", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Update snapshot metadata fail!');
        }
        return ResponseHelper::generate(true, 'Update snapshot metadata Successfully!', $response['data']);
    }

    /**
     * Rollback VM state to specified snapshot.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string   snapname The name of the snapshot.
     * @param array $data
     * @throws Exception
     */
    public function qemuSnapshotRollback(string $node, int $vmid, string $snapname, array $data = array()): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($snapname, 'snapname');
        $response = $this->client->post("nodes/$node/qemu/$vmid/snapshot/$snapname/rollback", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Rollback snapshot fail!');
        }
        return ResponseHelper::generate(true, 'Rollback snapshot successfully!', $response['data']);
    }

    /**
     * Directory index
     * GET /api2/json/nodes/{node}/qemu/{vmid}/status
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuStatus(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/status");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'status fail!');
        }
        return ResponseHelper::generate(true, 'status successfully!', $response['data']);
    }

    /**
     * Get virtual machine status.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/status/current
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuCurrent(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/status/current");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get virtual machine status fail!');
        }
        return ResponseHelper::generate(true, 'Get virtual machine status!', $response['data']);
    }

    /**
     * Resume the virtual machine.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/resume
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuResume(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/status/resume", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Resume virtual machine fail!');
        }
        return ResponseHelper::generate(true, 'Resume virtual machine!', $response['data']);
    }

    /**
     * Reset the virtual machine.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/reset
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuReset(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/status/reset", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Reset virtual machine fail!');
        }
        return ResponseHelper::generate(true, 'Reset virtual machine!', $response['data']);
    }

    /**
     * Shutdown virtual machine. This is similar to pressing the power button on a physical machine.This will send an ACPI event for the guest OS, which should then proceed to a clean shutdown.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/shutdown
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuShutdown(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/status/shutdown", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Shutdown virtual machine fail!');
        }
        return ResponseHelper::generate(true, 'Shutdown virtual machine!', $response['data']);
    }

    /**
     * Start the virtual machine.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/start
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuStart(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/status/start", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Started virtual machine fail!');
        }
        return ResponseHelper::generate(true, 'Started virtual machine!', $response['data']);
    }

    /**
     * Stop virtual machine. The qemu process will exit immediately. Thisis akin to pulling the power plug of a running computer and may damage the VM data
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/stop
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuStop(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/status/stop", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Stop virtual machine fail!');
        }
        return ResponseHelper::generate(true, 'Stop virtual machine!', $response['data']);
    }

    /**
     * Reboot virtual machine.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/reboot
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuReboot(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/status/reboot", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Reboot virtual machine fail!');
        }
        return ResponseHelper::generate(true, 'Reboot virtual machine!', $response['data']);
    }

    /**
     * Suspend the  virtual machine.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/suspend
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuSuspend(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/status/suspend", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Reboot virtual machine fail!');
        }
        return ResponseHelper::generate(true, 'Reboot virtual machine!', $response['data']);
    }

    /**
     * Execute Qemu Guest Agent commands.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/agent
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuAgent(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/status/agent", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Execute Qemu Guest Agent commands fail!');
        }
        return ResponseHelper::generate(true, 'Executed Qemu Guest Agent commands!', $response['data']);
    }

    /**
     * Execute command via Qemu Guest Agent.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/status/agent/exec
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuAgentExec(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/agent/exec", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Execute command via Qemu Guest Agent fail!');
        }
        return ResponseHelper::generate(true, 'Executed command via Qemu Guest Agent!', $response['data']);
    }

    /**
     * Change user password via Qemu Guest Agent.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/agent/set-user-password
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     */
    public function qemuAgentSetUserPassword(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/agent/set-user-password", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Change user password fail!');
        }
        return ResponseHelper::generate(true, 'Changed user password!', $response['data']);
    }

    /**
     * Create a copy of virtual machine/template
     * POST /api2/json/nodes/{node}/qemu/{vmid}/clone
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuClone(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/clone", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Create a copy of virtual machine/template fail!');
        }
        return ResponseHelper::generate(true, 'Created a copy of virtual machine/template!', $response['data']);
    }

    /**
     * Get current virtual machine configuration. This does not include pending configuration changes (see 'pending' API).
     * GET /api2/json/nodes/{node}/qemu/{vmid}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuConfig(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("/nodes/$node/qemu/$vmid/config");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get current virtual machine configuration fail!');
        }
        return ResponseHelper::generate(true, 'Get current virtual machine configuration!', $response['data']);
    }

    /**
     * Set virtual machine options (asynchrounous API).
     * POST /api2/json/nodes/{node}/qemu/{vmid}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createQemuConfig(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/config", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Set virtual machine configuration fail!');
        }
        return ResponseHelper::generate(true, 'Set virtual machine configuration!', $response['data']);
    }

    /**
     * Set virtual machine options (synchrounous API) - You should consider using the POST method instead for any actions involving hotplug or storage allocation.
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/config
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     */
    public function setQemuConfig(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/qemu/$vmid/config", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Set virtual machine options fail!');
        }
        return ResponseHelper::generate(true, 'Set virtual machine options!', $response['data']);
    }

    /**
     * Check if feature for virtual machine is available.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/feature
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuFeature(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/feature");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Check if feature for virtual machine is available fail!');
        }
        return ResponseHelper::generate(true, 'Check if feature for virtual machine is available!', $response['data']);
    }

    /**
     * Migrate virtual machine. Creates a new migration task.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/migrate
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuMigrate(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/migrate", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Migrate virtual machine fail!');
        }
        return ResponseHelper::generate(true, 'Migrate virtual machine!', $response['data']);
    }

    /**
     * Execute Qemu monitor commands.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/monitor
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuMonitor(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/monitor", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Execute Qemu monitor commands fail!');
        }
        return ResponseHelper::generate(true, 'Executed Qemu monitor commands!', $response['data']);
    }

    /**
     * Move volume to different storage.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/move_disk
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuMoveDisk(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/move_disk", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Move volume to different storage fail!');
        }
        return ResponseHelper::generate(true, 'Moved volume to different storage!', $response['data']);
    }

    /**
     * Get virtual machine configuration, including pending changes.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/pending
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function qemuPending(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/pending");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get virtual machine configuration, including pending changes fail!');
        }
        return ResponseHelper::generate(true, 'Get virtual machine configuration, including pending changes!', $response['data']);
    }

    /**
     * Extend volume size.
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/resize
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuResize(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/qemu/$vmid/resize", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Extend volume size fail!');
        }
        return ResponseHelper::generate(true, 'Extended volume size!', $response['data']);
    }

    /**
     * Read VM RRD statistics (returns PNG)
     * GET /api2/json/nodes/{node}/qemu/{vmid}/rrd
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param string|null $ds The list of datasources you want to display.
     * @param enum $timeframe Specify the time frame you are interested in.
     * @throws Exception
     */
    public function qemuRrd(string $node, int $vmid, ?string $ds = null, $timeframe = null): array
    {
        $optional['ds'] = !empty($ds) ? $ds : null;
        $optional['timeframe'] = !empty($timeframe) ? $timeframe : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/rrd", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read VM RRD statistics fail!');
        }
        return ResponseHelper::generate(true, 'Read VM RRD statistics!', $response['data']);
    }

    /**
     * Read VM RRD statistics
     * GET /api2/json/nodes/{node}/qemu/{vmid}/rrddata
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param enum $timeframe Specify the time frame you are interested in.
     * @throws Exception
     */
    public function qemuRrddata(string $node, int $vmid, $timeframe = null): array
    {
        $optional['timeframe'] = !empty($timeframe) ? $timeframe : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/rrddata", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read VM RRD statistics fail!');
        }
        return ResponseHelper::generate(true, 'Read VM RRD statistics!', $response['data']);
    }

    /**
     * Send key event to virtual machine.
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/sendkey
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuSendkey(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/qemu/$vmid/sendkey", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Read VM RRD statistics fail!');
        }
        return ResponseHelper::generate(true, 'Read VM RRD statistics!', $response['data']);
    }

    /**
     * Returns a SPICE configuration to connect to the CT.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/spiceproxy
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuSpiceproxy(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/spiceproxy", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Returns a SPICE configuration fail!');
        }
        return ResponseHelper::generate(true, 'Returns a SPICE configuration!', $response['data']);
    }

    /**
     * Create a Template.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/template
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createQemuTemplate(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/template", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Returns a SPICE configuration fail!');
        }
        return ResponseHelper::generate(true, 'Returns a SPICE configuration!', $response['data']);
    }

    /**
     * Unlink/delete disk images.
     * PUT /api2/json/nodes/{node}/qemu/{vmid}/unlink
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function qemuUnlink(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("/nodes/$node/qemu/$vmid/unlink", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Unlink/delete disk images fail!');
        }
        return ResponseHelper::generate(true, 'Unlink/delete disk images!', $response['data']);
    }

    /**
     * Creates a TCP VNC proxy connections.
     * POST /api2/json/nodes/{node}/qemu/{vmid}/vncproxy
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     * @throws Exception
     */
    public function createQemuVncproxy(string $node, int $vmid, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/qemu/$vmid/vncproxy", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Unlink/delete disk images fail!');
        }
        return ResponseHelper::generate(true, 'Unlink/delete disk images!', $response['data']);
    }

    /**
     * Opens a weksocket for VNC traffic.
     * GET /api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param integer|null $port Port number returned by previous vncproxy call.
     * @param string|null $vncticket Ticket from previous call to vncproxy.
     */
    public function qemuVncwebsocket(string $node, int $vmid, ?int $port = null, ?string $vncticket = null): array
    {
        $optional['port'] = !empty($port) ? $port : null;
        $optional['vncticket'] = !empty($vncticket) ? $vncticket : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/qemu/$vmid/vncwebsocket", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Opens a weksocket for VNC traffic fail!');
        }

        return ResponseHelper::generate(true, 'Opens a weksocket for VNC traffic!', $response['data']);
    }

    /**
     * List HA resources.
     * GET /api2/json/nodes/{node}/replication
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function replication(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/replication");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List HA resources fail!');
        }

        return ResponseHelper::generate(true, 'List HA resources!', $response['data']);
    }

    /**
     * Read replication job configuration.
     * GET /api2/json/nodes/{node}/replication/{id}
     * @param string $node The cluster node name.
     * @param string $id Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
     * @throws Exception
     */
    public function replicationId(string $node, string $id): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($id, 'id');
        $response = $this->client->get("nodes/$node/replication/$id");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read replication job configuration fail!');
        }

        return ResponseHelper::generate(true, 'Read replication job configuration!', $response['data']);
    }

    /**
     * Read replication job log.
     * GET /api2/json/nodes/{node}/replication/{id}/log
     * @param string $node The cluster node name.
     * @param string $id Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
     * @throws Exception
     */
    public function replicationLog(string $node, string $id): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($id, 'id');
        $response = $this->client->get("nodes/$node/replication/$id/log");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read replication job log fail!');
        }

        return ResponseHelper::generate(true, 'Read replication job log!', $response['data']);
    }

    /**
     * Schedule replication job to start as soon as possible.
     * POST /api2/json/nodes/{node}/replication/{id}/schedule_now
     * @param string $node The cluster node name.
     * @param string $id Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
     * @param array $data
     * @throws Exception
     */
    public function replicationScheduleNow(string $node, string $id, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($id, 'id');
        $response = $this->client->post("nodes/$node/replication/$id/schedule_now", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Schedule replication job to start as soon as possible fail!');
        }

        return ResponseHelper::generate(true, 'Schedule replication job to start as soon as possible!', $response['data']);
    }

    /**
     * Get replication job status.
     * GET /api2/json/nodes/{node}/replication/{id}/status
     * @param string $node The cluster node name.
     * @param string $id Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
     * @throws Exception
     */
    public function replicationStatus(string $node, string $id): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($id, 'id');
        $response = $this->client->get("nodes/$node/replication/$id/status");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'replication job status fail!');
        }

        return ResponseHelper::generate(true, 'replication job status!', $response['data']);
    }

    /**
     * Index of available scan methods
     * GET /api2/json/nodes/{node}/scan
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function scan(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/scan");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'available scan methods fail!');
        }

        return ResponseHelper::generate(true, 'available scan methods!', $response['data']);
    }

    /**
     * Scan remote GlusterFS server.
     * GET /api2/json/nodes/{node}/scan/glusterfs
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function scanGlusterfs(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/scan/glusterfs");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Scan remote GlusterFS server fail!');
        }

        return ResponseHelper::generate(true, 'Scan remote GlusterFS server!', $response['data']);
    }

    /**
     * Scan remote iSCSI server.
     * GET /api2/json/nodes/{node}/scan/iscsi
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function scanIscsi(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/scan/iscsi");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Scan remote iSCSI server fail!');
        }

        return ResponseHelper::generate(true, 'Scan remote iSCSI server!', $response['data']);
    }

    /**
     * List local LVM volume groups.
     * GET /api2/json/nodes/{node}/scan/lvm
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function scanLvm(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/scan/lvm");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List local LVM volume groups fail!');
        }

        return ResponseHelper::generate(true, 'List local LVM volume groups!', $response['data']);
    }

    /**
     * List local LVM Thin Pools.
     * GET /api2/json/nodes/{node}/scan/lvmthin
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function scanLvmthin(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/scan/lvmthin");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List local LVM Thin Pools fail!');
        }

        return ResponseHelper::generate(true, 'List local LVM Thin Pools!', $response['data']);
    }

    /**
     * List local USB devices.
     * GET /api2/json/nodes/{node}/scan/usb
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function scanUsb(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/scan/usb");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List local USB devices fail!');
        }

        return ResponseHelper::generate(true, 'List local USB devices!', $response['data']);
    }

    /**
     * Scan zfs pool list on local node.
     * GET /api2/json/nodes/{node}/scan/zfs
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function scanZfs(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/scan/zfs");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Scan zfs pool list on local node fail!');
        }

        return ResponseHelper::generate(true, 'Scan zfs pool list on local node!', $response['data']);
    }

    /**
     * Service list.
     * GET /api2/json/nodes/{node}/services
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function services(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/services");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Services fail!');
        }

        return ResponseHelper::generate(true, 'Services!', $response['data']);
    }

    /**
     * Service list.
     * GET /api2/json/nodes/{node}/services/{service}/reload
     * @param string $node The cluster node name.
     * @param enum $service Service ID
     * @throws Exception
     */
    public function listService(string $node, $service): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment((string) $service, 'service');
        $response = $this->client->get("nodes/$node/services/$service");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Services fail!');
        }

        return ResponseHelper::generate(true, 'Services!', $response['data']);
    }

    /**
     * Reload service.
     * POST /api2/json/nodes/{node}/services/{service}/reload
     * @param string $node The cluster node name.
     * @param enum $service Service ID
     * @param array $data
     * @throws Exception
     */
    public function servicesReload(string $node, $service, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($service, 'service');
        $response = $this->client->post("nodes/$node/services/$service/reload", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Reload service fail!');
        }

        return ResponseHelper::generate(true, 'Reload service!', $response['data']);
    }

    /**
     * Restart service.
     * POST /api2/json/nodes/{node}/services/{service}/restart
     * @param string $node The cluster node name.
     * @param enum $service Service ID
     * @param array $data
     * @throws Exception
     */
    public function servicesRestart(string $node, $service, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($service, 'service');
        $response = $this->client->post("nodes/$node/services/$service/restart", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Restart service fail!');
        }

        return ResponseHelper::generate(true, 'Restart service!', $response['data']);
    }

    /**
     * Start service.
     * POST /api2/json/nodes/{node}/services/{service}/start
     * @param string $node The cluster node name.
     * @param enum $service Service ID
     * @param array $data
     * @throws Exception
     */
    public function servicesStart(string $node, $service, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($service, 'service');
        $response = $this->client->post("nodes/$node/services/$service/start", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Start service fail!');
        }

        return ResponseHelper::generate(true, 'Start service!', $response['data']);
    }

    /**
     * Stop service.
     * POST /api2/json/nodes/{node}/services/{service}/stop
     * @param string $node The cluster node name.
     * @param enum $service Service ID
     * @param array $data
     * @throws Exception
     */
    public function servicesStop(string $node, $service, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($service, 'service');
        $response = $this->client->post("nodes/$node/services/$service/stop", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Stop service fail!');
        }

        return ResponseHelper::generate(true, 'Stop service!', $response['data']);
    }

    /**
     * Read service properties
     * GET /api2/json/nodes/{node}/services
     * @param string $node The cluster node name.
     * @param enum $service Service ID
     * @throws Exception
     */
    public function servicesState(string $node, $service): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($service, 'service');
        $response = $this->client->get("nodes/$node/services/$service/state");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read service properties fail!');
        }

        return ResponseHelper::generate(true, 'Read service properties!', $response['data']);
    }

    /**
     * Get status for all datastores.
     * GET /api2/json/nodes/{node}/storage
     * @param string $node The cluster node name.
     * @param string|null $content Only list stores which support this content type.
     * @param string|null $storage Only list status for specified storage
     * @param string|null $target If target is different to 'node', we only lists shared storages which content is accessible on this 'node' and the specified 'target' node.
     * @param boolean|null $enabled Only list stores which are enabled (not disabled in config).
     * @throws Exception
     */
    public function storage(string $node, ?string $content = null, ?string $storage = null, ?string $target = null, ?bool $enabled = null): array
    {
        $optional['content'] = !empty($content) ? $content : null;
        $optional['storage'] = !empty($storage) ? $storage : null;
        $optional['target'] = !empty($target) ? $target : null;
        $optional['enabled'] = !empty($enabled) ? $enabled : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/storage", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get status for all datastores fail!');
        }

        return ResponseHelper::generate(true, 'Get status for all datastores!', $response['data']);
    }

    /**
     * Get status datastores.
     * GET /api2/json/nodes/{node}/storage/{storage}
     * @param string $node The cluster node name.
     * @param string $storage The storage identifier.
     * @throws Exception
     */
    public function getStorage(string $node, string $storage): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($storage, 'storage');
        $response = $this->client->get("nodes/$node/storage/$storage");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Get status for all datastores fail!');
        }

        return ResponseHelper::generate(true, 'Get status for all datastores!', $response['data']);
    }

    /**
     * List storage content.
     * GET /api2/json/nodes/{node}/storage/{storage}/content
     * @param string $node The cluster node name.
     * @param string $storage The storage identifier.
     * @throws Exception
     */
    public function listStorageContent(string $node, string $storage): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($storage, 'storage');
        $response = $this->client->get("nodes/$node/storage/$storage/content");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'List storage content fail!');
        }

        return ResponseHelper::generate(true, 'List storage content!', $response['data']);
    }

    /**
     * Allocate disk images.
     * POST /api2/json/nodes/{node}/storage/{storage}/content
     * @param string $node The cluster node name.
     * @param string $storage The storage identifier.
     * @param array $data
     * @throws Exception
     */
    public function storageContent(string $node, string $storage, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($storage, 'storage');
        $response = $this->client->post("nodes/$node/storage/$storage/content", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Allocate disk images fail!');
        }

        return ResponseHelper::generate(true, 'Allocate disk images!', $response['data']);
    }

    /**
     * GET volume attributes
     * GET /api2/json/nodes/{node}/storage/{storage}/content/{volume}
     * @param string $node The cluster node name.
     * @param string $storage The storage identifier.
     * @throws Exception
     */
    public function storageContentVolume(string $node, string $storage, $volume): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($storage, 'storage');
        $this->validateSegment($volume, 'volume');
        $response = $this->client->get("nodes/$node/storage/$storage/content/$volume");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'GET volume attributes fail!');
        }

        return ResponseHelper::generate(true, 'GET volume attributes!', $response['data']);
    }

    /**
     * Copy a volume. This is experimental code - do not use.
     * POST /api2/json/nodes/{node}/storage/{storage}/content/{volume}
     * @param string $node The cluster node name.
     * @param string $storage The storage identifier.
     * @param array $data
     * @throws Exception
     */
    public function copyStorageContentVolume(string $node, string $storage, $volume, array $data): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($storage, 'storage');
        $this->validateSegment($volume, 'volume');
        $response = $this->client->post("nodes/$node/storage/$storage/content/$volume", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Copy a volume fail!');
        }

        return ResponseHelper::generate(true, 'Copy a volume!', $response['data']);
    }

    /**
     * Delete volume
     * DELETE /api2/json/nodes/{node}/storage/{storage}/content/{volume}
     * @param string $node The cluster node name.
     * @param string $storage The storage identifier.
     * @throws Exception
     */
    public function deleteStorageContentVolume(string $node, string $storage, $volume): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($storage, 'storage');
        $this->validateSegment($volume, 'volume');
        $response = $this->client->delete("nodes/$node/storage/$storage/content/$volume");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Delete a volume fail!');
        }

        return ResponseHelper::generate(true, 'Deleted a volume!', $response['data']);
    }

    /**
     * Read storage RRD statistics (returns PNG)
     * GET /api2/json/nodes/{node}/storage/rrd
     * @param string $node The cluster node name.
     * @return array
     * @throws Exception
     */
    public function storageRRD(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("/nodes/$node/storage/rrd");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read storage RRD statistics fail!');
        }

        return ResponseHelper::generate(true, 'Read storage RRD statistics!', $response['data']);
    }

    /**
     * Read storage RRD statistics.
     * GET /api2/json/nodes/{node}/storage/rrddata
     * @param string $node The cluster node name.
     * @return mixed
     * @throws Exception
     */
    public function storageRRDdata(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/storage/rrddata");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read storage RRD statistics fail!');
        }

        return ResponseHelper::generate(true, 'Read storage RRD statistics!', $response['data']);
    }

    /**
     * Read storage status.
     * GET /api2/json/nodes/{node}/storage/status
     * @param string $node The cluster node name.
     * @param string $storage The storage identifier.
     * @throws Exception
     */
    public function storageStatus(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/storage/status");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read storage status fail!');
        }

        return ResponseHelper::generate(true, 'Read storage status!', $response['data']);
    }

    /**
     * Upload templates and ISO images.
     * GET /api2/json/nodes/{node}/storage/upload
     * @param string $node The cluster node name.
     * @param array $data
     * @return mixed
     * @throws Exception
     */
    public function storageUpload(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/storage/upload", $data);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Upload templates and ISO images fail!');
        }

        return ResponseHelper::generate(true, 'Upload templates and ISO images!', $response['data']);
    }

    /**
     * Read task list for one node (finished tasks).
     * GET /api2/json/nodes/{node}/tasks
     * @param string $node The cluster node name.
     * @param boolean|null $errors
     * @param integer|null $limit
     * @param integer|null $vmid Only list tasks for this VM.
     * @param integer|null $start
     * @throws Exception
     */
    public function tasks(string $node, ?bool $errors = null, ?int $limit = null, ?int $vmid = null, ?int $start = null): array
    {
        $optional['errors']  = !empty($errors) ? $errors : false;
        $optional['limit']   = !empty($limit) ? $limit : null;
        $optional['vmid']    = !empty($vmid) ? $vmid : null;
        $optional['start']   = !empty($start) ? $start : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/tasks", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read task list fail!');
        }

        return ResponseHelper::generate(true, 'Read task list!', $response['data']);
    }

    /**
     * Read task upid
     * GET /api2/json/nodes/{node}/tasks/{upid}
     * @param string $node The cluster node name.
     * @param string $upid
     * @throws Exception
     */
    public function tasksUpid(string $node, string $upid): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($upid, 'upid');
        $response = $this->client->get("nodes/$node/tasks/$upid");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read task upid fail!');
        }

        return ResponseHelper::generate(true, 'Read task upid!', $response['data']);
    }

    /**
     * Stop a task.
     * DELETE /api2/json/nodes/{node}/tasks/{upid}
     * @param string $node The cluster node name.
     * @param string $upid
     * @throws Exception
     */
    public function tasksStop(string $node, string $upid): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($upid, 'upid');
        $response = $this->client->delete("nodes/$node/tasks/$upid");

        if (ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(true, 'Stop a task successfully', $response['data']);
        }

        return ResponseHelper::generate(false, 'Stop a task fail!');
    }

    /**
     * Read task log.
     * GET /api2/json/nodes/{node}/tasks/{upid}/log
     * @param string $node The cluster node name.
     * @param string $upid
     * @param integer $limit
     * @param integer $start
     * @throws Exception
     */
    public function tasksLog(string $node, string $upid, ?int $limit = null, ?int $start = null): array
    {
        $optional['limit']   = !empty($limit) ? $limit : null;
        $optional['start']   = !empty($start) ? $start : null;

        $this->validateSegment($node, 'node');
        $this->validateSegment($upid, 'upid');
        $response = $this->client->get("nodes/$node/tasks/$upid/log", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read task log fail!');
        }
        return ResponseHelper::generate(true, 'Read task log!', $response['data']);
    }

    /**
     * Read task status.
     * GET /api2/json/nodes/{node}/tasks/{upid}/status
     * @param string $node The cluster node name.
     * @param string $upid
     * @throws Exception
     */
    public function tasksStatus(string $node, string $upid): array
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($upid, 'upid');
        $response = $this->client->get("nodes/$node/tasks/$upid/status");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read task status fail!');
        }
        return ResponseHelper::generate(true, 'Read task status log!', $response['data']);
    }

    /**
     * Create backup.
     * POST /api2/json/nodes/{node}/vzdump
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function createVzdump(string $node, array $data): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/vzdump", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Read task status fail!');
        }
        return ResponseHelper::generate(true, 'Read task status log!', $response['data']);
    }
    /**
     * Extract configuration from vzdump backup archive
     * GET /api2/json/nodes/{node}/vzdump/extractconfig
     * @param string   $node     The cluster node name.
     */
    public function VzdumpExtractConfig(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/vzdump/extractconfig");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Extract configuration from vzdump backup archive fail!');
        }
        return ResponseHelper::generate(true, 'Extract configuration from vzdump backup archive!', $response['data']);
    }

    /**
     * Get list of VMs on a specific node
     *
     * @param string $node Node name
     * @return array
     * @throws Exception
     */
    public function getVMs(string $node): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/{$node}/qemu");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'node vms fail!');
        }
        return ResponseHelper::generate(true, 'node vm list!', $response['data']);
    }


    /**
     * Available OS types in Proxmox
     *
     * @var array
     */
    private const OS_TYPES = [
        'ubuntu' => 'other', // For Ubuntu and other modern Linux distributions
        'centos' => 'l26',   // For CentOS and older Linux distributions
        'windows' => 'win10' // For Windows
    ];

    /**
     * Create a new Virtual Machine
     *
     * @param string $node Node name
     * @param array $params VM configuration parameters
     * @return \Illuminate\Http\JsonResponse
     * @throws Exception
     */
    public function createVM(string $node, array $params): array
    {
        // Get next available VMID if not provided
        if (!isset($params['vmid'])) {
            $params['vmid'] = $this->getNextVMID();
        }

        // Set default values if not provided
        /* $defaults = [
             'cores' => 2,
             'sockets' => 2,
             'ostype' => 'other',
             'onboot' => 1,
             'scsihw' => 'virtio-scsi-pci',
             'bootdisk' => 'scsi0',
             'agent' => 1, // Enable QEMU Guest Agent
         ];

         $params = array_merge($defaults, $params);*/

        // Required parameters validation
        $required = ['vmid', 'name', 'ostype', 'memory', 'cores'];
        foreach ($required as $field) {
            if (!isset($params[$field])) {
                throw new Exception("Missing required parameter: {$field}");
            }
        }

        $config = ['cpu' => 'x86-64-v2-AES'];

        // Create VM and get response
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu", $params);
        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'VM create fail!');
        }

        $this->configVM($node, $params['vmid'], $config);

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $params['vmid'],
        ];

        return ResponseHelper::generate(true, 'VM created successfully', $successResponse);
    }

    protected function configVM(string $node, int $vmId, array $params): array
    {
        $this->validateSegment($node, 'node');
        return $this->client->put("nodes/{$node}/qemu/{$vmId}/config", $params);
    }

    public function createStorage(array $params): array
    {
        // Validate required parameters
        $required = ['storage', 'type'];
        foreach ($required as $field) {
            if (!isset($params[$field])) {
                throw new \Exception("Missing required parameter: {$field}");
            }
        }

        $response = $this->client->post('storage', $params);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'storage create fail!');
        }
        return ResponseHelper::generate(true, 'storage created!', $response['data']);
    }

    public function checkTaskStatus(string $node, string $upid)
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($upid, 'upid');
        $status = $this->client->get("nodes/{$node}/tasks/{$upid}/status");

        if ($status['data']['status'] === 'stopped') {
            if ($status['data']['exitstatus'] === 'OK') {
                return $status; // Task completed successfully
            } else {
                return $status;
                throw new Exception("Task failed with exit status: " . $status['data']['exitstatus']);
            }
        }
        return $status;
    }

    public function waitForTaskCompletion(string $node, string $upid)
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($upid, 'upid');
        do {
            // Poll task status
            $status = $this->client->get("nodes/{$node}/tasks/{$upid}/status");

            if ($status['data']['status'] === 'stopped') {
                if ($status['data']['exitstatus'] === 'OK') {
                    return $status['data']; // Task completed successfully
                } else {
                    throw new Exception("Task failed with exit status: " . $status['data']['exitstatus']);
                }
            }

            // Wait for a short period before polling again
            sleep(2);
        } while (true);
    }

    /**
     * Get VM status
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @return array
     * @throws Exception
     */
    public function getVMStatus(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/{$node}/qemu/{$vmid}/status/current");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'VM status check fail!');
        }
        return ResponseHelper::generate(true, 'VM status!', $response['data']);
    }

    /**
     * GET /api2/json/nodes/{node}/qemu/{vmid}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws Exception
     */
    public function vmQuery(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        return $this->client->get("nodes/$node/qemu/$vmid/status/current");
    }

    /**
     * Start VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @throws Exception
     */
    public function startVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/status/start");
        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'VM start fail!');
        }

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $vmid,
        ];

        return ResponseHelper::generate(true, 'VM Started', $successResponse);
    }

    /**
     * Stop VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @throws Exception
     */
    public function stopVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/status/stop");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'VM stop fail!');
        }

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $vmid,
        ];
        return ResponseHelper::generate(true, 'VM stopped', $successResponse);
    }

    /**
     * Reset VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @throws Exception
     */
    public function resetVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/status/reset");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'VM reset fail!');
        }

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $vmid,
        ];

        return ResponseHelper::generate(true, 'VM reset successfully', $successResponse);
    }

    /**
     * Current Status VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @throws Exception
     */
    public function statusVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/{$node}/qemu/{$vmid}/status/current");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'VM status fail!');
        }

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $vmid,
        ];

        return ResponseHelper::generate(true, 'VM status', $successResponse);
    }

    /**
     * Reboot VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @throws Exception
     */
    public function rebootVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/status/reboot");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'VM reboot fail!');
        }

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $vmid,
        ];

        return ResponseHelper::generate(true, 'VM rebooted', $successResponse);
    }

    /**
     * Shutdown VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @throws Exception
     */
    public function shutdownVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/status/shutdown");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'VM shutdown fail!');
        }

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $vmid,
        ];

        return ResponseHelper::generate(true, 'VM shutdown', $successResponse);
    }

    /**
     * Resume VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @throws Exception
     */
    public function resumeVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/status/resume");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'VM resume fail!');
        }

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $vmid,
        ];

        return ResponseHelper::generate(true, 'VM resumed', $successResponse);
    }

    /**
     * Suspend VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @throws Exception
     */
    public function suspendVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/status/suspend");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'VM suspend fail!');
        }

        $successResponse = [
            'data' => $response['data'],
            'node' => $node,
            'vmid' => $vmid,
        ];

        return ResponseHelper::generate(true, 'VM suspended', $successResponse);
    }

    /**
     * Rename a Virtual Machine
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @param string $newName New name for the VM
     * @throws Exception
     */
    public function renameVM(string $node, int $vmid, string $newName)
    {
        $this->validateSegment($node, 'node');
        try {
            // First, check if VM exists
            $vmStatus = $this->client->get("nodes/{$node}/qemu/{$vmid}/status/current");

            if (!isset($vmStatus['data'])) {
                return [
                    'success' => false,
                    'message' => "VM {$vmid} not found on node {$node}",
                    'data' => null
                ];
            }

            // Check if VM is running
            if ($vmStatus['data']['status'] === 'running') {
                return ResponseHelper::generate(false, 'Cannot rename running VM. Please stop the VM first.');
            }

            // Set new name
            $result = $this->setVMConfig($node, $vmid, [
                'name' => $newName
            ]);

            if (isset($result['data']) && $result['data']) {
                return ResponseHelper::generate(true, 'VM renamed successfully.');
            }

            return ResponseHelper::generate(false, 'Failed to rename VM.', $result['data'] ?? null);

        } catch (Exception $e) {
            return ResponseHelper::generate(false, $this->safeErrorMessage($e, 'Failed to rename VM'));
        }
    }


    /**
     * Fix non-running guest agent
     */
    public function fixGuestAgent(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        try {
            // 1. First ensure agent is enabled in config with correct settings
            $configResult = $this->client->post("nodes/{$node}/qemu/{$vmid}/config", [
                'agent' => 'enabled=1',
                'ostype' => 'l26'  // Linux 2.6+ kernel
            ]);

            // 2. Get current VM status
            $vmStatus = $this->client->get("nodes/{$node}/qemu/{$vmid}/status/current");
            $isRunning = isset($vmStatus['data']['status']) && $vmStatus['data']['status'] === 'running';

            // 3. If VM is running, need to restart it
            if ($isRunning) {
                // Stop VM
                $this->client->post("nodes/{$node}/qemu/{$vmid}/status/stop");

                // Wait for VM to stop
                sleep(15);

                // Start VM
                $this->client->post("nodes/{$node}/qemu/{$vmid}/status/start");

                // Wait for VM to start
                sleep(20);
            }

            // 4. Check agent status after restart
            try {
                $agentStatus = $this->client->get("nodes/{$node}/qemu/{$vmid}/agent/ping");
                $agentRunning = true;
            } catch (Exception $e) {
                $agentRunning = false;
            }

            return [
                'success' => true,
                'agent_enabled_in_config' => true,
                'agent_running' => $agentRunning,
                'vm_restarted' => $isRunning,
                'next_steps' => !$agentRunning ? [
                    'Install guest agent package inside VM:',
                    'For Ubuntu/Debian: apt install qemu-guest-agent',
                    'For CentOS/RHEL: yum install qemu-guest-agent',
                    'Then run: systemctl start qemu-guest-agent'
                ] : []
            ];

        } catch (Exception $e) {
            throw new Exception($this->safeErrorMessage($e, 'Failed to fix guest agent'), previous: $e);
        }
    }

    /**
     * Check detailed guest agent status
     */
    public function getDetailedAgentStatus(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        try {
            // Get VM configuration
            $config = $this->client->get("nodes/{$node}/qemu/{$vmid}/config");

            // Get current status
            $status = $this->client->get("nodes/{$node}/qemu/{$vmid}/status/current");

            // Try to ping agent
            try {
                $ping = $this->client->get("nodes/{$node}/qemu/{$vmid}/agent/ping");
                $agentResponding = true;
            } catch (Exception $e) {
                $agentResponding = false;
            }

            return [
                'config_status' => [
                    'agent_enabled' => isset($config['data']['agent']) && strpos($config['data']['agent'], 'enabled=1') !== false,
                    'os_type' => $config['data']['ostype'] ?? 'unknown'
                ],
                'runtime_status' => [
                    'vm_status' => $status['data']['status'] ?? 'unknown',
                    'agent_responding' => $agentResponding
                ]
            ];

        } catch (Exception $e) {
            throw new Exception($this->safeErrorMessage($e, 'Failed to get agent status'), previous: $e);
        }
    }

    /**
     * Enable QEMU Guest Agent for a VM
     */
    public function enableGuestAgent(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        try {
            // Enable QEMU Guest Agent in VM configuration
            $config = [
                'agent' => 1,  // Enable QEMU Guest Agent
                'ostype' => 'l26'  // Linux 2.6+/3.x/4.x Kernel
            ];

            $result = $this->client->post("nodes/{$node}/qemu/{$vmid}/config", $config);

            return [
                'success' => true,
                'config' => $config,
                'response' => $result
            ];

        } catch (Exception $e) {
            throw new Exception($this->safeErrorMessage($e, 'Failed to enable guest agent'), previous: $e);
        }
    }

    /**
     * Configure and start QEMU Guest Agent
     */
    public function configureGuestAgent(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        try {
            // First, enable the QEMU guest agent in VM config
            $configResult = $this->client->post("nodes/{$node}/qemu/{$vmid}/config", [
                'agent' => 'enabled=1,fstrim_cloned_disks=1',
                'ostype' => 'l26'  // For Linux VMs
            ]);

            // Stop the VM if it's running
            $this->client->post("nodes/{$node}/qemu/{$vmid}/status/stop");

            // Wait for VM to stop
            sleep(10);

            // Start the VM to apply changes
            $startResult = $this->client->post("nodes/{$node}/qemu/{$vmid}/status/start");

            // Check agent status (might take a few seconds to initialize)
            sleep(20);  // Wait for VM to fully start

            $status = $this->client->get("nodes/{$node}/qemu/{$vmid}/agent/ping");

            return [
                'success' => true,
                'config_result' => $configResult,
                'start_result' => $startResult,
                'agent_status' => $status
            ];

        } catch (Exception $e) {
            throw new Exception($this->safeErrorMessage($e, 'Failed to configure guest agent'), previous: $e);
        }
    }

    /**
     * Check Guest Agent status
     */
    public function checkGuestAgentStatus(string $node, int $vmid): array
    {
        $this->validateSegment($node, 'node');
        try {
            // Get VM status including agent info
            $status = $this->client->get("nodes/{$node}/qemu/{$vmid}/status/current");

            // Try to ping the agent
            try {
                $ping = $this->client->get("nodes/{$node}/qemu/{$vmid}/agent/ping");
                $agentRunning = true;
            } catch (Exception $e) {
                $agentRunning = false;
            }

            return [
                'success' => true,
                'agent_enabled' => isset($status['data']['agent']) && $status['data']['agent'] == 1,
                'agent_running' => $agentRunning,
                'status' => $status['data']
            ];

        } catch (Exception $e) {
            throw new Exception($this->safeErrorMessage($e, 'Failed to check guest agent status'), previous: $e);
        }
    }

    /**
     * Configure network settings for a VM
     */
    public function configureNetwork(string $node, int $vmid, array $networkParams): array
    {
        $this->validateSegment($node, 'node');
        try {
            // Validate IP format
            if (!filter_var($networkParams['ip'], FILTER_VALIDATE_IP)) {
                throw new Exception('Invalid IP address format');
            }
            if (!filter_var($networkParams['gateway'], FILTER_VALIDATE_IP)) {
                throw new Exception('Invalid gateway IP format');
            }

            // Format the network configuration
            $netConfig = [
                'ipconfig0' => sprintf(
                    'ip=%s/%s,gw=%s',
                    $networkParams['ip'],
                    $networkParams['subnet_mask'] ?? '24',
                    $networkParams['gateway']
                )
            ];

            // Add optional network parameters
            if (isset($networkParams['nameserver'])) {
                $netConfig['nameserver'] = $networkParams['nameserver'];
            }
            if (isset($networkParams['searchdomain'])) {
                $netConfig['searchdomain'] = $networkParams['searchdomain'];
            }

            // Apply network configuration
            $result = $this->client->post("nodes/{$node}/qemu/{$vmid}/config", $netConfig);

            return [
                'success' => true,
                'config' => $netConfig,
                'response' => $result
            ];

        } catch (Exception $e) {
            throw new Exception($this->safeErrorMessage($e, 'Failed to configure network'), previous: $e);
        }
    }

    /**
     * @throws Exception
     */
    public function setVMPassword(string $node, int $vmid, #[\SensitiveParameter] string $password, string $user = 'root')
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("/nodes/{$node}/qemu/{$vmid}/config", [
            'ciuser' => $user,
            'cipassword' => $password
        ]);

        // LPX-004: Proxmox returns {"data": null} on success here.
        $ok = ResponseHelper::hasData($response);

        return ResponseHelper::generate(
            $ok,
            $ok ? 'SSH credentials injected successfully' : 'SSH credentials failed to inject!',
            $response['data'] ?? null
        );
    }

    /**
     * Get the next available VMID
     *
     * @return int
     * @throws Exception
     */
    private function getNextVMID(): int
    {
        $response = $this->client->get('cluster/nextid');

        if (!isset($response['data'])) {
            throw new Exception('Failed to get next VMID');
        }

        return (int)$response['data'];
    }

    /**
     * Create a VM from template
     *
     * @param string $node Node name
     * @param int $templateId Template VMID to clone from
     * @param array $params Clone configuration parameters
     * @throws Exception
     */
    public function cloneVM(string $node, int $templateId, array $params)
    {
        if (!isset($params['newid'])) {
            $params['newid'] = $this->getNextVMID();
        }

        // Set default values
        $defaults = [
            'full' => 1,  // Full clone (not linked)
        ];

        $params = array_merge($defaults, $params);

        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$templateId}/clone", $params);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Failed to create VM!');
        }

        $successResponse = [
            'node' => $node,
            'vmid' => $params['newid'],
            'data' => $response['data']
        ];

        return ResponseHelper::generate(true, 'VM Created successfully', $successResponse);
    }

    /**
     * Set VM configuration
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @param array $params Configuration parameters
     * @return array
     * @throws Exception
     */
    public function setVMConfig(string $node, int $vmid, array $params): array
    {
        $this->validateSegment($node, 'node');
        return $this->client->post("nodes/{$node}/qemu/{$vmid}/config", $params);
    }

    /**
     * Attach disk to VM
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @param array $params Disk parameters
     * @throws Exception
     */
    public function attachDisk(string $node, int $vmid, array $params)
    {
        // Validate required parameters
        if (!isset($params['storage']) || !isset($params['size'])) {
            return ResponseHelper::generate(false, 'Storage and size parameters are required');
        }

        $this->validateSegment($node, 'node');
        try {
            // Get current VM configuration
            $config = $this->client->get("nodes/{$node}/qemu/{$vmid}/config");

            // Find next available SCSI disk ID
            $nextId = 0;
            foreach ($config['data'] as $key => $value) {
                if (preg_match('/^scsi(\d+)$/', $key, $matches)) {
                    $nextId = max($nextId, (int)$matches[1] + 1);
                }
            }

            // Prepare disk parameters - Fixed format
//            $size = preg_match('/^\d+G$/', $params['size']) ? $params['size'] : "{$params['size']}";
            $size = preg_replace('/\D/', '', $params['size']);;

            // Base disk specification - Note the "volume=0" format
            $diskParams = [
                "scsi{$nextId}" => "{$params['storage']}:{$size}"
            ];

            // Add optional parameters
            $optionalParams = '';
            if (isset($params['format'])) {
                $optionalParams .= ",format={$params['format']}";
            }
            if (isset($params['cache'])) {
                $optionalParams .= ",cache={$params['cache']}";
            }
            if (isset($params['iothread'])) {
                $optionalParams .= ",iothread={$params['iothread']}";
            }

            // Append optional parameters if any exist
            if (!empty($optionalParams)) {
                $diskParams["scsi{$nextId}"] .= $optionalParams;
                $diskParams["net0"] = 'virtio,bridge=vmbr0,firewall=1';

                $diskParams['boot'] = "order=scsi{$nextId};net0";
//                $diskParams['boot'] = "order=ide2;scsi{$nextId};net0";
            }

            // Apply configuration
            $result = $this->client->post("nodes/{$node}/qemu/{$vmid}/config", $diskParams);

            if (!ResponseHelper::hasData($result)) {
                return ResponseHelper::generate(false, "Failed to attach disk: No response data received");
            }

            $successResponse = [
                'disk_id' => "scsi{$nextId}",
                'config' => $diskParams,
                'data' => $result['data']
            ];

            return ResponseHelper::generate(true, 'Disk attach success', $successResponse);

        } catch (Exception $e) {
            return ResponseHelper::generate(false, $this->safeErrorMessage($e, 'Failed to attach disk'));
        }
    }

    /**
     * @throws Exception
     */
    public function detachDisk(string $node, int $vmid, string $disk, bool $type = false)
    {
        $this->validateSegment($node, 'node');
        try {
            // API endpoint to remove a disk
            $result = $this->client->post("nodes/{$node}/qemu/{$vmid}/config", [
                'delete' => $disk, // Specify the disk to delete (e.g., 'scsi0')
                'force' => $type
            ]);

            if (!ResponseHelper::hasData($result)) {
                return ResponseHelper::generate(false, "Failed to detach disk");
            }

            $successResponse = [
                'node' => $node,
                'vmid' => $vmid,
                'disk' => $disk,
                'data' => $result['data']
            ];

            return ResponseHelper::generate(true, 'Disk attach success', $successResponse);
        } catch (Exception $e) {
            return ResponseHelper::generate(false, $this->safeErrorMessage($e, 'Failed to detach disk'));
        }
    }

    /**
     * Generate SSH Key Pair
     *
     * SAST-001 remediation: key material is generated entirely in-process
     * via ext-openssl (no shell exec, no OS-command sink). The private key
     * is written, passphrase-encrypted, under a fixed storage root that is
     * never influenced by caller input (CWE-73/CWE-78 fix); the private key
     * content is never included in the response envelope (CWE-522); the
     * encryption passphrase is caller-supplied or, when omitted, a fresh
     * cryptographically random value (CWE-321/CWE-798 fix); every OpenSSL
     * operation's result is checked and failures raise an Exception.
     *
     * @param  string|null  $name        Basename for the key files (sanitised). A random
     *                                   name is generated when omitted. If a key pair with
     *                                   the sanitised name already exists, an Exception is
     *                                   thrown; existing keys are never overwritten (LPX-005).
     * @param  string|null  $passphrase  Passphrase used to encrypt the private key. A
     *                                   cryptographically random passphrase is generated
     *                                   and returned when omitted.
     * @return array{private_key_path:string,public_key_path:string,public_key:string,passphrase_generated:bool,passphrase?:string}
     * @throws Exception
     */
    public function generateSSHKey(?string $name = null, ?string $passphrase = null): array
    {
        $safeName = $name !== null ? preg_replace('/[^a-z0-9]+/i', '_', strtolower($name)) : '';
        if ($safeName === '') {
            $safeName = 'key_' . bin2hex(random_bytes(8));
        }

        $storageRoot = $this->sshKeyStorageRoot();
        if (!is_dir($storageRoot) && !mkdir($storageRoot, 0700, true) && !is_dir($storageRoot)) {
            throw new Exception("Unable to create SSH key storage directory: {$storageRoot}");
        }
        $this->assertSafeKeyStorageRoot($storageRoot);

        $privateKeyPath = $storageRoot . DIRECTORY_SEPARATOR . $safeName;
        $publicKeyPath  = $privateKeyPath . '.pub';

        // LPX-005 (CWE-73): distinct names can sanitise to the same basename
        // (e.g. "web 1" / "web-1"), and a repeated name maps to the same path.
        // Fail closed instead of silently replacing an existing key pair.
        // (Exclusive creation in writeNewKeyFile() closes the race window.)
        foreach ([$privateKeyPath, $publicKeyPath] as $path) {
            if (file_exists($path) || is_link($path)) {
                throw new Exception(
                    "SSH key '{$safeName}' already exists; refusing to overwrite an existing key pair. Choose a different name."
                );
            }
        }

        $passphraseGenerated = $passphrase === null;
        $effectivePassphrase = $passphrase ?? base64_encode(random_bytes(24));

        $resource = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if ($resource === false) {
            throw new Exception('Failed to generate SSH key pair: ' . $this->opensslErrorSummary());
        }

        $exported = openssl_pkey_export($resource, $privateKeyPem, $effectivePassphrase);

        if ($exported === false || !is_string($privateKeyPem) || $privateKeyPem === '') {
            throw new Exception('Failed to export SSH private key: ' . $this->opensslErrorSummary());
        }

        $details = openssl_pkey_get_details($resource);

        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new Exception('Failed to derive SSH public key: ' . $this->opensslErrorSummary());
        }

        $publicKeyLine = $this->encodeOpenSshRsaPublicKey($details['rsa']['n'], $details['rsa']['e'], $safeName);

        $this->writeNewKeyFile($privateKeyPath, $privateKeyPem, 0600, $safeName);

        try {
            $this->writeNewKeyFile($publicKeyPath, $publicKeyLine . PHP_EOL, 0644, $safeName);
        } catch (Exception $e) {
            // Never leave a half-written pair behind; the private key file
            // was created by this call, so removing it is safe.
            @unlink($privateKeyPath);
            throw $e;
        }

        $response = [
            'private_key_path'     => $privateKeyPath,
            'public_key_path'      => $publicKeyPath,
            'public_key'           => $publicKeyLine,
            'passphrase_generated' => $passphraseGenerated,
        ];

        // The private key itself is never returned. The passphrase is only
        // surfaced when we generated it (the caller cannot otherwise learn
        // it); a caller-supplied passphrase is already known to the caller.
        if ($passphraseGenerated) {
            $response['passphrase'] = $effectivePassphrase;
        }

        return ResponseHelper::generate(true, 'SSH key generated successfully', $response);
    }

    /**
     * Fixed, non-caller-controlled storage root for generated SSH key material.
     *
     * Prefers the host Laravel app's storage path when a booted application
     * container is available; falls back to the system temp dir so the
     * method also works outside a booted Laravel app (e.g. plain PHPUnit).
     * Never derived from caller input.
     */
    private function sshKeyStorageRoot(): string
    {
        if (function_exists('app')) {
            try {
                $app = app();
                if ($app instanceof \Illuminate\Contracts\Foundation\Application) {
                    return rtrim($app->storagePath(), '/') . '/app/proxmox-ssh-keys';
                }
            } catch (\Throwable) {
                // No booted container available — fall through to the temp-dir default.
            }
        }

        return rtrim(sys_get_temp_dir(), '/') . '/proxmox-ssh-keys';
    }

    /**
     * LPX-005: refuse to write key material into a storage root that is a
     * symlink, is not owned by the current user, or is group/world-writable
     * (any of which would let another principal swap or pre-plant files).
     *
     * @throws Exception
     */
    private function assertSafeKeyStorageRoot(string $storageRoot): void
    {
        clearstatcache(true, $storageRoot);

        if (is_link($storageRoot) || !is_dir($storageRoot)) {
            throw new Exception('SSH key storage directory is not a real directory; refusing to write key material.');
        }

        if (function_exists('posix_geteuid') && fileowner($storageRoot) !== posix_geteuid()) {
            throw new Exception('SSH key storage directory is not owned by the current user; refusing to write key material.');
        }

        if ((fileperms($storageRoot) & 0022) !== 0) {
            throw new Exception('SSH key storage directory is group/world-writable; refusing to write key material.');
        }
    }

    /**
     * LPX-005: create $path exclusively (O_CREAT|O_EXCL via fopen 'x', which
     * also refuses an existing or dangling symlink) and write $contents.
     * Never truncates an existing file.
     *
     * @throws Exception
     */
    private function writeNewKeyFile(string $path, string $contents, int $mode, string $keyName): void
    {
        $handle = @fopen($path, 'xb');
        if ($handle === false) {
            throw new Exception(
                "SSH key '{$keyName}' already exists or cannot be created; refusing to overwrite an existing key pair."
            );
        }

        try {
            if (!chmod($path, $mode)) {
                throw new Exception("Failed to set permissions on SSH key file for '{$keyName}'.");
            }
            if (fwrite($handle, $contents) !== strlen($contents) || !fflush($handle)) {
                throw new Exception("Failed to write SSH key file for '{$keyName}'.");
            }
        } catch (Exception $e) {
            fclose($handle);
            @unlink($path);
            throw $e;
        }

        fclose($handle);
    }

    private function opensslErrorSummary(): string
    {
        $messages = [];
        while ($msg = openssl_error_string()) {
            $messages[] = $msg;
        }
        return $messages === [] ? 'unknown OpenSSL error' : implode('; ', $messages);
    }

    /**
     * Encode an RSA public key (raw modulus/exponent from openssl_pkey_get_details)
     * into OpenSSH authorized_keys wire format: "ssh-rsa <base64> [comment]".
     */
    private function encodeOpenSshRsaPublicKey(string $modulus, string $exponent, string $comment = ''): string
    {
        $blob = $this->sshString('ssh-rsa') . $this->sshMpint($exponent) . $this->sshMpint($modulus);
        $encoded = 'ssh-rsa ' . base64_encode($blob);

        return $comment !== '' ? "{$encoded} {$comment}" : $encoded;
    }

    private function sshString(string $value): string
    {
        return pack('N', strlen($value)) . $value;
    }

    /**
     * Encode a raw big-endian unsigned integer as an SSH "mpint": a length
     * prefix followed by the bytes, with a leading 0x00 inserted when the
     * high bit of the first byte is set (so it is not misread as negative).
     */
    private function sshMpint(string $binary): string
    {
        if ($binary !== '' && (ord($binary[0]) & 0x80) !== 0) {
            $binary = "\x00" . $binary;
        }

        return $this->sshString($binary);
    }

    /**
     * Attach SSH Key to VM Cloud-Init Configuration
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @param string $publicKey SSH public key content
     * @return array
     * @throws Exception
     */
    public function attachSSHKey(string $node, int $vmid, string $publicKey): array
    {
        $this->validateSegment($node, 'node');
        // First check if VM exists and uses cloud-init
        $vmConfig = $this->client->get("nodes/{$node}/qemu/{$vmid}/config");

        if (!isset($vmConfig['data'])) {
            throw new Exception("VM {$vmid} not found on node {$node}");
        }


        // Clean up the public key
        $publicKey = trim($publicKey);

        // Set SSH key in cloud-init config
        return $this->setVMConfig($node, $vmid, [
            'sshkeys' => $publicKey
        ]);
    }

    /**
     * Create Ubuntu VM with SSH Key
     *
     * @param string $node Node name
     * @param array $params VM configuration parameters
     * @param string|null $sshKey SSH public key content
     * @return array
     * @throws Exception
     */
    public function createUbuntuVMWithSSH(
        string  $node,
        array   $params,
        ?string $sshKey = null
    ): array
    {
        // Generate new SSH key if none provided
        if ($sshKey === null) {
            // LPX-005: generateSSHKey() now refuses to overwrite an existing
            // key pair, so the auto-generated name gets a server-controlled
            // random suffix — re-provisioning a VM with a reused name must
            // neither clobber the earlier VM's keys nor fail.
            $keyName = ($params['name'] ?? 'vm') . '-' . bin2hex(random_bytes(4));
            $sshKeyPair = $this->generateSSHKey($keyName);

            if (!($sshKeyPair['success'] ?? false) || !isset($sshKeyPair['data']['public_key'])) {
                throw new Exception('Failed to generate SSH key for VM: ' . ($sshKeyPair['message'] ?? 'unknown error'));
            }

            $sshKey = $sshKeyPair['data']['public_key'];
        }

        // Add cloud-init specific defaults
        $cloudInitDefaults = [
            'ostype' => 'other',
            'cores' => 2,
            'memory' => 2048,
            'cpu' => 'host',
            'agent' => 1,
            'bios' => 'ovmf',
            'net0' => 'virtio,bridge=vmbr0',
            'cicustom' => 'user=local:snippets/cloud-init-user.yml',
            'ipconfig0' => 'ip=dhcp',
            'sshkeys' => urlencode($sshKey)
        ];

        $params = array_merge($cloudInitDefaults, $params);

        // Create VM
        $result = $this->createVM($node, $params);

        return array_merge($result, [
            'ssh_key' => $sshKey
        ]);
    }

    public function configureVMCloudInitNetwork(string $node, int $vmid, $ip, $gateway, $netmask)
    {
        $this->validateSegment($node, 'node');

        $params = [
            "ipconfig0" => "ip={$ip}/{$netmask},gw={$gateway}"
        ];

        $response = $this->client->put("nodes/{$node}/qemu/{$vmid}/config", $params);

        // SAST-007 (CWE-393): the previous `!isset($response['data'])` predicate
        // reported success when the response carried NO data and failure when
        // it DID — the exact opposite of every other call site in this class
        // (e.g. deleteStorage()). Normalised to array_key_exists() so presence
        // of the 'data' key (even null, which Proxmox returns for this
        // endpoint on success) is what signals success.
        if (array_key_exists('data', $response)) {
            $successResponse = [
                'node' => $node,
                'vmid' => $vmid,
                'public_ip' => $ip,
                'netmask' => $netmask,
                'gateway' => $gateway,
            ];
            return ResponseHelper::generate(true, 'Network configured successfully', $successResponse);
        }
        return ResponseHelper::generate(false, 'Network configure fail!', $response['data'] ?? null);
    }

    /**
     * @throws Exception
     */
    public function updateVmConfig(string $node, int $vmid, $params)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/{$node}/qemu/{$vmid}/config", $params);

        if (!ResponseHelper::hasData($response)) {
            $successResponse = [
                'node' => $node,
                'vmid' => $vmid,
            ];
            return ResponseHelper::generate(true, 'Config updated successfully', $successResponse);
        }
        return ResponseHelper::generate(false, 'Config update failed!', $response['data']);
    }

    /**
     * @throws Exception
     */
    public function resizeVm(string $node, int $vmid, $params)
    {
        // Disk resize parameters
        $resizeParams = [
            'disk' => 'scsi0', // Disk you want to resize (e.g., scsi0, virtio0)
            'size' => '+10G',  // Size to add (e.g., +10G for 10GB)
        ];
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/config", $params);

        if (!ResponseHelper::hasData($response)) {
            $successResponse = [
                'node' => $node,
                'vmid' => $vmid,
            ];
            return ResponseHelper::generate(true, 'Config updated successfully', $successResponse);
        }
        return ResponseHelper::generate(false, 'Config update failed!', $response['data']);
    }

    /**
     * @throws Exception
     */
    public function fetchAvailableIPs($node)
    {
//        $params = ['type' => 'bridge'];
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/{$node}/network");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Network list fail!', $response['data']);
        }
        return ResponseHelper::generate(true, 'Network list', $response['data']);
    }


    public function applyCloudInitVM(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        return $this->client->post("nodes/{$node}/qemu/{$vmid}/cloudinit");
    }

    /**
     * Destroy the vm (also delete all used/owned volumes)
     * DELETE /api2/json/nodes/{node}/qemu/{vmid}
     * @param string $node The cluster node name.
     * @param integer $vmid The (unique) ID of the VM.
     * @param array $data
     */
    public function destroyVm(string $node, int $vmid, $data = array())
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->delete("nodes/$node/qemu/$vmid", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Destroy the vm fail!', $response['data']);
        }
        return ResponseHelper::generate(true, 'Destroyed the vm', $response['data']);
    }

    /**
     * Delete a Virtual Machine
     *
     * @param string $node Node name
     * @param int $vmid VM ID
     * @param bool $force Force delete even if running (will stop VM first)
     * @param bool $purge Remove VM disk
     * @throws Exception
     */
    public function deleteVM(string $node, int $vmid, bool $force = false, bool $purge = true)
    {
        $this->validateSegment($node, 'node');
        // Check if VM exists
        $vmStatus = $this->client->get("nodes/{$node}/qemu/{$vmid}/status/current");

        if (!isset($vmStatus['data'])) {
            throw new Exception("VM {$vmid} not found on node {$node}");
        }

        // If VM is running and force is true, stop it first
        if ($vmStatus['data']['status'] === 'running') {
            if (!$force) {
                throw new Exception("Cannot delete running VM. Either stop the VM first or use force option.");
            }

            // Stop the VM
            $this->stopVM($node, $vmid);

            // Wait for VM to stop (max 30 seconds)
            $timeout = 30;
            $start = time();
            do {
                sleep(2);
                $currentStatus = $this->client->get("nodes/{$node}/qemu/{$vmid}/status/current");
                if ($currentStatus['data']['status'] === 'stopped') {
                    break;
                }
            } while (time() - $start < $timeout);

            // Check if VM actually stopped
            if ($currentStatus['data']['status'] !== 'stopped') {
                throw new Exception("Failed to stop VM {$vmid} within timeout period");
            }
        }

        // Delete the VM
        $params = [];
        if ($purge) {
            $params['purge'] = 1; // Also remove disk
            $params['destroy-unreferenced-disks'] = 1; // Remove unreferenced disks
        }

        try {
            $response = $this->client->delete("nodes/$node/qemu/$vmid", $params);

            if (!ResponseHelper::hasData($response)) {
                return ResponseHelper::generate(false, "Failed to delete VM {$vmid}");
            }

            $successResponse = [
                'data' => $response['data'],
                'node' => $node,
                'vmid' => $vmid,
            ];
            return ResponseHelper::generate(true, 'VM Deleted successfully', $successResponse);
        } catch (Exception $e) {
            return ResponseHelper::generate(false, $this->safeErrorMessage($e, "Failed to delete VM {$vmid}"));
        }
    }

    /**
     * Delete multiple Virtual Machines
     *
     * @param string $node Node name
     * @param array $vmids Array of VM IDs
     * @param bool $force Force delete even if running
     * @param bool $purge Remove VM disks
     * @return array
     */
    public function deleteMultipleVMs(string $node, array $vmids, bool $force = false, bool $purge = true): array
    {
        $results = [];
        $errors = [];

        foreach ($vmids as $vmid) {
            try {
                $results[$vmid] = $this->deleteVM($node, $vmid, $force, $purge);
            } catch (Exception $e) {
                $errors[$vmid] = $this->safeErrorMessage($e, "Failed to delete VM {$vmid}");
            }
        }

        return [
            'success' => $results,
            'errors' => $errors
        ];
    }

    public function updateCredential(string $node, int $vmid, $payload)
    {
        $params = [
            'cipassword' => $payload['password']
        ];

        $this->validateSegment($node, 'node');
        try {
            $response = $this->client->post("/nodes/{$node}/qemu/{$vmid}/config", $params);

            if (!ResponseHelper::hasData($response)) {
                return ResponseHelper::generate(false, 'Failed to Update VM Credential Password!');
            }

            $successResponse = [
                'data' => $response['data'],
                'node' => $node,
                'vmid' => $vmid,
            ];

            return ResponseHelper::generate(true, 'VM Credential Password Updated successfully', $successResponse);
        } catch (\Exception $e) {
            return ResponseHelper::generate(false, $this->safeErrorMessage($e, "Failed to Update VM Credential Password {$vmid}"));
        }
    }

    public function injectSSHCredentials(string $node, int $vmid, $username, $password, $sshKey = null)
    {
        $payload = [
            'ciuser' => $username,
            'cipassword' => $password
        ];

        if ($sshKey) {
            $payload['sshkeys'] = $sshKey;
        }

        $this->validateSegment($node, 'node');
        $url = "/nodes/{$node}/qemu/{$vmid}/config";
        return $this->client->post($url, $payload);
    }

    public function rebuildCloudInit(string $node, int $vmid)
    {
        $this->validateSegment($node, 'node');
        $url = "/nodes/{$node}/qemu/{$vmid}/cloudinit";
        return $this->client->post($url);
    }

    /**
     * Node index.
     * @throws Exception
     */
    public function diskList(string $node)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/{$node}/disks");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Disk list failed!', $response['data']);
        }

        $successResponse = [
            'node' => $node,
            'data' => $response['data']
        ];

        return ResponseHelper::generate(true, 'Disk list successfully', $successResponse);
    }

    /**
     * PVE Managed storages..
     * $type directory, lvm, lvmthin, zfs,
     * @throws Exception
     */
    public function diskTypeList(string $node, string $type)
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($type, 'type');
        $response = $this->client->get("nodes/{$node}/disks/{$type}");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Disk fetch failed!', $response['data']);
        }

        $successResponse = [
            'node' => $node,
            'data' => $response['data']
        ];

        return ResponseHelper::generate(true, 'Disk fetch successfully', $successResponse);
    }

    /**
     * PVE Managed storages..
     * $type directory, lvm, lvmthin, zfs,
     * @throws Exception
     */
    public function createDiskType(string $node, string $type, array $params)
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($type, 'type');
        $response = $this->client->post("nodes/{$node}/disks/{$type}", $params);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Disk fetch failed!', $response['data']);
        }

        $successResponse = [
            'node' => $node,
            'data' => $response['data']
        ];

        return ResponseHelper::generate(true, 'Disk fetch successfully', $successResponse);
    }

    /**
     * PVE Managed storages..
     * $type directory, lvm, lvmthin, zfs,
     * @throws Exception
     */
    public function deleteDiskType(string $node, string $type, $name)
    {
        $this->validateSegment($node, 'node');
        $this->validateSegment($type, 'type');
        $this->validateSegment($name, 'name');
        $response = $this->client->delete("nodes/{$node}/disks/{$type}/{$name}");

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Disk delete failed!', $response['data']);
        }

        $successResponse = [
            'node' => $node,
            'data' => $response['data']
        ];

        return ResponseHelper::generate(true, 'Disk deleted successfully', $successResponse);
    }

    /**
     * QEMU monitor commands...
     * @throws Exception
     */
    public function vmMonitor(string $node, int $vmid, $params)
    {
        $params = ['command' => 'info'];
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/{$node}/qemu/{$vmid}/monitor", $params);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Failed to fetch monitoring data!', $response['data']);
        }

        $successResponse = [
            'node' => $node,
            'data' => $response['data']
        ];

        return ResponseHelper::generate(true, 'Data retrieved successfully', $successResponse);
    }

    /**
     * QEMU VM  RRDdata (Round Robin Database data)...
     * @throws Exception
     */
    public function vmRrddata(string $node, int $vmid, $params)
    {
        $this->validateSegment($node, 'node');
        try {
            // Fixed URL by removing extra curly brace
            $response = $this->client->get("nodes/{$node}/qemu/{$vmid}/rrddata", $params);

            if (!isset($response['data'])) {
                return ResponseHelper::generate(
                    false,
                    'No monitoring data available',
                    []
                );
            }

            $successResponse = [
                'node' => $node,
                'vmid' => $vmid,
                'data' => array_map(function ($entry) {
                    return [
                        'time' => isset($entry['time']) ? date('Y-m-d H:i:s', $entry['time']) : null,
                        'cpu' => $entry['cpu'] ?? null,
                        'mem' => $entry['mem'] ?? null,
                        'netin' => $entry['netin'] ?? null,
                        'netout' => $entry['netout'] ?? null,
                        'diskread' => $entry['diskread'] ?? null,
                        'diskwrite' => $entry['diskwrite'] ?? null
                    ];
                }, $response['data'])
            ];

            return ResponseHelper::generate(true, 'Data retrieved successfully', $successResponse);

        } catch (Exception $e) {
            return ResponseHelper::generate(
                false,
                $this->safeErrorMessage($e, 'Failed to fetch monitoring data'),
                []
            );
        }
    }

    public function getVMMetrics(string $node, int $vmid, $params)
    {
        $this->validateSegment($node, 'node');
        try {
            $response = $this->client->get("nodes/{$node}/qemu/{$vmid}/rrddata", $params);

            if (!isset($response['data']) || empty($response['data'])) {
                return ResponseHelper::generate(false, 'No metrics data available', []);
            }

            // Process and format the metrics
            $formattedMetrics = array_map(function ($entry) {
                return [
                    'timestamp' => date('Y-m-d H:i:s', $entry['time']),

                    // CPU Metrics
                    'cpu' => [
                        'usage_percentage' => isset($entry['cpu']) ? round($entry['cpu'] * 100, 2) : null,
                    ],

                    // Memory Metrics
                    'memory' => [
                        'used_bytes' => $entry['mem'] ?? null,
                        'used_gb' => isset($entry['mem']) ? round($entry['mem'] / (1024 * 1024 * 1024), 2) : null,
                        'total_bytes' => $entry['maxmem'] ?? null,
                        'total_gb' => isset($entry['maxmem']) ? round($entry['maxmem'] / (1024 * 1024 * 1024), 2) : null,
                    ],

                    // Network Metrics
                    'network' => [
                        'in_bytes' => $entry['netin'] ?? null,
                        'in_mb' => isset($entry['netin']) ? round($entry['netin'] / (1024 * 1024), 2) : null,
                        'out_bytes' => $entry['netout'] ?? null,
                        'out_mb' => isset($entry['netout']) ? round($entry['netout'] / (1024 * 1024), 2) : null,
                    ],

                    // Disk I/O Metrics
                    'disk' => [
                        'read_bytes' => $entry['diskread'] ?? null,
                        'read_mb' => isset($entry['diskread']) ? round($entry['diskread'] / (1024 * 1024), 2) : null,
                        'write_bytes' => $entry['diskwrite'] ?? null,
                        'write_mb' => isset($entry['diskwrite']) ? round($entry['diskwrite'] / (1024 * 1024), 2) : null,
                    ]
                ];
            }, $response['data']);

            $successResponse = [
                'node' => $node,
                'vmid' => $vmid,
                'metrics' => $formattedMetrics,
                'summary' => [
                    'latest_cpu_usage' => end($formattedMetrics)['cpu']['usage_percentage'] ?? null,
                    'latest_memory_used_gb' => end($formattedMetrics)['memory']['used_gb'] ?? null,
                    'latest_network_in_mb' => end($formattedMetrics)['network']['in_mb'] ?? null,
                    'latest_network_out_mb' => end($formattedMetrics)['network']['out_mb'] ?? null,
                ]
            ];

            return ResponseHelper::generate(true, 'Metrics retrieved successfully', $successResponse);

        } catch (Exception $e) {
            return ResponseHelper::generate(
                false,
                $this->safeErrorMessage($e, 'Failed to fetch metrics'),
                []
            );
        }
    }

    /**
     * Get list of appliances.
     * GET /api2/json/nodes/{node}/aplinfo
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function aplinfo($node)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/aplinfo");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'aplinfo fetch failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Aplinfo retrieved successfully', $response);
    }

    /**
     * Download appliance templates.
     * POST /api2/json/nodes/{node}/aplinfo
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function downloadTemplate($node, $data = array())
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/aplinfo", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'aplinfo fetch failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Aplinfo retrieved successfully', $response);
    }

    /**
     * Get list of appliances.
     * GET /api2/json/nodes/{node}/dns
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function dns($node)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/dns");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'dns fetch failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'dns retrieved successfully', $response);
    }

    /**
     * Write DNS settings.
     * PUT /api2/json/nodes/{node}/dns
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function setDns($node, $data = array())
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/dns", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'set Dns failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'setDns successfully', $response);
    }

    /**
     * Execute multiple commands in order
     * POST /api2/json/nodes/{node}/execute
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function execute($node, $data = array())
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/execute", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Execute failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Execute successfully', $response);
    }

    /**
     * Migrate all VMs and Containers
     * POST /api2/json/nodes/{node}/migrateall
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function migrateAll($node, array $data)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/migrateall", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Migrate failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Migrate successfully', $response);
    }

    /**
     * Read tap/vm network device interface counters
     * GET /api2/json/nodes/{node}/netstat
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function netstat($node)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/netstat");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'netstat failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'netstat successfully', $response);
    }

    /**
     * Gather various systems information about a node
     * GET /api2/json/nodes/{node}/report
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function report($node)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/report");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'report failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'report successfully', $response);
    }

    /**
     * Read node RRD statistics (returns PNG)
     * GET /api2/json/nodes/{node}/rrd
     * @param string $node The cluster node name.
     * @param string $ds The list of datasources you want to display.
     * @param enum $timeframe Specify the time frame you are interested in.
     * @throws Exception
     */
    public function rrd(string $node, $ds = null, $timeframe = null)
    {
        $this->validateSegment($node, 'node');
        $optional['ds'] = !empty($ds) ? $ds : null;
        $optional['timeframe'] = !empty($timeframe) ? $timeframe : null;
        $response = $this->client->get("nodes/$node/rrd", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'RRD statistics failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'RRD statistics successfully', $response);
    }

    /**
     * Read node RRD statistics
     * GET /api2/json/nodes/{node}/rrddata
     * @param string $node The cluster node name.
     * @param enum $timeframe Specify the time frame you are interested in.
     * @throws Exception
     */
    public function rrddata($node, $timeframe = null)
    {
        $this->validateSegment($node, 'node');
        $optional['timeframe'] = !empty($timeframe) ? $timeframe : null;
        $response = $this->client->get("nodes/$node/rrddata", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'rrddata statistics failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'rrddata statistics successfully', $response);
    }

    /**
     * Creates a SPICE shell
     * POST /api2/json/nodes/{node}/spiceshell
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function spiceShell($node, $data = array())
    {
        $this->validateSegment($node, 'node');
        // LPX-007: spiceshell is a side-effecting POST in the Proxmox API.
        $response = $this->client->post("nodes/$node/spiceshell", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'SPICE shell failed!');
        }

        return ResponseHelper::generate(true, 'SPICE shell successfully', $response);
    }

    /**
     * Start all VMs and containers (when onboot=1)
     * POST /api2/json/nodes/{node}/startall
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function startAll($node, $data = array())
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/startall", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Start all VMs failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Start all VMs successfully', $response);
    }

    /**
     * Reboot or shutdown a node
     * POST /api2/json/nodes/{node}/status
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function reboot(string $node, array $data)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/status", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Reboot node failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Reboot node successfully', $response);
    }

    /**
     * Stop all VMs and Containers.
     * POST /api2/json/nodes/{node}/stopall
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function stopAll(string $node, array $data)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/stopall", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Reboot node failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Stop node successfully', $response);
    }

    /**
     * Read subscription info.
     * GET /api2/json/nodes/{node}/subscription
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function subscription(string $node)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/subscription");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'subscription node failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'subscription node successfully', $response);
    }

    /**
     * update subscription info.
     * POST /api2/json/nodes/{node}/subscription
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function updateSubscription(string $node, array $data)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/subscription", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'subscription update failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'subscription update successfully', $response);
    }

    /**
     * Set subscription key.
     * PUT /api2/json/nodes/{node}/subscription
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function setSubscription(string $node, array $data)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/subscription", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Set subscription failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Set subscription successfully', $response);
    }

    /**
     * Read system log
     * GET /api2/json/nodes/{node}/syslog
     * @param string $node The cluster node name.
     * @param integer|null $limit
     * @param integer $start
     * @param string $since Display all log since this date-time string.
     * @param string $until Display all log until this date-time string.
     * @throws Exception
     */
    public function syslog(string $node, ?int $limit = null, $start = null, $since = null, $until = null)
    {
        $optional['limit'] = !empty($limit) ? $limit : 50;
        $optional['start'] = !empty($start) ? $start : null;
        $optional['since'] = !empty($since) ? $since : null;
        $optional['until'] = !empty($until) ? $until : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/syslog", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read system log failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Read system log successfully', $response);
    }

    /**
     * Read server time and time zone settings.
     * GET /api2/json/nodes/{node}/time
     * @param string $node The cluster node name.
     * @throws Exception
     */
    public function time(string $node)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/time");

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Read server time failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Read server time successfully', $response);
    }

    /**
     * PUT time zone.
     * PUT /api2/json/nodes/{node}/time
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function setTime(string $node, array $data)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->put("nodes/$node/time", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'PUT time zone failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'PUT time zone successfully', $response);
    }

    /**
     * Creates a VNC Shell proxy.
     * POST /api2/json/nodes/{node}/vncshell
     * @param string $node The cluster node name.
     * @param array $data
     * @throws Exception
     */
    public function createVNCShell(string $node, array $data)
    {
        $this->validateSegment($node, 'node');
        $response = $this->client->post("nodes/$node/vncshell", $data);

        if (!ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(false, 'Creates a VNC Shell proxy failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Creates a VNC Shell proxy successfully', $response);
    }

    /**
     * Opens a weksocket for VNC traffic.
     * GET /api2/json/nodes/{node}/vncwebsocket
     * @param string $node The cluster node name.
     * @param integer|null $port Port number returned by previous vncproxy call.
     * @param string|null $vncticket Ticket from previous call to vncproxy.
     */
    public function vNCWebSocket(string $node, ?int $port = null, ?string $vncticket = null)
    {
        $optional['port'] = !empty($port) ? $port : null;
        $optional['vncticket'] = !empty($vncticket) ? $vncticket : null;

        $this->validateSegment($node, 'node');
        $response = $this->client->get("nodes/$node/vncwebsocket", $optional);

        if (!isset($response['data'])) {
            return ResponseHelper::generate(false, 'Opens a weksocket for VNC traffic failed!', $response['data']);
        }

        return ResponseHelper::generate(true, 'Opens a weksocket for VNC traffic successfully', $response);
    }
}
