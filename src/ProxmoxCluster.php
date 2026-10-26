<?php

namespace Cycoslave\Proxmox;

use Cycoslave\Proxmox\Support\ResponseHelper;
use Cycoslave\Proxmox\Traits\ValidatesPathSegments;

class ProxmoxCluster
{
    use ValidatesPathSegments;

    public function __construct(protected ProxmoxAccess $client) {}

    /**
     * @throws \Exception
     */
    public function cluster()
    {
        $response = $this->client->get('cluster');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster fail.');
        }

        return ResponseHelper::generate(true,'Cluster list', $response['data']);
    }

    /**
     * List vzdump backup schedule.
     * GET /api2/json/cluster/backup
     * @throws \Exception
     */
    public function listBackup()
    {
        $response = $this->client->get("cluster/backup");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster backup.');
        }

        return ResponseHelper::generate(true,'Cluster backup', $response['data']);
    }

    /**
     * Get cluster status
     * @throws \Exception
     */
    public function getClusterStatus()
    {
        $response = $this->client->get('cluster/status');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster status fail.');
        }

        return ResponseHelper::generate(true,'Cluster status', $response['data']);
    }

    /**
     * Get cluster resources
     * @throws \Exception
     */
    public function getClusterResources()
    {
        $response = $this->client->get('cluster/resources');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster resources fail.');
        }

        return ResponseHelper::generate(true,'Cluster resources', $response['data']);
    }

    /**
     * Get cluster tasks
     * @throws \Exception
     */
    public function getClusterTasks()
    {
        $response = $this->client->get('cluster/tasks');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster tasks fail.');
        }

        return ResponseHelper::generate(true,'Cluster tasks', $response['data']);
    }

    /**
     * Get cluster log
     * @throws \Exception
     */
    public function getClusterLog()
    {
        $response = $this->client->get('cluster/log');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster log fail.');
        }

        return ResponseHelper::generate(true,'Cluster log', $response['data']);
    }

    /**
     * Get cluster backup schedule
     * @throws \Exception
     */
    public function getBackupSchedule()
    {
        $response = $this->client->get('cluster/backup');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster backup schedule fail.');
        }

        return ResponseHelper::generate(true,'Cluster backup schedule', $response['data']);
    }

    /**
     * Create backup schedule
     * @throws \Exception
     */
    public function createBackup($data)
    {
        $response = $this->client->post('cluster/backup', $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster Create backup schedule fail.');
        }

        return ResponseHelper::generate(true,'Cluster Create backup schedule', $response['data']);
    }

    /**
     * Read vzdump backup job definition.
     * @param string $id The job ID.
     * @throws \Exception
     */
    public function backupId($id)
    {
        $this->validateSegment((string) $id, 'id');
        $response = $this->client->get("cluster/backup/$id");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster backup job fail.');
        }

        return ResponseHelper::generate(true,'Cluster backup job', $response['data']);
    }

    /**
     * Update vzdump backup job definition.
     * @param string $id The job ID.
     * @param array $data
     * @throws \Exception
     */
    public function updateBackup($id, array $data)
    {
        $this->validateSegment((string) $id, 'id');
        $response = $this->client->put("cluster/backup/$id", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster backup job create fail.');
        }

        return ResponseHelper::generate(true,'Cluster backup job created', $response['data']);
    }

    /**
     * Delete vzdump backup job definition.
     * @param string $id The job ID.
     * @throws \Exception
     */
    public function deleteBackup($id)
    {
        $this->validateSegment((string) $id, 'id');
        $response = $this->client->delete("cluster/backup/$id");

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster backup job delete fail.');
        }

        return ResponseHelper::generate(true,'Cluster backup job deleted', $response['data']);
    }

    /**
     * Read cluster config.
     * @throws \Exception
     */
    public function config()
    {
        $response = $this->client->get("cluster/config");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster config fail.');
        }

        return ResponseHelper::generate(true,'Cluster config', $response['data']);
    }

    /**
     * node list.
     * GET cluster config nodes
     * @throws \Exception
     */
    public function listConfigNodes()
    {
        $response = $this->client->get("cluster/config/nodes");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster node config fail.');
        }

        return ResponseHelper::generate(true,'Cluster node config', $response['data']);
    }

    /**
     * Get corosync totem protocol settings.
     * GET /api2/json/cluster/config/totem
     * @throws \Exception
     */
    public function configTotem()
    {
        $response = $this->client->get("cluster/config/totem");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster totem protocol settings fail.');
        }

        return ResponseHelper::generate(true,'Cluster totem protocol settings', $response['data']);
    }

    /**
     *  * Directory index.
     * Get cluster firewall settings
     * @throws \Exception
     */
    public function firewall()
    {
        $response = $this->client->get('cluster/firewall');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall', $response['data']);
    }

    /**
     * List aliases
     * @throws \Exception
     */
    public function firewallListAliases()
    {
        $response = $this->client->get('cluster/firewall/aliases');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall aliases fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall aliases', $response['data']);
    }

    /**
     * Create IP or Network Alias.
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function createFirewallAliase(array $data)
    {
        $response = $this->client->post('cluster/firewall/aliases', $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall Create fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall created', $response['data']);
    }

    /**
     * Read alias.
     * @param string $name Alias name.
     * @throws \Exception
     */
    public function getFirewallAliasesName($name)
    {
        $this->validateSegment((string) $name, 'name');
        $response = $this->client->get("cluster/firewall/aliases/$name");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall alias fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall alias', $response['data']);
    }

    /**
     * Update IP or Network alias.
     * @param string $name Alias name.
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function updateFirewallAliase($name, array $data)
    {
        $this->validateSegment((string) $name, 'name');
        $response = $this->client->put("cluster/firewall/aliases/$name", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall alias update fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall alias updated successfully', $response['data']);
    }

    /**
     * Update IP or Network alias.
     * @param string $name Alias name.
     * @throws \Exception
     */
    public function removeFirewallAliase($name)
    {
        $this->validateSegment((string) $name, 'name');
        $response = $this->client->delete("cluster/firewall/aliases/$name");

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall alias delete fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall alias deleted successfully', $response['data']);
    }

    /**
     * List security groups.
     * @throws \Exception
     */
    public function firewallListGroups()
    {
        $response = $this->client->get("cluster/firewall/groups");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall groups fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall groups', $response['data']);
    }

    /**
     * Create new security group.
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function createFirewallGroup(array $data)
    {
        // LPX-008 (CWE-628): the caller's group definition was never sent.
        $response = $this->client->post("cluster/firewall/groups", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall security group fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall security group', $response['data']);
    }

    /**
     * List rules
     * @param string $group Security Group name.
     * @throws \Exception
     */
    public function firewallGroupsGroup($group)
    {
        $this->validateSegment((string) $group, 'group');
        $response = $this->client->get("cluster/firewall/groups/$group");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall security group fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall security group', $response['data']);
    }

    /**
     * Create new rule.
     * @param string $group Security Group name.
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function createRuleFirewallGroup($group, array $data)
    {
        $this->validateSegment((string) $group, 'group');
        $response = $this->client->post("cluster/firewall/groups/$group", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall create fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall created', $response['data']);
    }

    /**
     * Delete security group.
     * @param string $group Security Group name.
     * @throws \Exception
     */
    public function removeFirewallGroup($group)
    {
        $this->validateSegment((string) $group, 'group');
        $response = $this->client->delete("cluster/firewall/groups/$group");

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall remove fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall removed successfully');
    }

    /**
     * Get single rule data.
     * @param string $group Security Group name.
     * @param integer $pos Update rule at position <pos>.
     * @throws \Exception
     */
    public function firewallGroupsGroupPos(string $group, int $pos)
    {
        $this->validateSegment((string) $group, 'group');
        $response = $this->client->get("cluster/firewall/groups/$group/$pos");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall group position fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall group position details', $response['data']);
    }

    /**
     * Modify rule data
     * @param string $group Security Group name.
     * @param integer $pos Update rule at position <pos>.
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function setFirewallGroupPos(string $group, int $pos, array $data)
    {
        $this->validateSegment((string) $group, 'group');
        $response = $this->client->put("cluster/firewall/groups/$group/$pos", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall group position update fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall group position updated', $response['data']);
    }

    /**
     * Delete rule.
     * @param string $group Security Group name.
     * @param integer $pos Update rule at position <pos>.
     * @throws \Exception
     */
    public function removeFirewallGroupPos(string $group, int $pos)
    {
        $this->validateSegment((string) $group, 'group');
        $response = $this->client->delete("cluster/firewall/groups/$group/$pos");

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall group position delete fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall group position deleted successfully');
    }

    /**
     * List IPSets
     * @throws \Exception
     */
    public function firewallListIpset()
    {
        $response = $this->client->get('cluster/firewall/ipset');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall ips fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall ips', $response['data']);
    }

    /**
     * Create new IPSet
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function createFirewallIpset(array $data)
    {
        $response = $this->client->post('cluster/firewall/ipset', $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall ip create fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall ip created successfully', $response['data']);
    }

    /**
     * List IPSet content
     * @param string $name IP set name.
     * @throws \Exception
     */
    public function firewallIpsetName($name)
    {
        $this->validateSegment((string) $name, 'name');
        $response = $this->client->get("cluster/firewall/ipset/$name");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall ip details fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall ip details', $response['data']);
    }

    /**
     * Add IP or Network to IPSet.
     * @param string $name IP set name.
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function addFirewallIpsetName($name, array $data)
    {
        $this->validateSegment((string) $name, 'name');
        $response = $this->client->post("cluster/firewall/ipset/$name", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall ip add fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall ip added successfully', $response['data']);
    }

    /**
     * Delete IPSet
     * @param string $name IP set name.
     * @throws \Exception
     */
    public function deleteFirewallIpsetName($name)
    {
        $this->validateSegment((string) $name, 'name');
        $response = $this->client->delete("cluster/firewall/ipset/$name");

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall ip delete fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall ip deleted successfully');
    }

    /**
     * List rules.
     * @throws \Exception
     */
    public function firewallListRules()
    {
        $response = $this->client->get("cluster/firewall/rules");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall list rules fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall list rules', $response['data']);
    }

    /**
     * Create new rule.
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function createFirewallRules(array $data)
    {
        $response = $this->client->post("cluster/firewall/rules", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall create rule fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall created rule successfully', $response['data']);
    }

    /**
     * Get single rule data.
     * @param integer $pos Update rule at position <pos>.
     * @throws \Exception
     */
    public function firewallRulesPos(int $pos): array
    {
        $response = $this->client->get("cluster/firewall/rules/$pos");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall Get single rule data fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall Get single rule data', $response['data']);
    }

    /**
     * Modify rule data.
     * PUT /api2/json/cluster/firewall/rules/{pos}
     * @param integer  $pos      Update rule at position <pos>.
     * @param array    $data
     */
    public function setFirewallRulesPos(int $pos, array $data = []): array
    {
        $response = $this->client->put("cluster/firewall/rules/$pos", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Modify rule data fail.');
        }

        return ResponseHelper::generate(true,'Modify rule data', $response['data']);
    }

    /**
     * Update cluster firewall settings
     * @throws \Exception
     */
    public function updateFirewallSettings($data)
    {
        $response = $this->client->put('cluster/firewall', $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall update fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall updated successfully', $response['data']);
    }



    /**
     * Delete rule.
     * @param integer $pos Update rule at position <pos>.
     * @throws \Exception
     */
    public function deleteFirewallRulesPos(int $pos)
    {
        $response = $this->client->delete("cluster/firewall/rules/$pos");

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall rule delete fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall rule deleted successfully');
    }

    /**
     * List available macros
     * @throws \Exception
     */
    public function firewallListMacros()
    {
        $response = $this->client->get("cluster/firewall/macros");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall macros fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall macros', $response['data']);
    }

    /**
     * Get Firewall options.
     * @throws \Exception
     */
    public function firewallListOptions()
    {
        $response = $this->client->get("cluster/firewall/options");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall options fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall options', $response['data']);
    }

    /**
     * Set Firewall options.
     * @param array $data
     * @throws \Exception
     */
    public function setFirewallOptions(array $data)
    {
        $response = $this->client->put("cluster/firewall/options", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster firewall options update fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall options updated', $response['data']);
    }

    /**
     * Lists possible IPSet/Alias reference which are allowed in source/dest properties.
     * @throws \Exception
     */
    public function firewallListRefs()
    {
        $response = $this->client->get("cluster/firewall/refs");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster firewall refs fail.');
        }

        return ResponseHelper::generate(true,'Cluster firewall refs', $response['data']);
    }

    /**
     * Get cluster HA resources
     * @throws \Exception
     */
    public function getHAResources()
    {
        $response = $this->client->get('cluster/ha/resources');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster HA resources fail.');
        }

        return ResponseHelper::generate(true,'Cluster HA resources', $response['data']);
    }

    /**
     * Get HA groups.
     * GET /api2/json/cluster/ha/groups
     * @throws \Exception
     */
    public function getHaGroups()
    {
        $response = $this->client->get("cluster/ha/groups");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster HA group fail.');
        }

        return ResponseHelper::generate(true,'Cluster HA group', $response['data']);
    }

    /**
     * Read ha group configuration.
     * @param string $group The HA group identifier.
     * @throws \Exception
     */
    public function haGroups($group)
    {
        $this->validateSegment((string) $group, 'group');
        $response = $this->client->get("cluster/ha/groups/$group");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster HA group fail.');
        }

        return ResponseHelper::generate(true,'Cluster HA group', $response['data']);
    }

    /**
     * List replication.
     * @throws \Exception
     */
    public function replication()
    {
        $response = $this->client->get("cluster/replication");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster replication fail.');
        }

        return ResponseHelper::generate(true,'Cluster replication', $response['data']);
    }

    /**
     * Create a new replication job
     * @param array $data
     * @throws \Exception
     */
    public function createReplication(array $data)
    {
        $response = $this->client->post("cluster/replication", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster replication create fail.');
        }

        return ResponseHelper::generate(true,'Cluster replication created successfully', $response['data']);
    }

    /**
     * Read replication job configuration.
     * @param string $id Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
     * @throws \Exception
     */
    public function replicationId($id)
    {
        $this->validateSegment((string) $id, 'id');
        $response = $this->client->get("cluster/replication/$id");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster replication details fail.');
        }

        return ResponseHelper::generate(true,'Cluster replication details', $response['data']);
    }

    /**
     * Update replication job configuration.
     * @param string $id Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
     * @param array $data
     * @throws \Exception
     */
    public function updateReplication($id, array $data)
    {
        $this->validateSegment((string) $id, 'id');
        $response = $this->client->put("cluster/replication/$id", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster replication update fail.');
        }

        return ResponseHelper::generate(true,'Cluster replication updated successfully', $response['data']);
    }

    /**
     * Mark replication job for removal.
     * @param string $id Replication Job ID. The ID is composed of a Guest ID and a job number, separated by a hyphen, i.e. '<GUEST>-<JOBNUM>'.
     * @throws \Exception
     */
    public function deleteReplication($id)
    {
        $this->validateSegment((string) $id, 'id');
        $response = $this->client->delete("cluster/replication/$id");

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster replication delete fail.');
        }

        return ResponseHelper::generate(true,'Cluster replication deleted successfully');
    }

    /**
     * Read cluster log
     * @param integer  $max     Maximum number of entries.
     */
    public function log($max = null)
    {
        $optional['max'] = !empty($max) ? $max : null;
        $response = $this->client->get("cluster/log", $optional);

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster log fail.');
        }

        return ResponseHelper::generate(true,'Cluster log', $response['data']);
    }

    /**
     * Get next free VMID. If you pass an VMID it will raise an error if the ID is already used.
     * @param integer $vmid The (unique) ID of the VM.
     * @throws \Exception
     */
    public function nextVmid($vmid = null)
    {
        $optional['vmid'] = !empty($vmid) ? $vmid : null;

        $response = $this->client->get("cluster/nextid", $optional);

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster next Vmid fail.');
        }

        return ResponseHelper::generate(true,'Cluster next Vmid', $response['data']);
    }

    /**
     * Get datacenter options.
     * @throws \Exception
     */
    public function options()
    {
        $response = $this->client->get("cluster/options");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster datacenter options fail.');
        }

        return ResponseHelper::generate(true,'Cluster datacenter options', $response['data']);
    }

    /**
     * Set datacenter options.
     * @param array $data
     * @return array
     * @throws \Exception
     */
    public function setOptions(array $data)
    {
        $response = $this->client->put("cluster/options", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster set datacenter options fail.');
        }

        return ResponseHelper::generate(true,'Cluster set datacenter options', $response['data']);
    }

    /**
     * Resources index (cluster wide).
     * @param enum $type vm | storage | node
     * @throws \Exception
     */
    public function resources($type = null)
    {
        $optional['type'] = !empty($type) ? $type : null;
        $response = $this->client->get("cluster/resources", $optional);

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster resources fail.');
        }

        return ResponseHelper::generate(true,'Cluster resources', $response['data']);
    }

    /**
     * Get cluster status informations.
     * @throws \Exception
     */
    public function status()
    {
        $response = $this->client->get("cluster/status");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster status fail.');
        }

        return ResponseHelper::generate(true,'Cluster status', $response['data']);
    }
    /**
     * List recent tasks (cluster wide).
     */
    public function tasks()
    {
        $response = $this->client->get("cluster/tasks");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Cluster tasks fail.');
        }

        return ResponseHelper::generate(true,'Cluster tasks', $response['data']);
    }

    /**
     * Create HA resource
     * @throws \Exception
     */
    public function createHAResource($data)
    {
        $response = $this->client->post('cluster/ha/resources', $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Cluster Create HA resource fail.');
        }

        return ResponseHelper::generate(true,'Cluster Create HA resource successfully', $response['data']);
    }
}
