# Proxmox API Integration for Laravel

A Laravel package for interacting with one or more Proxmox servers via API. Supports both ticket-based and API token authentication, with named multi-connection support.

> Forked from [irabbi360/laravel-php-proxmox](https://github.com/irabbi360/laravel-php-proxmox). If you find any errors, typos, or unexpected behaviour, please open an [issue](https://github.com/cycoslave/laravel-proxmox/issues/new).

***

## Installation

```bash
composer require cycoslave/laravel-proxmox
```

Publish the config file:

```bash
php artisan vendor:publish --tag=proxmox-config
```

***

## Configuration

Edit `config/proxmox.php` to define one or more connections:

```php
return [
    'default' => env('PROXMOX_CONNECTION', 'primary'),
    'connections' => [
        'primary' => [
            'host'         => env('PROXMOX_HOST', '127.0.0.1'),
            'port'         => env('PROXMOX_PORT', 8006),
            'username'     => env('PROXMOX_USER', 'root'),
            'realm'        => env('PROXMOX_REALM', 'pam'),
            'password'     => env('PROXMOX_PASSWORD', null),
            'token_id'     => env('PROXMOX_TOKEN_ID', null),
            'token_secret' => env('PROXMOX_TOKEN_SECRET', null),
            'verify_tls'   => env('PROXMOX_VERIFY_TLS', true),
            'timeout'      => env('PROXMOX_TIMEOUT', 10),
            'pinned_public_key' => env('PROXMOX_PINNED_PUBLIC_KEY'),
        ],
    ],
];
```

Add the corresponding values to your `.env`:

```dotenv
PROXMOX_CONNECTION=primary
PROXMOX_HOST=192.168.1.10
PROXMOX_PORT=8006
PROXMOX_USER=root
PROXMOX_REALM=pam
PROXMOX_PASSWORD=

# API token auth (takes precedence over password if both are set)
PROXMOX_TOKEN_ID=
PROXMOX_TOKEN_SECRET=

PROXMOX_VERIFY_TLS=true
PROXMOX_TIMEOUT=10

# Optional SPKI pin (sha256//<base64>; ';' separates several). Enforced by curl
# (CURLOPT_PINNEDPUBLICKEY) even when PROXMOX_VERIFY_TLS=false, so a self-signed
# node can be pinned instead of running unverified. Unpinned verify-off still warns.
PROXMOX_PINNED_PUBLIC_KEY=
```

***

## Basic Usage

```php
use Cycoslave\Proxmox\Facades\Proxmox;

// Default connection
Proxmox::nodes()->all();

// Named connection
Proxmox::connection('datacenter2')->nodes()->get('pve1');

// Named connection — fluent
Proxmox::connection('backup-pve')
    ->storage()
    ->list('pve-node', 'dir');
```

### VM Operations

```php
use Cycoslave\Proxmox\Facades\ProxmoxNodeVM;

// Get version
ProxmoxNodeVM::version();

// Create a VM
public function createVm(string $node, Request $request)
{
    $params = [
        'name'     => $request->name,
        'cores'    => $request->cores,
        'sockets'  => $request->sockets,
        'memory'   => $request->memory,
        'ostype'   => $request->ostype,
        'onboot'   => 1,
        'scsihw'   => 'virtio-scsi-pci',
        'bootdisk' => 'scsi0',
        'net0'     => 'virtio,bridge=vmbr0',
    ];

    return ProxmoxNodeVM::createVM($node, $params);
}

// Start / Stop
public function vmStart(string $node, int $vmId)
{
    return ProxmoxNodeVM::startVM($node, $vmId);
}

public function vmStop(string $node, int $vmId)
{
    return ProxmoxNodeVM::stopVM($node, $vmId);
}
```

***

## API Reference

### Access

```php
use Cycoslave\Proxmox\Facades\ProxmoxAccess;

ProxmoxAccess::access();
ProxmoxAccess::acl();
ProxmoxAccess::updateAcl(array $data);
ProxmoxAccess::createTicket(array $data);
```

### Domains

```php
ProxmoxAccess::domains();
ProxmoxAccess::addDomain(array $data);
ProxmoxAccess::domainsRealm(string $realm);
ProxmoxAccess::updateDomain(string $realm, array $data);
ProxmoxAccess::deleteDomain(string $realm);
```

### Groups

```php
ProxmoxAccess::groups();
ProxmoxAccess::createGroup(array $data);
ProxmoxAccess::groupId(string $groupid);
ProxmoxAccess::updateGroup(string $groupid, array $data);
ProxmoxAccess::deleteGroup(string $groupid);
```

### Roles

```php
ProxmoxAccess::roles();
ProxmoxAccess::createRole(array $data);
ProxmoxAccess::roleId(string $roleid);
ProxmoxAccess::updateRole(string $roleid, array $data);
ProxmoxAccess::deleteRole(string $roleid);
```

### Users

```php
ProxmoxAccess::users();
ProxmoxAccess::createUser(array $data);
ProxmoxAccess::getUser(string $userid);
ProxmoxAccess::updateUser(string $userid, array $data);
ProxmoxAccess::deleteUser(string $userid);
ProxmoxAccess::changeUserPassword(array $data);
```

***

### Cluster

```php
use Cycoslave\Proxmox\Facades\ProxmoxCluster;

ProxmoxCluster::cluster();
ProxmoxCluster::getClusterLog();
ProxmoxCluster::nextVmid(?int $vmid = null);
ProxmoxCluster::options();
ProxmoxCluster::setOptions(array $data);
ProxmoxCluster::resources(?string $type = null);
ProxmoxCluster::status();
ProxmoxCluster::tasks();
```

### Backup

```php
ProxmoxCluster::listBackup();
ProxmoxCluster::createBackup(array $data);
ProxmoxCluster::backupId(string $id);
ProxmoxCluster::updateBackup(string $id, array $data);
ProxmoxCluster::deleteBackup(string $id);
```

### Cluster Config

```php
ProxmoxCluster::config();
ProxmoxCluster::listConfigNodes();
ProxmoxCluster::configTotem();
```

### Cluster Firewall

```php
ProxmoxCluster::firewall();
ProxmoxCluster::firewallListAliases();
ProxmoxCluster::createFirewallAlias(array $data);
ProxmoxCluster::getFirewallAliasesName(string $name);
ProxmoxCluster::updateFirewallAlias(string $name, array $data);
ProxmoxCluster::removeFirewallAlias(string $name);
ProxmoxCluster::firewallListGroups();
ProxmoxCluster::createFirewallGroup(array $data);
ProxmoxCluster::firewallGroupsGroup(string $group);
ProxmoxCluster::createRuleFirewallGroup(string $group, array $data);
ProxmoxCluster::removeFirewallGroup(string $group);
ProxmoxCluster::firewallGroupsGroupPos(string $group, int $pos);
ProxmoxCluster::setFirewallGroupPos(string $group, int $pos, array $data);
ProxmoxCluster::removeFirewallGroupPos(string $group, int $pos);
ProxmoxCluster::firewallListIpset();
ProxmoxCluster::createFirewallIpset(array $data);
ProxmoxCluster::firewallIpsetName(string $name);
ProxmoxCluster::addFirewallIpsetName(string $name, array $data);
ProxmoxCluster::deleteFirewallIpsetName(string $name);
ProxmoxCluster::firewallListRules();
ProxmoxCluster::createFirewallRules(array $data);
ProxmoxCluster::firewallRulesPos(int $pos);
ProxmoxCluster::setFirewallRulesPos(int $pos, array $data);
ProxmoxCluster::deleteFirewallRulesPos(int $pos);
ProxmoxCluster::firewallListMacros();
ProxmoxCluster::firewallListOptions();
ProxmoxCluster::setFirewallOptions(array $data);
ProxmoxCluster::firewallListRefs();
```

### HA

```php
ProxmoxCluster::getHaGroups();
ProxmoxCluster::HaGroups(string $group);
ProxmoxCluster::getHAResources();
```

### Replication

```php
ProxmoxCluster::replication();
ProxmoxCluster::createReplication(array $data);
ProxmoxCluster::replicationId(string $id);
ProxmoxCluster::updateReplication(string $id, array $data);
ProxmoxCluster::deleteReplication(string $id);
```

***

### Pools

```php
use Cycoslave\Proxmox\Facades\ProxmoxPools;

ProxmoxPools::pools();
ProxmoxPools::poolsId(string $poolid);
ProxmoxPools::putPool(string $poolid, array $data);
```

***

### Storage

```php
use Cycoslave\Proxmox\Facades\ProxmoxStorage;

ProxmoxStorage::storage(?string $type = null);
ProxmoxStorage::createStorage(array $data);
ProxmoxStorage::getStorage(string $storage);
ProxmoxStorage::updateStorage(string $storage, array $data);
ProxmoxStorage::deleteStorage(string $storage);
```

***

### Nodes

```php
use Cycoslave\Proxmox\Facades\ProxmoxNode;

ProxmoxNode::version();
ProxmoxNode::getNodes();
ProxmoxNode::aplinfo(string $node);
ProxmoxNode::downloadTemplate(string $node, array $data);
ProxmoxNode::dns(string $node);
ProxmoxNode::setDns(string $node, array $data);
ProxmoxNode::execute(string $node, array $data); // ⚠ remote command execution — see "Remote command execution" under Security Vulnerabilities
ProxmoxNode::migrateAll(string $node, array $data);
ProxmoxNode::netstat(string $node);
ProxmoxNode::report(string $node);
ProxmoxNode::rrd(string $node, ?string $ds = null, ?string $timeframe = null);
ProxmoxNode::rrddata(string $node, ?string $timeframe = null);
ProxmoxNode::spiceShell(string $node, array $data);
ProxmoxNode::startAll(string $node, array $data);
ProxmoxNode::reboot(string $node, array $data);
ProxmoxNode::stopAll(string $node, array $data);
ProxmoxNode::subscription(string $node);
ProxmoxNode::updateSubscription(string $node, array $data);
ProxmoxNode::setSubscription(string $node, array $data = []);
ProxmoxNode::syslog(string $node, ?int $limit = null, ?int $start = null, ?string $since = null, ?string $until = null);
ProxmoxNode::time(string $node);
ProxmoxNode::setTime(string $node, array $data);
ProxmoxNode::version(string $node);
ProxmoxNode::createVNCShell(string $node, array $data);
ProxmoxNode::vNCWebSocket(string $node, ?int $port = null, ?string $vncticket = null);
```

### Apt

```php
ProxmoxNode::apt(string $node);
ProxmoxNode::updateApt(string $node, array $data);
ProxmoxNode::aptChangelog(string $node, ?string $name = null);
ProxmoxNode::aptUpdate(string $node);
ProxmoxNode::createAptUpdate(array $data);
```

### Ceph

```php
ProxmoxNode::ceph(string $node);
ProxmoxNode::cephFlags(string $node);
ProxmoxNode::setCephFlags(string $node, string $flag, array $data);
ProxmoxNode::unsetCephFlags(string $node, string $flag);
ProxmoxNode::createCephMgr(string $node, array $data);
ProxmoxNode::destroyCephMgr(string $node, string $id);
ProxmoxNode::cephMon(string $node);
ProxmoxNode::createCephMon(string $node, array $data);
ProxmoxNode::destroyCephMon(string $node, string $monid);
ProxmoxNode::cephOsd(string $node);
ProxmoxNode::createCephOsd(string $node, array $data);
ProxmoxNode::destroyCephOsd(string $node, int $osdid);
ProxmoxNode::cephOsdIn(string $node, int $osdid, array $data);
ProxmoxNode::cephOsdOut(string $node, int $osdid, array $data);
ProxmoxNode::getCephPools(string $node);
ProxmoxNode::createCephPool(string $node, array $data);
ProxmoxNode::destroyCephPool(string $node);
ProxmoxNode::cephConfig(string $node);
ProxmoxNode::cephCrush(string $node);
ProxmoxNode::cephDisks(string $node);
ProxmoxNode::createCephInit(string $node, array $data);
ProxmoxNode::cephLog(string $node, ?int $limit = null, ?int $start = null);
ProxmoxNode::cephRules(string $node);
ProxmoxNode::cephStart(string $node, array $data);
ProxmoxNode::cephStop(string $node, array $data);
ProxmoxNode::cephStatus(string $node);
```

### Disks

```php
ProxmoxNode::getDisks(string $node);
ProxmoxNode::disk(string $node, array $data);
ProxmoxNode::disksList(string $node);
ProxmoxNode::disksSmart(string $node, ?string $disk = null);
```

### Node Firewall

```php
ProxmoxNode::firewall(string $node);
ProxmoxNode::firewallRules(string $node);
ProxmoxNode::createFirewallRule(string $node, array $data = []);
ProxmoxNode::firewallRulesPos(string $node, int $pos);
ProxmoxNode::setFirewallRulePos(string $node, int $pos, array $data = []);
ProxmoxNode::deleteFirewallRulePos(string $node, int $pos);
ProxmoxNode::firewallRulesLog(string $node);
ProxmoxNode::firewallRulesOptions(string $node);
ProxmoxNode::setFirewallRuleOptions(string $node, array $data = []);
```

### LXC

```php
ProxmoxNode::lxc(string $node);
ProxmoxNode::createLxc(string $node, array $data = []);
ProxmoxNode::lxcVmid(string $node, int $vmid);
ProxmoxNode::deleteLxc(string $node, int $vmid);
ProxmoxNode::lxcFirewall(string $node, int $vmid);
ProxmoxNode::lxcFirewallAliases(string $node, int $vmid);
ProxmoxNode::createLxcFirewallAlias(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcFirewallAliasesName(string $node, int $vmid, string $name);
ProxmoxNode::updateLxcFirewallAliaseName(string $node, int $vmid, string $name, array $data = []);
ProxmoxNode::deleteLxcFirewallAliaseName(string $node, int $vmid, string $name);
ProxmoxNode::lxcFirewallIpset(string $node, int $vmid);
ProxmoxNode::createLxcFirewallIpset(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcFirewallIpsetName(string $node, int $vmid, string $name);
ProxmoxNode::addLxcFirewallIpsetName(string $node, int $vmid, string $name, array $data = []);
ProxmoxNode::deleteLxcFirewallIpsetName(string $node, int $vmid, string $name);
ProxmoxNode::lxcFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr);
ProxmoxNode::updateLxcFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr, array $data = []);
ProxmoxNode::deleteLxcFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr);
ProxmoxNode::lxcFirewallRules(string $node, int $vmid);
ProxmoxNode::createLxcFirewallRules(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcFirewallRulesPos(string $node, int $vmid, int $pos);
ProxmoxNode::setLxcFirewallRulesPos(string $node, int $vmid, int $pos, array $data = []);
ProxmoxNode::deleteLxcFirewallRulesPos(string $node, int $vmid, int $pos);
ProxmoxNode::lxcFirewallLog(string $node, int $vmid, ?int $limit = null, ?int $start = null);
ProxmoxNode::lxcFirewallOptions(string $node, int $vmid);
ProxmoxNode::setLxcFirewallOptions(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcSnapshot(string $node, int $vmid);
ProxmoxNode::createLxcSnapshot(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcSnapname(string $node, int $vmid, string $snapname);
ProxmoxNode::deleteLxcSnapshot(string $node, int $vmid, string $snapname);
ProxmoxNode::lxcSnapnameConfig(string $node, int $vmid, string $snapname);
ProxmoxNode::lxcSnapshotConfig(string $node, int $vmid, string $snapname, array $data = []);
ProxmoxNode::lxcSnapshotRollback(string $node, int $vmid, string $snapname, array $data = []);
ProxmoxNode::lxcStatus(string $node, int $vmid);
ProxmoxNode::lxcCurrent(string $node, int $vmid);
ProxmoxNode::lxcResume(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcShutdown(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcStart(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcStop(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcReboot(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcSuspend(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcClone(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcConfig(string $node, int $vmid);
ProxmoxNode::setLxcConfig(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcFeature(string $node, int $vmid);
ProxmoxNode::lxcMigrate(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcResize(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcRrd(string $node, int $vmid, ?string $ds = null, ?string $timeframe = null);
ProxmoxNode::lxcRrddata(string $node, int $vmid, ?string $timeframe = null);
ProxmoxNode::lxcSpiceproxy(string $node, int $vmid, array $data = []);
ProxmoxNode::createLxcTemplate(string $node, int $vmid, array $data = []);
ProxmoxNode::createLxcVncproxy(string $node, int $vmid, array $data = []);
ProxmoxNode::lxcVncwebsocket(string $node, int $vmid, ?int $port = null, ?string $vncticket = null);
```

### Network

```php
ProxmoxNode::network(string $node, ?string $type = null);
ProxmoxNode::createNetwork(string $node, array $data = []);
ProxmoxNode::revertNetwork(string $node);
ProxmoxNode::networkIface(string $node, string $iface);
ProxmoxNode::updateNetworkIface(string $node, string $iface, array $data = []);
ProxmoxNode::deleteNetworkIface(string $node, string $iface);
```

### QEMU

```php
ProxmoxNode::qemu(string $node);
ProxmoxNode::createQemu(string $node, array $data = []);
ProxmoxNode::qemuVmid(string $node, int $vmid);
ProxmoxNode::deleteQemu(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuFirewall(string $node, int $vmid);
ProxmoxNode::qemuFirewallAliases(string $node, int $vmid);
ProxmoxNode::createQemuFirewallAlias(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuFirewallAliasesName(string $node, int $vmid, string $name);
ProxmoxNode::updateQemuFirewallAliaseName(string $node, int $vmid, string $name, array $data = []);
ProxmoxNode::deleteQemuFirewallAliaseName(string $node, int $vmid, string $name);
ProxmoxNode::qemuFirewallIpset(string $node, int $vmid);
ProxmoxNode::createQemuFirewallIpset(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuFirewallIpsetName(string $node, int $vmid, string $name);
ProxmoxNode::addQemuFirewallIpsetName(string $node, int $vmid, string $name, array $data = []);
ProxmoxNode::deleteQemuFirewallIpsetName(string $node, int $vmid, string $name);
ProxmoxNode::qemuFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr);
ProxmoxNode::updateQemuFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr, array $data = []);
ProxmoxNode::deleteQemuFirewallIpsetNameCidr(string $node, int $vmid, string $name, string $cidr);
ProxmoxNode::qemuFirewallRules(string $node, int $vmid);
ProxmoxNode::createQemuFirewallRules(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuFirewallRulesPos(string $node, int $vmid, int $pos);
ProxmoxNode::updateQemuFirewallRulesPos(string $node, int $vmid, int $pos, array $data = []);
ProxmoxNode::deleteQemuFirewallRulesPos(string $node, int $vmid, int $pos);
ProxmoxNode::qemuFirewallLog(string $node, int $vmid, ?int $limit = null, ?int $start = null);
ProxmoxNode::qemuFirewallOptions(string $node, int $vmid);
ProxmoxNode::setQemuFirewallOptions(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuFirewallRefs(string $node, int $vmid);
ProxmoxNode::qemuSnapshot(string $node, int $vmid);
ProxmoxNode::createQemuSnapshot(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuSnapname(string $node, int $vmid, string $snapname);
ProxmoxNode::deleteQemuSnapshot(string $node, int $vmid, string $snapname);
ProxmoxNode::qemuSnapnameConfig(string $node, int $vmid, string $snapname);
ProxmoxNode::updateQemuSnapshotConfig(string $node, int $vmid, string $snapname, array $data = []);
ProxmoxNode::qemuSnapshotRollback(string $node, int $vmid, string $snapname, array $data = []);
ProxmoxNode::qemuStatus(string $node, int $vmid);
ProxmoxNode::qemuCurrent(string $node, int $vmid);
ProxmoxNode::qemuResume(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuReset(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuShutdown(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuStart(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuStop(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuReboot(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuSuspend(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuAgent(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuAgentExec(string $node, int $vmid, array $data = []); // ⚠ remote command execution — see "Remote command execution" under Security Vulnerabilities
ProxmoxNode::qemuAgentSetUserPassword(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuClone(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuConfig(string $node, int $vmid);
ProxmoxNode::createQemuConfig(string $node, int $vmid, array $data = []);
ProxmoxNode::setQemuConfig(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuFeature(string $node, int $vmid);
ProxmoxNode::qemuMigrate(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuMonitor(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuMoveDisk(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuPending(string $node, int $vmid);
ProxmoxNode::qemuResize(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuRrd(string $node, int $vmid, ?string $ds = null, ?string $timeframe = null);
ProxmoxNode::qemuRrddata(string $node, int $vmid, ?string $timeframe = null);
ProxmoxNode::qemuSendkey(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuSpiceproxy(string $node, int $vmid, array $data = []);
ProxmoxNode::createQemuTemplate(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuUnlink(string $node, int $vmid, array $data = []);
ProxmoxNode::createQemuVncproxy(string $node, int $vmid, array $data = []);
ProxmoxNode::qemuVncwebsocket(string $node, int $vmid, ?int $port = null, ?string $vncticket = null);
```

### Node Replication

```php
ProxmoxNode::replication(string $node);
ProxmoxNode::replicationId(string $node, string $id);
ProxmoxNode::replicationLog(string $node, string $id);
ProxmoxNode::replicationScheduleNow(string $node, string $id, array $data = []);
ProxmoxNode::replicationStatus(string $node, string $id);
```

### Scan

```php
ProxmoxNode::scan(string $node);
ProxmoxNode::scanGlusterfs(string $node);
ProxmoxNode::scanIscsi(string $node);
ProxmoxNode::scanLvm(string $node);
ProxmoxNode::scanLvmthin(string $node);
ProxmoxNode::scanUsb(string $node);
ProxmoxNode::scanZfs(string $node);
```

### Services

```php
ProxmoxNode::services(string $node);
ProxmoxNode::listService(string $node, string $service);
ProxmoxNode::servicesReload(string $node, string $service, array $data = []);
ProxmoxNode::servicesRestart(string $node, string $service, array $data = []);
ProxmoxNode::servicesStart(string $node, string $service, array $data = []);
ProxmoxNode::servicesStop(string $node, string $service, array $data = []);
ProxmoxNode::servicesState(string $node, string $service);
```

### Node Storage

```php
ProxmoxNode::storage(string $node, ?string $content = null, ?string $storage = null, ?string $target = null, ?bool $enabled = null);
ProxmoxNode::getStorage(string $node, string $storage);
ProxmoxNode::listStorageContent(string $node, string $storage);
ProxmoxNode::storageContent(string $node, string $storage, array $data = []);
ProxmoxNode::storageContentVolume(string $node, string $storage, string $volume);
ProxmoxNode::copyStorageContentVolume(string $node, string $storage, string $volume, array $data = []);
ProxmoxNode::deleteStorageContentVolume(string $node, string $storage, string $volume);
ProxmoxNode::storageRRD(string $node);
ProxmoxNode::storageRRDdata(string $node);
ProxmoxNode::storageStatus(string $node);
ProxmoxNode::storageUpload(string $node, array $data = []);
```

### Tasks

```php
ProxmoxNode::tasks(string $node, ?bool $errors = null, ?int $limit = null, ?int $vmid = null, ?int $start = null);
ProxmoxNode::tasksUpid(string $node, string $upid);
ProxmoxNode::tasksStop(string $node, string $upid);
ProxmoxNode::tasksLog(string $node, string $upid, ?int $limit = null, ?int $start = null);
ProxmoxNode::tasksStatus(string $node, string $upid);
```

### Vzdump

```php
ProxmoxNode::createVzdump(string $node, array $data = []);
ProxmoxNode::vzdumpExtractConfig(string $node);
```

***

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for recent changes.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security Vulnerabilities

Please review [our security policy](../../security/policy) for reporting vulnerabilities.

### Remote command execution (`execute()` / `qemuAgentExec()`)

`ProxmoxNode::execute()` (`POST /nodes/{node}/execute`) and
`ProxmoxNode::qemuAgentExec()` (`POST /nodes/{node}/qemu/{vmid}/agent/exec`)
run arbitrary commands on the Proxmox host or inside a guest via the QEMU
Guest Agent, respectively. This package performs no authorization checks of
its own before issuing these calls — it is a thin client over the Proxmox
API and inherits whatever privileges the configured connection's
credentials (ticket user or API token) hold on the target node/VM.

Callers **must** treat any application code path that reaches `execute()` or
`qemuAgentExec()` as a privileged, remote-code-execution-capable operation:

- Never expose `$data`/command arguments to end users unvalidated; treat
  them the same as you would raw shell input.
- Scope the Proxmox user/token used by this package to the minimum
  privileges needed (a dedicated realm/role, not `root@pam`) so a
  compromised or misused call is contained.
- Add your own application-level authorization/audit-logging in front of
  any controller or job that calls these two methods — the package does
  not do this for you.

## Credits

- [Fazle Rabbi](https://github.com/irabbi360) — original package
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.