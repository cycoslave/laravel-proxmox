# Changelog

## Unreleased: carbon F-11 (ResponseHelper envelope contracts)

27 `ProxmoxNode` methods now return the documented `ResponseHelper::generate()` envelope
`['success' => bool, 'message' => string, 'data'? => mixed]`. Callers that read the old shapes must update.

### Behaviour changes

* `vmQuery`, `setVMConfig`, `applyCloudInitVM`, `injectSSHCredentials`, `rebuildCloudInit` no longer return the raw
  client payload `['data' => ...]`. They return `['success' => true, 'message' => ..., 'data' => <payload>]`
  (the `data` key is omitted when Proxmox answers `{"data": null}`, as `ResponseHelper::generate()` always does).
  A response without a `data` key is now `['success' => false, 'message' => ...]`. `vmQuery` is a read, so a null
  `data` is also a failure; the four mutations treat a present-but-null `data` as success (LPX-004).
  Migration: `$r['data']` is still the payload on success; check `$r['success']` first.
* `attachSSHKey()` (returns `setVMConfig()`'s result) therefore now returns the envelope too.
  `renameVM()` was adapted internally; its own return value is unchanged.
* 22 node methods (`aplinfo`, `downloadTemplate`, `dns`, `setDns`, `execute`, `migrateAll`, `netstat`, `report`,
  `rrd`, `rrddata`, `spiceShell`, `startAll`, node `reboot`, `stopAll`, `subscription`, `updateSubscription`,
  `setSubscription`, `syslog`, `time`, `setTime`, `createVNCShell`, `vNCWebSocket`): success `data` is now the
  Proxmox payload itself. It was the whole client response, i.e. `$r['data']['data']`.
  Migration: replace `$r['data']['data']` with `$r['data']`. Failure envelopes are unchanged.
* F-11 itself changed return shapes only; it added no parameters and changed no existing parameter. The signature
  additions in this release come from F-08 (`?string $ostype = null`) and the F-01 attribute; see
  "Unreleased: carbon F-01..F-10" below. `configVM()` (protected, result unused) is untouched.

## Unreleased: carbon F-01..F-10

Caller-visible changes from the carbon SAST/SCA remediation (details per finding in
`REMEDIATION_LPX_SAST_SCA.md`). New throws are listed so callers can adapt.

### Signature changes

* F-08: `ProxmoxNode::fixGuestAgent`, `enableGuestAgent` and `configureGuestAgent` gain a trailing optional
  `?string $ostype = null`. Existing calls compile unchanged. See F-08 below for the behaviour change.
* F-01: `#[\SensitiveParameter]` added to `HttpClient::sendRequest`/`buildCurlOptions`,
  `ProxmoxAccess::get/post/put/delete/request`, `ProxmoxStorage::createStorage`, and
  `ProxmoxNode::createStorage`/`setVMConfig`/`writeNewKeyFile`. Attribute only: no behaviour or signature
  change beyond redacting these arguments in stack traces.

### Behaviour changes

* F-02: `new ProxmoxAccess(...)` throws `InvalidArgumentException` for an invalid `host` (must be an RFC 1123
  hostname, IPv4 or IPv6 literal; no userinfo, path, query or port in the host) or a `port` outside 1-65535.
  `ProxmoxManager::resolve()` also rejects missing/empty/non-string `host`/`username` and a non-integer `port`
  with `InvalidArgumentException`.
* F-03: `ProxmoxNode::detachDisk` accepts only slots matching `scsi|sata|ide|virtio|efidisk|tpmstate|unused` plus
  digits; anything else throws `InvalidArgumentException` before a request is sent.
* F-04: cloud-init values (`ip`, `subnet_mask`/`netmask`, `gateway` in `configureNetwork` and
  `configureVMCloudInitNetwork`) are rejected if they contain `,`, `=` or control characters; `nameserver` and
  `searchdomain` reject control characters. `attachSSHKey`/`injectSSHCredentials` validate the key and now send
  `sshkeys` percent-encoded (as `createUbuntuVMWithSSH` already did); multi-line or option-prefixed keys throw.
* F-06: `ProxmoxNode::attachDisk` validates `size`: an integer or `[0-9]{1,12}` with an optional `K`/`M`/`G`/`T`
  suffix (no suffix = GiB). K/M/T are converted to whole GiB (previously mis-read as GiB: `2T` -> 2, `2048M` ->
  2048) and must come to a whole number >= 1. Invalid sizes return the existing `Failed to attach disk.` failure
  envelope with no API call; `'10G'`, `'10'` and `10` still give `local-lvm:10`.
* F-05: `Authenticator` rejects CR/LF/NUL in token id/secret, ticket and CSRF token values
  (`ProxmoxException`; the message names the field, never the value). A missing or non-string
  `CSRFPreventionToken` in the ticket login response now throws `AuthenticationException` instead of raising an
  `Undefined array key` warning.
* F-07: `HttpClient` sends payloads containing a `CURLFile`/`CURLStringFile` as real `multipart/form-data`
  (POST/PUT), so `ProxmoxNode::storageUpload` now uploads the file instead of urlencoding the local path.
  Payloads without a file are unchanged. Unsupported object values in a payload throw `InvalidArgumentException`.
* F-08: the three guest-agent helpers no longer force `ostype=l26`; `ostype` is sent only when the caller passes
  one (validated against the Proxmox qemu ostype list, `InvalidArgumentException` otherwise), so win11/BSD
  profiles are no longer overwritten. A running guest gets a graceful `status/shutdown` first and falls back to
  `status/stop` only if that is refused, fails or times out. Fixed `sleep()` calls and the `deleteVM(force)` loop
  are replaced by bounded task/status polling (`waitForTaskCompletion`, `awaitGuestStatus`); bounds are protected
  properties, not new public parameters. `deleteVM` no longer dereferences a missing `['data']['status']`.
* F-09: `ProxmoxManager::purge()` also resets the five resource singletons (`proxmox-node`, `-cluster`,
  `-storage`, `-pools`, `-access-api`) when purging all or the default connection. Logging in `ProxmoxAccess`
  and `Authenticator` goes through `Support\SafeLog` and is a no-op without a Laravel app, so standalone use no
  longer throws `A facade root has not been set.`
* F-10: `createUbuntuVMWithSSH` removes the generated private/public key files (and an empty per-call temp dir)
  when the VM is not created. The no-Laravel fallback key directory is a private random directory
  (`sys_get_temp_dir()/proxmox-ssh-keys-<hex>`, mode 0700) instead of the shared `/tmp/proxmox-ssh-keys`. The
  host-app `storage/app/proxmox-ssh-keys` root is unchanged and never removed.

## Unreleased — test tooling (LPM-002)

- `vendor/bin/phpunit` no longer needs a coverage driver: `phpunit.xml` configures no coverage reports, so the
  suite runs instead of aborting with "No code coverage driver available … No tests executed".
- `composer test` runs `phpunit --no-coverage`; `composer coverage` uses the opt-in `phpunit-coverage.xml.dist`
  (requires Xdebug or PCOV). `failOnEmptyTestSuite` stays on, so a CI job that runs zero tests fails.

## Unreleased — breaking changes (LPX-SAST-006 / LPX-SAST-007)

Operator-approved public-API break. Callers must update.

### Changed signatures

| Method | Before | After |
|---|---|---|
| `ProxmoxNode::storageUpload` | `(string $node, array $data)` — `GET nodes/{node}/storage/upload` | `(string $node, string $storage, array $data = [])` — `POST nodes/{node}/storage/{storage}/upload` |
| `ProxmoxNode::destroyCephPool` | `(string $node)` — `DELETE nodes/{node}/ceph/pools` | `(string $node, string $name)` — `DELETE nodes/{node}/ceph/pools/{name}` |
| `ProxmoxNode::waitForTaskCompletion` | `(string $node, string $upid)` — polled forever | `(string $node, string $upid, int $timeoutSeconds = 120, int $pollIntervalSeconds = 2)` |

Migration: `storageUpload($node, $data)` → `storageUpload($node, $storage, $data)`;
`destroyCephPool($node)` → `destroyCephPool($node, $poolName)`. `storage` and `name` must match `[A-Za-z0-9_.-]+`
(no `/`, no `..`).

### Behaviour changes

* `checkTaskStatus()` now **throws** `ProxmoxException` (`Task failed with exit status: …`) when the task has stopped
  with an exit status other than `OK`; previously it returned the status envelope (the `throw` was unreachable).
  Running and successful tasks still return the raw envelope. Use `tasksStatus()` if you want the envelope for a failed task.
* `waitForTaskCompletion()` is now bounded. If the task is still running after `$timeoutSeconds` it throws
  `Cycoslave\Proxmox\Exceptions\TaskTimeoutException` (extends `ProxmoxException`); the task keeps running on the
  cluster. **Long tasks (backups, migrations) must pass a larger `$timeoutSeconds`.** `$timeoutSeconds` and
  `$pollIntervalSeconds` must be >= 1 (`InvalidArgumentException` otherwise). Task failure now throws
  `ProxmoxException` (was bare `\Exception`; still catchable as `\Exception`).
* Missing `data` in a task-status response no longer raises an `Undefined array key` warning (treated as "not stopped").

### Input validation

* `$volume` (`storageContentVolume`, `copyStorageContentVolume`, `deleteStorageContentVolume`): accepts Proxmox volume IDs
  such as `local:iso/ubuntu.iso` or `local-lvm:vm-100-disk-0` (`[A-Za-z0-9_.@:+-]` plus inner `/`); rejects empty,
  `.`/`..`/empty path components, `%`, `?`, `#`, backslash, whitespace and control characters. The value is
  `rawurlencode()`d into a single path segment.
* `$cidr` (the six LXC/QEMU `…FirewallIpsetNameCidr` methods): must be an IPv4/IPv6 address with optional prefix
  (`0–32` / `0–128`) and optional single leading `!`; `rawurlencode()`d into one segment. Anything else throws
  `InvalidArgumentException` before a request is sent.
* Both previously used the `[\w.-]` segment validator, which rejected every real volume ID and CIDR.
