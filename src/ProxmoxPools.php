<?php

namespace Cycoslave\Proxmox;

use Cycoslave\Proxmox\Support\ResponseHelper;
use Cycoslave\Proxmox\Traits\ValidatesPathSegments;

class ProxmoxPools
{
    use ValidatesPathSegments;

    public function __construct(protected ProxmoxAccess $client) {}

    /**
     * List all resource pools.
     *
     * @return array{success: bool, message: string, data: mixed}
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     */
    public function pools(): array
    {
        $response = $this->client->get('pools');

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Pools system log fail.');
        }
        return ResponseHelper::generate(true,'Pools system log.', $response['data']);
    }

    /**
     * Get details for a specific pool.
     *
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     */
    public function poolsId(string $poolid): array
    {
        $this->validateSegment($poolid, 'poolid');
        $response = $this->client->get("pools/$poolid");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Pools system log fail.');
        }
        return ResponseHelper::generate(true,'Pools system log.', $response['data']);
    }

    /**
     * Update a pool's comment or member list.
     *
     * @param  array<string, mixed>  $data
     * @throws \Cycoslave\Proxmox\Exceptions\ApiException
     * @throws \Cycoslave\Proxmox\Exceptions\ConnectionException
     */
    public function putPool(string $poolid, array $data = []): array
    {
        $this->validateSegment($poolid, 'poolid');
        $response = $this->client->put("pools/{$poolid}", $data);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Pools system log fail.');
        }
        return ResponseHelper::generate(true,'Pools system log.', $response['data']);
    }
}
