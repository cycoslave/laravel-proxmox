<?php

namespace Cycoslave\Proxmox;

use Cycoslave\Proxmox\Support\ResponseHelper;
use Cycoslave\Proxmox\Traits\ValidatesPathSegments;

class ProxmoxStorage
{
    use ValidatesPathSegments;

    public function __construct(protected ProxmoxAccess $client) {}

    /**
     * Storage index.
     * @param $type Only list storage of specific type
     * @throws \Exception
     */
    public function storage($type = null)
    {
        $params['type'] = !empty($type) ? $type : null;
        $response = $this->client->get('storage', $params);

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Storage list fetch fail!');
        }
        return ResponseHelper::generate(true,'Storage list!', $response['data']);
    }

    /**
     * Create Storage
     * @param array $params Storage configuration parameters
     * @throws \Exception
     */
    public function createStorage(array $params)
    {
        // Validate required parameters
        $required = ['storage', 'type'];
        foreach ($required as $field) {
            if (!isset($params[$field])) {
                throw new \Exception("Missing required parameter: {$field}");
            }
        }

        $response = $this->client->post('storage', $params);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Storage create fail.');
        }
        return ResponseHelper::generate(true,'Storage created successfully.', $response['data']);
    }

    /**
     * Read storage configuration.
     * GET /api2/json/storage/{storage}
     * @param string $storage The storage identifier.
     * @throws \Exception
     */
    public function getStorage($storage)
    {
        $this->validateSegment((string) $storage, 'storage');
        $response = $this->client->get("storage/$storage");

        if (!isset($response['data'])){
            return ResponseHelper::generate(false,'Storage fail.');
        }
        return ResponseHelper::generate(true,'Storage details.', $response['data']);
    }

    /**
     * Create Directory Storage
     *
     * @param string $name Storage name
     * @param string $path Directory path
     * @param array $options Additional options
     * @throws \Exception
     */
    public function createDirectoryStorage(string $name, string $path, array $options = [])
    {
        // Create Directory Storage
        /*$params = [
            'storage' => 'local-storage',  // Name of the storage
            'type' => 'dir',              // Storage type (directory)
            'path' => '/mnt/local',       // Path to the storage directory
            'content' => 'images,iso',    // Types of content this storage can hold
            'shared' => false             // Whether the storage is shared across nodes
        ];*/

        $defaults = [
            'storage' => $name,
            'type' => 'dir',
            'path' => $path,
            'content' => 'images,iso,backup,vztmpl',
            'shared' => 0,
            'preallocation' => 0
        ];

        return $this->createStorage(array_merge($defaults, $options));
    }

    /**
     * Create NFS Storage
     *
     * @param string $name Storage name
     * @param string $server NFS server
     * @param string $export NFS export path
     * @param array $options Additional options
     * @throws \Exception
     */
    public function createNFSStorage(string $name, string $server, string $export, array $options = [])
    {
        $defaults = [
            'storage' => $name,
            'type' => 'nfs',
            'server' => $server,
            'export' => $export,
            'content' => 'images,iso',
            'shared' => 1,
            'options' => 'soft,async'
        ];

        return $this->createStorage(array_merge($defaults, $options));
    }

    /**
     * Create LVM Storage
     *
     * @param string $name Storage name
     * @param string $vgname Volume group name
     * @param array $options Additional options
     * @throws \Exception
     */
    public function createLVMStorage(string $name, string $vgname, array $options = [])
    {
        $defaults = [
            'storage' => $name,
            'type' => 'lvm',
            'vgname' => $vgname,
            'content' => 'images',
            'shared' => 0
        ];

        return $this->createStorage(array_merge($defaults, $options));
    }

    /**
     * Create CIFS Storage
     *
     * @param string $name Storage name
     * @param string $server CIFS server
     * @param string $share Share name
     * @param string $username Username
     * @param string $password Password
     * @param array $options Additional options
     * @return array
     * @throws \Exception
     */
    public function createCIFSStorage(
        string $name,
        string $server,
        string $share,
        string $username,
        #[\SensitiveParameter] string $password,
        array $options = []
    ): array {
        $defaults = [
            'storage' => $name,
            'type' => 'cifs',
            'server' => $server,
            'share' => $share,
            'username' => $username,
            'password' => $password,
            'content' => 'images,iso',
            'shared' => 1,
            'version' => '3.0'
        ];

        return $this->createStorage(array_merge($defaults, $options));
    }

    /**
     * Delete Storage
     *
     * @param string $storage Storage name
     * @throws \Exception
     */
    public function deleteStorage(string $storage)
    {
        $this->validateSegment((string) $storage, 'storage');
        $response = $this->client->delete("storage/{$storage}");

        if (ResponseHelper::hasData($response)) {
            return ResponseHelper::generate(true, 'Storage deleted successfully', $response['data']);
        }
        return ResponseHelper::generate(false,'Storage delete fail!');
    }

    /**
     * Update Storage Configuration
     *
     * @param string $storage Storage name
     * @param array $params Update parameters
     * @return array
     * @throws \Exception
     */
    public function updateStorage(string $storage, array $params): array
    {
        $this->validateSegment((string) $storage, 'storage');
        $response = $this->client->put("storage/{$storage}", $params);

        if (!ResponseHelper::hasData($response)){
            return ResponseHelper::generate(false,'Storage update fail!');
        }
        return ResponseHelper::generate(true,'Storage updated successfully!', $response['data']);
    }
}
