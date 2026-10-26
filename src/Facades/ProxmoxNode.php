<?php

namespace Cycoslave\Proxmox\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \Cycoslave\Proxmox\ProxmoxNode
 */
class ProxmoxNode extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'proxmox-node';
    }
}
