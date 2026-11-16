<?php

namespace Cycoslave\Proxmox\Exceptions;

/**
 * A polled Proxmox task was still running when the caller-supplied
 * timeout elapsed (ProxmoxNode::waitForTaskCompletion()). The task keeps
 * running on the cluster; this only means the wait was abandoned.
 */
class TaskTimeoutException extends ProxmoxException
{
    //
}
