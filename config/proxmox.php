<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Multiple Proxmox Connections
    |--------------------------------------------------------------------------
    |
    | This package is configured around named Proxmox connections.
    | Define each reachable Proxmox endpoint under "connections", and
    | set which one is the default using the "default" key.
    |
    | Example .env:
    |   PROXMOX_CONNECTION=primary
    |
    |   PROXMOX_HOST=proxmox.example.com
    |   PROXMOX_PORT=8006
    |   PROXMOX_USER=root@pam
    |   PROXMOX_REALM=pam
    |
    |   # Use either password OR token — token takes precedence if both are set.
    |   PROXMOX_PASSWORD=null
    |   PROXMOX_TOKEN_ID=null          # e.g. root@pam!mytoken
    |   PROXMOX_TOKEN_SECRET=null      # UUID token secret from Proxmox UI
    |
    |   # TLS — always keep true in production.
    |   # Only set false on a trusted internal network with a self-signed cert,
    |   # and never in a publicly reachable environment.
    |   PROXMOX_VERIFY_TLS=true
    |
    |   # Optional SPKI pin (sha256//<base64>, ';'-separated for several).
    |   # Enforced by curl even when PROXMOX_VERIFY_TLS=false (self-signed node).
    |   PROXMOX_PINNED_PUBLIC_KEY=
    |
    |   PROXMOX_TIMEOUT=10             # Total request timeout in seconds
    |
    */

    'default' => env('PROXMOX_CONNECTION', 'primary'),

    'connections' => [
        'primary' => [
            'host'         => env('PROXMOX_HOST', 'proxmox.example.com'),
            'port'         => (int) env('PROXMOX_PORT', 8006),
            'username'     => env('PROXMOX_USER', 'root'),
            'realm'        => env('PROXMOX_REALM', 'pam'),
            'password'     => env('PROXMOX_PASSWORD'),
            'token_id'     => env('PROXMOX_TOKEN_ID'),
            'token_secret' => env('PROXMOX_TOKEN_SECRET'),
            'verify_tls'   => (bool) env('PROXMOX_VERIFY_TLS', true),
            'timeout'      => (int) env('PROXMOX_TIMEOUT', 10),
            'pinned_public_key' => env('PROXMOX_PINNED_PUBLIC_KEY'),
        ],
    ],
];