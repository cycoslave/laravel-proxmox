<?php

namespace Cycoslave\Proxmox\Support;

/**
 * ResponseHelper — normalises all API responses into a consistent envelope.
 *
 * Every public method in this package returns:
 *   ['success' => bool, 'message' => string, 'data' => mixed]
 *
 * Callers should always check $response['success'] before consuming $response['data'].
 */
class ResponseHelper
{
    /**
     * Build a standard response envelope.
     *
     * @param  bool                $success  Whether the operation succeeded
     * @param  string              $message  Human-readable status message
     * @param  array|string|null   $data     Payload from the Proxmox API
     * @return array{success: bool, message: string, data?: array|string}
     */
    public static function generate(
        bool $success,
        string $message,
        array|string|null $data = null,
    ): array {
        $response = [
            'success' => $success,
            'message' => $message,
        ];

        if (! is_null($data)) {
            $response['data'] = $data;
        }

        return $response;
    }

    /**
     * Whether a decoded Proxmox API envelope carries a `data` key.
     *
     * LPX-004 (CWE-253): Proxmox answers many successful mutations
     * (POST/PUT/DELETE) with `{"data": null}`. `isset($r['data'])` is false
     * for a present-but-null key, so a successful write was reported as a
     * failure. Mutation wrappers use key *presence* (not non-nullness) as
     * the success signal; HTTP/API errors are already raised as exceptions
     * by the HTTP layer, so a missing key means a malformed envelope.
     *
     * @param  array  $response  Decoded API response
     */
    public static function hasData(array $response): bool
    {
        return array_key_exists('data', $response);
    }
}