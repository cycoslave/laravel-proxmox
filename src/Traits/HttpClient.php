<?php

namespace Cycoslave\Proxmox\Traits;

use Cycoslave\Proxmox\Exceptions\ApiException;
use Cycoslave\Proxmox\Exceptions\ConnectionException;

/**
 * HttpClient trait — raw cURL dispatcher.
 *
 * Throws typed exceptions so callers can distinguish error categories:
 *   - ConnectionException  : cURL / network-level failure
 *   - ApiException         : HTTP 4xx / 5xx or malformed JSON from Proxmox
 */
trait HttpClient
{
    /**
     * Build the cURL option array for a request without executing it.
     *
     * Extracted from sendRequest() (SAST-009) so tests can exercise the
     * production option-building logic (timeout floors/caps, TLS mapping,
     * GET query-string vs POST body handling) directly instead of testing
     * a duplicated copy.
     *
     * @param  string   $method   HTTP verb (GET, POST, PUT, DELETE)
     * @param  string   $url      Fully-qualified URL
     * @param  array    $params   Body params (POST/PUT) or query params (GET/DELETE)
     * @param  string[] $headers  Auth headers resolved by Authenticator
     * @return array<int, mixed>  cURL option array keyed by CURLOPT_* constant
     */
    protected function buildCurlOptions(
        string $method,
        #[\SensitiveParameter] string $url,
        #[\SensitiveParameter] array  $params  = [],
        #[\SensitiveParameter] array  $headers = [],
    ): array {
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => $this->verifyTls,
            CURLOPT_SSL_VERIFYHOST => $this->verifyTls ? 2 : 0,
            CURLOPT_CONNECTTIMEOUT => max(1, min(5, $this->timeout)),
            CURLOPT_TIMEOUT        => max(1, $this->timeout),
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_HTTPHEADER     => $headers,
        ];

        // H2: SPKI pinning. curl enforces the pin independently of
        // VERIFYPEER/VERIFYHOST, so pin + verify-off is a valid combination.
        if ($this->pinnedPublicKey !== null && $this->pinnedPublicKey !== '') {
            $options[CURLOPT_PINNEDPUBLICKEY] = $this->pinnedPublicKey;
        }

        $hasFile = $this->containsUploadFile($params);

        if ($method === 'POST' || $method === 'PUT') {
            $options[CURLOPT_URL] = $url;
            // F-07: http_build_query() serialises a CURLFile's public properties
            // ("filename[name]=/local/path"), leaking the path and never uploading
            // the file. With a file present send an array so cURL builds a real
            // multipart/form-data body; otherwise keep the urlencoded string.
            $options[CURLOPT_POSTFIELDS] = $hasFile
                ? $this->multipartFields($params)
                : http_build_query($params);
        } else {
            if ($hasFile) {
                throw new \InvalidArgumentException('File uploads are only supported for POST and PUT requests.');
            }
            $options[CURLOPT_URL] = empty($params)
                ? $url
                : $url . '?' . http_build_query($params);
        }

        return $options;
    }

    /**
     * True when $value is, or (recursively) contains, a CURLFile / CURLStringFile.
     */
    private function containsUploadFile(mixed $value): bool
    {
        if ($value instanceof \CURLFile || $value instanceof \CURLStringFile) {
            return true;
        }

        if (is_array($value)) {
            foreach ($value as $item) {
                if ($this->containsUploadFile($item)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Flatten a payload into the single-level array cURL needs for multipart
     * POSTFIELDS. Scalars follow http_build_query() semantics (null skipped,
     * bool -> 1/0, nested arrays -> "a[b][c]"); upload files pass through.
     *
     * @param  array<array-key, mixed> $params
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException  For values that cannot be form fields
     */
    private function multipartFields(array $params, string $prefix = ''): array
    {
        $fields = [];

        foreach ($params as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';

            if ($value === null) {
                continue;
            }

            if ($value instanceof \CURLFile || $value instanceof \CURLStringFile) {
                $fields[$name] = $value;
            } elseif (is_array($value)) {
                $fields += $this->multipartFields($value, $name);
            } elseif (is_bool($value)) {
                $fields[$name] = $value ? '1' : '0';
            } elseif (is_scalar($value) || $value instanceof \Stringable) {
                $fields[$name] = (string) $value;
            } else {
                throw new \InvalidArgumentException('Unsupported value type in multipart payload.');
            }
        }

        return $fields;
    }

    /**
     * Execute a cURL request and return the decoded JSON response.
     *
     * @param  string   $method   HTTP verb (GET, POST, PUT, DELETE)
     * @param  string   $url      Fully-qualified URL
     * @param  array    $params   Body params (POST/PUT) or query params (GET/DELETE)
     * @param  string[] $headers  Auth headers resolved by Authenticator
     * @return array    Decoded JSON response body
     *
     * @throws ConnectionException  On cURL / network failure or timeout
     * @throws ApiException         On HTTP 4xx/5xx or invalid JSON
     */
    protected function sendRequest(
        string $method,
        #[\SensitiveParameter] string $url,
        #[\SensitiveParameter] array  $params  = [],
        #[\SensitiveParameter] array  $headers = [],
    ): array {
        $curl    = curl_init();
        $options = $this->buildCurlOptions($method, $url, $params, $headers);

        curl_setopt_array($curl, $options);

        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $error    = curl_error($curl);
        $errno    = curl_errno($curl);
        curl_close($curl);

        if ($response === false || $error !== '') {
            // LPX-006: carry the curl errno as the exception code so logs can
            // record a categorised failure without the raw diagnostic text.
            // LPX-SAST-004: curl_error() embeds the target host/IP and local
            // TLS/pin paths; curl_strerror() gives the same category with no
            // endpoint detail. The errno is carried as the exception code.
            $generic = function_exists('curl_strerror') ? (string) curl_strerror($errno) : 'transport failure';
            throw new ConnectionException("Proxmox cURL error ({$errno}): {$generic}", $errno);
        }

        if ($httpCode >= 400) {
            // Redact query string (MED-2) and, per LPX-SAST-004, scheme/host/port:
            // log only the API path so uncaught exceptions never disclose the hypervisor.
            $safeUrl = (string) (parse_url(strtok($url, '?'), PHP_URL_PATH) ?: '/');
            throw new ApiException(
                "Proxmox API HTTP {$httpCode} for: {$safeUrl}",
                $httpCode,
            );
        }

        $decoded = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new ApiException(
                'Proxmox API returned invalid JSON: ' . json_last_error_msg(),
            );
        }

        return $decoded ?? [];
    }
}