<?php
declare(strict_types=1);
/**
 * +----------------------------------------------------------------------+
 * |                   At all timesI love the moment                      |
 * +----------------------------------------------------------------------+
 * | Copyright (c) 2019 www.Woisk.com All rights reserved.                |
 * +----------------------------------------------------------------------+
 * | This source file is subject to version 2.0 of the Apache license,    |
 * | that is bundled with this package in the file LICENSE, and is        |
 * | available through the world-wide-web at the following url:           |
 * | www.apache.org/licenses/LICENSE-2.0.html                             |
 * +----------------------------------------------------------------------+
 * |  Author:  Maple Grove  <bolelin@126.com>   QQ:364956690   286013629  |
 * +----------------------------------------------------------------------+
 */


namespace Woisk\Jwt;


use Carbon\Carbon;
use Woisk\Jwt\Exceptions\DataException;
use Woisk\Jwt\Exceptions\EncryptMethodException;
use Woisk\Jwt\Exceptions\ExpireException;
use Woisk\Jwt\Exceptions\InvalidException;

class Token
{

    /**
     * Notes: encode
     * @param array  $payload
     * @param        $secret_key
     * @param string $alg
     * @return string
     * @throws DataException
     * @throws EncryptMethodException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 18:32
     */
    public function encode(array $payload, $secret_key, string $alg = 'HS256'): string
    {
        $header = ['typ' => 'JWT', 'alg' => $alg];

        $segments = [];
        $segments[] = $this->base64UrlSafeEncode($this->jsonEncode($header));
        $segments[] = $this->base64UrlSafeEncode($this->jsonEncode($payload));

        $signing_input = implode('.', $segments);
        $signature = $this->sign($signing_input, $secret_key, $alg);
        $segments[] = $this->base64UrlSafeEncode($signature);

        return implode('.', $segments);
    }

    /**
     * Notes:decode
     * @param string $token
     * @param        $secret_key
     * @return array
     * @throws DataException
     * @throws EncryptMethodException
     * @throws InvalidException
     * @throws ExpireException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 10:45
     */
    public function decode(string $token, $secret_key): array
    {
        $parts = explode('.', $token);
        if (count($parts) === 3) {

            $header = $this->jsonDecode($this->base64UrlSafeDecode($parts[0]));
            $payload = $this->jsonDecode($this->base64UrlSafeDecode($parts[1]));
            $signature = $parts[2];

            if ( !$this->verify($signature, "$parts[0].$parts[1]", $secret_key, $header['alg'])) {
                throw new InvalidException('Signature verification failed');
            }

            if ( !$payload['exp'] > Carbon::now()->timestamp) {
                throw new ExpireException('Token expire');
            }

            return $payload;
        }

        throw new InvalidException('Wrong number of segments');
    }


    /**
     * Notes:jsonEncode
     * @param array $data
     * @return string
     * @throws DataException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/3/31 21:18
     */
    private function jsonEncode(array $data): string
    {
        $json = json_encode($data);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new DataException('Error while encoding to JSON: ' . json_last_error_msg());
        }

        return $json;
    }

    /**
     * Notes:
     * @param string $str
     * @return string
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 8:29
     */
    private function base64UrlSafeEncode(string $str): string
    {
        return str_replace('=', '', strtr(base64_encode($str), '+/', '-_'));
    }

    /**
     * Notes:json_decode to array
     * @param string $str
     * @return array
     * @throws DataException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 10:10
     */
    private function jsonDecode(string $str): array
    {
        $data = json_decode($str, true);
        if (json_last_error() != JSON_ERROR_NONE) {
            throw new DataException('Error while decoding to JSON: ' . json_last_error_msg());
        }

        return $data;
    }

    /**
     * Notes:base64_decode
     * @param string $str
     * @return string
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 8:54
     */
    private function base64UrlSafeDecode(string $str): string
    {
        if ($remainder = strlen($str) % 4) {
            $str .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($str, '-_', '+/'));
    }

    /**
     * Notes:sign
     * @param string $str
     * @param string $secret_key
     * @param string $encrypt_method
     * @return string
     * @throws EncryptMethodException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/3/31 20:55
     */
    private function sign(string $str, string $secret_key, string $encrypt_method = 'HS256'): string
    {
        $methods = [
            'HS256' => 'sha256',
            'HS384' => 'sha384',
            'HS512' => 'sha512',
        ];
        if (empty($methods[$encrypt_method])) {
            throw new EncryptMethodException('Algorithm not supported');
        }

        return hash_hmac($methods[$encrypt_method], $str, $secret_key, true);
    }


    /**
     * Notes:verify
     * @param string $signature
     * @param string $header_payload
     * @param string $secret_key
     * @param string $encrypt_method
     * @return bool
     * @throws EncryptMethodException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 9:21
     */
    private function verify(string $signature, string $header_payload, string $secret_key, string $encrypt_method): bool
    {
        $signedInput = $this->base64UrlSafeEncode($this->sign("$header_payload", $secret_key, $encrypt_method));

        return hash_equals($signature, $signedInput);
    }


}