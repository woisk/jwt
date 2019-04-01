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
use Illuminate\Support\Facades\Cache;

class JWT
{
    private $instance;

    public function __construct()
    {
        $this->instance = new Token;
    }

    /**
     * Notes: encode
     * @param string $token_type_name
     * @param int    $account_uid
     * @param string $aud
     * @param array  $data
     * @return string
     * @throws Exceptions\DataException
     * @throws Exceptions\EncryptMethodException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 14:18
     */
    public function encode(string $token_type_name, int $account_uid, string $aud, array $data = []): string
    {
        $time = Carbon::now()->timestamp;
        $payload = [
            'iss'  => jwt_iss(),
            'aud'  => $aud ?: jwt_iss(),
            'iat'  => $time,
            'exp'  => $time + jwt_expire_time(),
            'type' => $token_type_name,
            'ide'  => $account_uid,
            'data' => $data
        ];


        return $this->instance->encode($payload, jwt_secret_key());
    }

    /**
     * Notes: decode
     * @param string $token
     * @return array
     * @throws Exceptions\DataException
     * @throws Exceptions\EncryptMethodException
     * @throws Exceptions\ExpireException
     * @throws Exceptions\InvalidException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 15:23
     */
    public function decode(string $token): array
    {
        return $this->instance->decode($token, jwt_secret_key());
    }

    /**
     * Notes: refresh
     * @param string $token
     * @return string
     * @throws Exceptions\DataException
     * @throws Exceptions\EncryptMethodException
     * @throws Exceptions\ExpireException
     * @throws Exceptions\InvalidException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 16:45
     */
    public function refresh(string $token): string
    {
        $time = Carbon::now()->timestamp;
        $old_token = $this->decode($token);
        $iat = $old_token['iat'] - $time;

        if ($iat <= jwt_refresh_ttl()) {
            $payload = [
                'iss'  => $old_token['iss'],
                'aud'  => $old_token['aud'],
                'iat'  => $old_token['iat'],
                'exp'  => $time + jwt_expire_time(),
                'type' => $old_token['type'],
                'ide'  => $old_token['ide'],
                'data' => $old_token['data'],
            ];

            return $this->instance->encode($payload, jwt_secret_key());
        }

        return res(1002, 'Token Expire');
    }

    /**
     * Notes: invalid
     * @param string $token
     * @return bool
     * @throws Exceptions\DataException
     * @throws Exceptions\EncryptMethodException
     * @throws Exceptions\ExpireException
     * @throws Exceptions\InvalidException
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 16:50
     */
    public function invalid(string $token)
    {
        $time = Carbon::now()->timestamp;
        $old_token = $this->decode($token);
        $sec = $old_token['exp'] - $time;

        return Cache::put('token_invalid:' . $token, $token, $sec);
    }


}