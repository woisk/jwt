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
return [

    /**
     * token status_code
     * 1001 Account Status Not logged in
     * 1002 Token Expire
     */
    //token 加密秘钥
    'secret_key'  => env('JWT_SECRET', 'woisk'),

    /*
     * (issuer)：签发人
     * 签发者 xxx domain
     */
    'iss'         => env('JWT_iss', 'woisk.com'),

    /*
     * (audience)：受众
     * 发放给 xxx domain
     */
    'aud'         => env('JWT_aud', 'woisk.com'),

    /*
     * (expiration time)：过期时间
     * time Sec
     * 时间单位 秒(默认5个小时)
     */
    'exp'         => env('JWT_exp', 18000),

    /*
     * refresh time
     * time Sec
     * 时间单位 秒
     * 可以刷新令牌的时长(默认14天)
     */
    'refresh_ttl' => env('JWT_REFRESH_TTL', 1209600),
];