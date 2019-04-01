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

namespace Woisk\Jwt\Middleware;


use Closure;
use Exception;
use Illuminate\Support\Facades\Cache;
use Woisk\Jwt\Exceptions\DataException;
use Woisk\Jwt\Exceptions\EncryptMethodException;
use Woisk\Jwt\Exceptions\ExpireException;
use Woisk\Jwt\Exceptions\InvalidException;
use Woisk\Jwt\JWT;

class JwtAuth
{
    public function handle($request, Closure $next)
    {
        try {
            $token = jwt_parser_token();
            if ( !$token) {
                return res(1001, 'Account Status Not logged in');
            }

            return $next($request);

        } catch (DataException $e) {

            return res(500, 'Data Exception');

        } catch (EncryptMethodException $e) {

            return res(500, 'Encrypt Method Error or Not');

        } catch (ExpireException $e) {

            try {
                sleep(rand(1, 5) / 100);
                $jwt = new JWT();
                $newToken = $jwt->refresh($token);
                $request->headers->set('Authorization', 'Bearer ' . $newToken); // 给当前的请求设置性的token,以备在本次请求中需要调用用户信息
                // 将旧token存储在redis中,30秒内再次请求是有效的
                Cache::put('token_interim:' . $token, $token, 30);
            } catch (Exception $e) {
                // 在黑名单的有效期,放行
                if ($newToken = Cache::get('token_interim:' . $token)) {
                    $request->headers->set('Authorization', 'Bearer ' . $newToken); // 给当前的请求设置性的token,以备在本次请求中需要调用用户信息

                    return $next($request);
                }

                return res(1002, 'Token Expire');
            }

        } catch (InvalidException $e) {

            return res(403, 'Token Invalid');

        }

    }
}