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


namespace Woisk\Jwt\Providers;


use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Notes: boot
     * ------------------------------------------------------
     * Author: Maple Grove  <bolelin@126.com> 2019/4/1 14:52
     */
    public function boot()
    {
        $path = realpath(__DIR__ . '/../../config/config.php');

        $this->publishes([$path => config_path('woisk/jwt/config.php')], 'config');

    }
}