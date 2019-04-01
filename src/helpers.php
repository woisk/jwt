<?php
declare(strict_types=1);

/*
 * token secret key
 * 加密秘钥 config文件读取
 */
if ( !function_exists('jwt_secret_key')) {
    function jwt_secret_key()
    {
        return config('woisk.jwt.config.secret_key');
    }
}
if ( !function_exists('jwt_expire_time')) {
    function jwt_expire_time()
    {
        return config('woisk.jwt.config.exp');
    }
}
if ( !function_exists('jwt_iss')) {
    function jwt_iss()
    {
        return config('woisk.jwt.config.iss');
    }
}

/*
 * jwt refresh_ttl
 * 允许的刷新时间
 */
if ( !function_exists('jwt_refresh_ttl')) {
    function jwt_refresh_ttl()
    {
        return config('woisk.jwt.config.refresh_ttl');
    }
}

/**
 * jwt 获取token
 * @param string $token_name
 * @return string
 */
if ( !function_exists('jwt_parser_token')) {
    function jwt_parser_token(string $token_name = 'access_token'): string
    {
        $token = request()->server->get('HTTP_AUTHORIZATION') ?: request()->server->get('REDIRECT_HTTP_AUTHORIZATION');
        if ($token && preg_match('/' . 'bearer' . '\s*(\S+)\b/i', $token, $matches)) {
            $token = $matches[1];
        }

        if (empty($token)) {
            $token = request()->cookie($token_name) ?: request()->get($token_name);
        }

        return $token;
    }


}

