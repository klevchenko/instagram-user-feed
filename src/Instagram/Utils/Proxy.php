<?php

declare(strict_types=1);

namespace Instagram\Utils;

class Proxy
{
    public static $proxy = '';

    public static function set($proxy): void
    {
        self::$proxy = $proxy;
    }

    public static function get(): string
    {
        print_r('proxy ' . self::$proxy . "\n");
        return self::$proxy;
    }
}