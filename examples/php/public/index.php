<?php

use Dotenv\Dotenv;
use Wallester\Example\App;

ini_set('display_errors', 1);

require __DIR__ . '/../vendor/autoload.php';

if (!class_exists(Dotenv::class) || !file_exists(__DIR__ . '/../.env')) {
    throw new \RuntimeException('Please run "make install"');
}

Dotenv::createImmutable(__DIR__ . '/../')->load();

(new App)->main();
