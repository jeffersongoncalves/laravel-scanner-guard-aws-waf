<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuardAwsWaf\Tests;

use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;
use JeffersonGoncalves\ScannerGuardAwsWaf\ScannerGuardAwsWafServiceProvider;
use JeffersonGoncalves\VisitorFingerprint\VisitorFingerprintServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            VisitorFingerprintServiceProvider::class,
            ScannerGuardServiceProvider::class,
            ScannerGuardAwsWafServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('cache.default', 'array');
        $app['config']->set('scanner-guard-aws-waf.credentials', ['key' => 'test', 'secret' => 'test']);
        $app['config']->set('scanner-guard-aws-waf.ipv4_arn', 'arn:aws:wafv2:sa-east-1:123456789012:regional/ipset/scanner-guard-v4/11111111-2222-3333-4444-555555555555');
        $app['config']->set('scanner-guard-aws-waf.ipv6_arn', 'arn:aws:wafv2:us-east-1:123456789012:global/ipset/scanner-guard-v6/66666666-7777-8888-9999-000000000000');
    }
}
