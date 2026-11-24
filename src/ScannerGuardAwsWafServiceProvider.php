<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuardAwsWaf;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class ScannerGuardAwsWafServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-scanner-guard-aws-waf')
            ->hasConfigFile('scanner-guard-aws-waf');
    }
}
