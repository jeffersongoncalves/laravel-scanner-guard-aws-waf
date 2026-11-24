<?php

declare(strict_types=1);

use Aws\WAFV2\WAFV2Client;
use Illuminate\Support\Facades\Process;
use JeffersonGoncalves\ScannerGuardAwsWaf\AwsWafSink;

// Needs Docker: SERVER_TESTS=1 vendor/bin/pest --filter=RealServer
// Moto is a mock of AWS: it proves the calls are well-formed and the lock token is right, not what AWS itself accepts.

it('replaces real ip sets over http', function () {
    $container = trim(Process::timeout(300)->run(['docker', 'run', '-d', '--rm', '-p', '127.0.0.1:5055:5000', 'motoserver/moto:latest'])->throw()->output());

    try {
        for ($i = 0; $i < 50 && ! @file_get_contents('http://127.0.0.1:5055/moto-api/data.json'); $i++) {
            usleep(200000);
        }

        $options = ['endpoint' => 'http://127.0.0.1:5055'];
        config(['scanner-guard-aws-waf.client' => $options]);
        $client = new WAFV2Client($options + ['region' => 'us-east-1', 'version' => 'latest', 'credentials' => ['key' => 'test', 'secret' => 'test']]);
        $sets = [];

        foreach (['ipv4' => 'REGIONAL', 'ipv6' => 'CLOUDFRONT'] as $version => $scope) {
            $sets[$version] = $client->createIPSet([
                'Name' => "scanner-guard-{$version}", 'Scope' => $scope, 'IPAddressVersion' => strtoupper($version), 'Addresses' => [], 'Description' => 'kept',
            ])['Summary'] + ['Scope' => $scope];
            config(["scanner-guard-aws-waf.{$version}_arn" => $sets[$version]['ARN']]);
        }

        $read = fn (string $version): array => $client->getIPSet(array_intersect_key($sets[$version], ['Name' => 1, 'Id' => 1, 'Scope' => 1]))['IPSet'];
        $entries = array_map(
            fn (string $ip): array => ['ip' => $ip, 'reason' => 'static', 'expires_at' => null],
            ['185.177.72.0/24', '203.0.113.7', '2001:db8::1'],
        );

        app(AwsWafSink::class)->sync($entries);

        expect($read('ipv4'))->toMatchArray(['Addresses' => ['185.177.72.0/24', '203.0.113.7/32'], 'Description' => 'kept'])
            ->and($read('ipv6')['Addresses'])->toBe(['2001:db8::1/128']);

        app(AwsWafSink::class)->sync([]);

        expect($read('ipv4')['Addresses'])->toBe([])->and($read('ipv6')['Addresses'])->toBe([]);
    } finally {
        Process::run(['docker', 'stop', '-t', '0', $container]);
    }
})->skip(getenv('SERVER_TESTS') === false, 'set SERVER_TESTS=1 (needs Docker)');
