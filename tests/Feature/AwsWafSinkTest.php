<?php

declare(strict_types=1);

use Aws\CommandInterface;
use Aws\MockHandler;
use Aws\Result;
use Aws\WAFV2\Exception\WAFV2Exception;
use Illuminate\Support\Facades\Log;
use JeffersonGoncalves\ScannerGuardAwsWaf\AwsWafSink;

/**
 * @return list<array{string, array<string, mixed>}> every call since fakeAws()
 */
function &calls(): array
{
    static $calls = [];

    return $calls;
}

/**
 * Answers every call, recording it; $fail makes the nth one throw.
 */
function fakeAws(string $description = '', ?int $fail = null): void
{
    $calls = &calls();
    $calls = [];

    $answer = function (CommandInterface $command) use ($description, $fail, &$calls) {
        $calls[] = [$command->getName(), array_diff_key($command->toArray(), ['@http' => 1, '@context' => 1])];

        if (count($calls) === $fail) {
            return new WAFV2Exception('stale lock token', $command, ['code' => 'WAFOptimisticLockException']);
        }

        return $command->getName() === 'GetIPSet'
            ? new Result(['IPSet' => ['Description' => $description], 'LockToken' => 'lock-'.count($calls)])
            : new Result(['NextLockToken' => 'next']);
    };

    config(['scanner-guard-aws-waf.client' => ['handler' => new MockHandler(array_fill(0, 20, $answer)), 'retries' => 0]]);
}

/**
 * @return list<list<string>> the Addresses of every UpdateIPSet
 */
function updates(): array
{
    return array_values(array_map(
        fn (array $call): array => $call[1]['Addresses'],
        array_filter(calls(), fn (array $call): bool => $call[0] === 'UpdateIPSet'),
    ));
}

function sink(): AwsWafSink
{
    return app(AwsWafSink::class);
}

function entry(string $ip): array
{
    return ['ip' => $ip, 'reason' => 'static', 'expires_at' => null];
}

it('replaces each ip set with the entries of its version, as cidrs', function () {
    fakeAws();

    sink()->sync([entry('185.177.72.0/24'), entry('2001:db8::/32'), entry('203.0.113.7'), entry('2001:db8::1')]);

    expect(calls())->toBe([
        ['GetIPSet', ['Name' => 'scanner-guard-v4', 'Id' => '11111111-2222-3333-4444-555555555555', 'Scope' => 'REGIONAL']],
        ['UpdateIPSet', [
            'Name' => 'scanner-guard-v4', 'Id' => '11111111-2222-3333-4444-555555555555', 'Scope' => 'REGIONAL',
            'Addresses' => ['185.177.72.0/24', '203.0.113.7/32'], 'LockToken' => 'lock-1',
        ]],
        ['GetIPSet', ['Name' => 'scanner-guard-v6', 'Id' => '66666666-7777-8888-9999-000000000000', 'Scope' => 'CLOUDFRONT']],
        ['UpdateIPSet', [
            'Name' => 'scanner-guard-v6', 'Id' => '66666666-7777-8888-9999-000000000000', 'Scope' => 'CLOUDFRONT',
            'Addresses' => ['2001:db8::/32', '2001:db8::1/128'], 'LockToken' => 'lock-3',
        ]],
    ]);
});

it('calls the region of the arn', function () {
    $regions = [];
    $handler = new MockHandler(array_fill(0, 4, function (CommandInterface $command, $request) use (&$regions) {
        $regions[] = $request->getUri()->getHost();

        return new Result(['LockToken' => 'x']);
    }));
    config(['scanner-guard-aws-waf.client' => ['handler' => $handler]]);

    sink()->sync([]);

    expect(array_values(array_unique($regions)))->toBe(['wafv2.sa-east-1.amazonaws.com', 'wafv2.us-east-1.amazonaws.com']);
});

it('keeps the description of the set', function () {
    fakeAws('Managed by scanner-guard');

    sink()->sync([]);

    expect(calls()[1][1]['Description'])->toBe('Managed by scanner-guard');
});

it('clears host bits and drops the duplicates that makes', function () {
    fakeAws();

    sink()->sync(array_map(entry(...), ['10.1.2.3/8', '10.0.0.0/8', '10.255.255.255/9', '192.0.2.7/31', '192.0.2.7', '2001:DB8:0::f/33', '2001:db8::/128']));

    expect(updates())->toBe([
        ['10.0.0.0/8', '10.128.0.0/9', '192.0.2.6/31', '192.0.2.7/32'],
        ['2001:db8::/33', '2001:db8::/128'],
    ]);
});

it('skips the /0 AWS rejects', function () {
    fakeAws();
    Log::spy();

    sink()->sync([entry('0.0.0.0/0'), entry('::/0'), entry('203.0.113.7')]);

    expect(updates())->toBe([['203.0.113.7/32'], []]);
    Log::shouldHaveReceived('warning')->with('scanner-guard-aws-waf: skipped an entry AWS WAF rejects', Mockery::any())->twice();
});

it('keeps the first 10000 entries, the most an ip set holds', function () {
    fakeAws();
    Log::spy();

    sink()->sync(array_map(fn (int $i): array => entry(long2ip(ip2long('10.0.0.0') + $i)), range(1, 10001)));

    expect(updates()[0])->toHaveCount(10000)->and(updates()[0][0])->toBe('10.0.0.1/32')
        ->and(updates()[0][9999])->toBe('10.0.39.16/32');
    Log::shouldHaveReceived('warning')->with('scanner-guard-aws-waf: more entries than an IP set holds, the last ones were left out', ['entries' => 10001])->once();
});

it('calls AWS only for the set that changed', function () {
    fakeAws();

    sink()->sync([entry('203.0.113.7')]);
    sink()->sync([entry('203.0.113.7')]);
    sink()->sync([entry('203.0.113.7'), entry('2001:db8::1')]);

    expect(updates())->toBe([['203.0.113.7/32'], [], ['2001:db8::1/128']])
        ->and(calls())->toHaveCount(6);
});

it('throws when AWS refuses the replace, so the next sync retries', function () {
    fakeAws(fail: 2);

    expect(fn () => sink()->sync([entry('203.0.113.7')]))->toThrow(WAFV2Exception::class);

    sink()->sync([entry('203.0.113.7')]);

    expect(updates())->toBe([['203.0.113.7/32'], ['203.0.113.7/32'], []]);
});

it('leaves an ip version without a set to the app', function () {
    config(['scanner-guard-aws-waf.ipv6_arn' => null]);
    fakeAws();

    sink()->sync([entry('2001:db8::1'), entry('203.0.113.7')]);

    expect(updates())->toBe([['203.0.113.7/32']]);
});

it('refuses to run without a set or with another kind of arn', function (?string $arn, string $message) {
    config(['scanner-guard-aws-waf.ipv4_arn' => $arn, 'scanner-guard-aws-waf.ipv6_arn' => null]);
    fakeAws();

    expect(fn () => sink()->sync([]))->toThrow(RuntimeException::class, $message);
    expect(calls())->toBe([]);
})->with([
    [null, 'Set scanner-guard-aws-waf.ipv4_arn'],
    ['arn:aws:wafv2:us-east-1:123456789012:regional/webacl/acl/11111111-2222-3333-4444-555555555555', 'Not an AWS WAF IP set ARN'],
]);

it('is driven by scanner-guard:sync-denylist', function () {
    fakeAws();
    config([
        'scanner-guard.driver' => 'http', // no database needed: bans come from the (empty) last pull
        'scanner-guard.sinks' => [AwsWafSink::class],
        'scanner-guard.ip_blocklist' => ['185.177.72.69'],
    ]);

    $this->artisan('scanner-guard:sync-denylist')->assertSuccessful();

    expect(updates())->toBe([['185.177.72.69/32'], []]);
});
