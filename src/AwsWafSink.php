<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuardAwsWaf;

use Aws\WAFV2\WAFV2Client;
use Illuminate\Support\Facades\Log;
use JeffersonGoncalves\ScannerGuard\Contracts\DenylistSink;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use RuntimeException;

/**
 * Replaces AWS WAF IP sets (one for IPv4, one for IPv6) with the denylist; a
 * web ACL rule referencing them then blocks those IPs. A set is only replaced
 * when its content changed since the last successful replace.
 */
class AwsWafSink implements DenylistSink
{
    public const HASH_KEY = 'scanner-guard-aws-waf:synced-hash:';

    /** AWS quota, not adjustable. */
    public const MAX_ADDRESSES = 10000;

    public function __construct(protected ScannerGuard $scannerGuard) {}

    public function sync(array $entries): void
    {
        $arns = array_filter([
            4 => (string) config('scanner-guard-aws-waf.ipv4_arn'),
            6 => (string) config('scanner-guard-aws-waf.ipv6_arn'),
        ], fn (string $arn): bool => $arn !== '');

        if ($arns === []) {
            throw new RuntimeException('Set scanner-guard-aws-waf.ipv4_arn and/or ipv6_arn.');
        }

        foreach ($arns as $family => $arn) {
            $this->replace($arn, $this->addresses($entries, $family));
        }
    }

    /**
     * @param  list<string>  $addresses
     */
    protected function replace(string $arn, array $addresses): void
    {
        $hash = hash('sha256', (string) json_encode($addresses));
        $cache = $this->scannerGuard->cache();

        if ($cache->get(self::HASH_KEY.$arn) === $hash) {
            return;
        }

        if (! preg_match('#^arn:[\w-]+:wafv2:([\w-]+):\d+:(regional|global)/ipset/([\w-]+)/([\w-]+)$#', $arn, $matches)) {
            throw new RuntimeException("Not an AWS WAF IP set ARN: {$arn}");
        }

        [, $region, $scope, $name, $id] = $matches;
        $target = ['Name' => $name, 'Id' => $id, 'Scope' => $scope === 'global' ? 'CLOUDFRONT' : 'REGIONAL'];
        $client = $this->client($region);
        $set = $client->getIPSet($target);
        $description = (string) $set->search('IPSet.Description');

        $client->updateIPSet($target + [
            'Addresses' => $addresses,
            'LockToken' => (string) $set->get('LockToken'),
        ] + ($description === '' ? [] : ['Description' => $description])); // left out, AWS would clear it

        $cache->forever(self::HASH_KEY.$arn, $hash);
    }

    /**
     * The family's entries as the CIDRs AWS takes: always with a prefix, no /0.
     *
     * @param  list<array{ip: string, reason: string, expires_at: string|null}>  $entries
     * @return list<string>
     */
    protected function addresses(array $entries, int $family): array
    {
        $addresses = [];

        foreach ($entries as $entry) {
            [$address, $prefix] = array_pad(explode('/', $entry['ip'], 2), 2, null);

            if ((str_contains($address, ':') ? 6 : 4) !== $family) {
                continue;
            }

            if ($prefix !== null && (int) $prefix === 0) {
                Log::warning('scanner-guard-aws-waf: skipped an entry AWS WAF rejects', ['ip' => $entry['ip']]);

                continue;
            }

            $addresses[$this->cidr($address, (int) ($prefix ?? ($family === 6 ? 128 : 32)))] = true;
        }

        $addresses = array_map('strval', array_keys($addresses));

        if (count($addresses) > self::MAX_ADDRESSES) {
            // Static entries and the longest bans come first, so those are the ones kept.
            Log::warning('scanner-guard-aws-waf: more entries than an IP set holds, the last ones were left out', ['entries' => count($addresses)]);

            $addresses = array_slice($addresses, 0, self::MAX_ADDRESSES);
        }

        return $addresses;
    }

    /**
     * Network address of the range, host bits cleared.
     */
    protected function cidr(string $address, int $prefix): string
    {
        $bytes = (string) inet_pton($address);
        $mask = str_pad(str_repeat("\xff", intdiv($prefix, 8)).($prefix % 8 === 0 ? '' : chr(0xFF << (8 - $prefix % 8) & 0xFF)), strlen($bytes), "\0");

        return inet_ntop($bytes & $mask).'/'.$prefix;
    }

    protected function client(string $region): WAFV2Client
    {
        $credentials = (array) config('scanner-guard-aws-waf.credentials');

        return new WAFV2Client(['region' => $region, 'version' => 'latest']
            // Without a key, the SDK's default chain: environment, profile, instance/task role.
            + (empty($credentials['key']) ? [] : ['credentials' => $credentials])
            + (array) config('scanner-guard-aws-waf.client'));
    }
}
