<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | IP Sets
    |--------------------------------------------------------------------------
    |
    | ARNs of the AWS WAF IP sets the sink owns, one per IP version (AWS allows
    | no mixed set). Region and scope come from the ARN. The sink REPLACES the
    | whole set on every change: give it sets of its own. Null = leave that IP
    | version to the app; at least one is required.
    |
    */
    'ipv4_arn' => env('SCANNER_GUARD_AWS_WAF_IPV4_ARN'),

    'ipv6_arn' => env('SCANNER_GUARD_AWS_WAF_IPV6_ARN'),

    /*
    |--------------------------------------------------------------------------
    | Credentials
    |--------------------------------------------------------------------------
    |
    | Needs wafv2:GetIPSet and wafv2:UpdateIPSet on those sets. Without a key,
    | the AWS SDK looks for credentials itself (environment, profile, EC2, ECS
    | or EKS role).
    |
    */
    'credentials' => [
        'key' => env('AWS_ACCESS_KEY_ID'),
        'secret' => env('AWS_SECRET_ACCESS_KEY'),
        'token' => env('AWS_SESSION_TOKEN'),
    ],

    /*
    |--------------------------------------------------------------------------
    | SDK Client
    |--------------------------------------------------------------------------
    |
    | Extra options for Aws\WAFV2\WAFV2Client (e.g. "endpoint", "profile").
    |
    */
    'client' => [
        'http' => ['connect_timeout' => 5, 'timeout' => 10],
    ],

];
