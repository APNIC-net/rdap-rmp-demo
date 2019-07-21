#!/usr/bin/perl

use warnings;
use strict;

use Crypt::JWT qw(decode_jwt);
use Crypt::PK::ECC;
use File::Slurp qw(read_file write_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json encode_json);
use LWP::UserAgent;

use APNIC::RDAP::RMP::Client;
use APNIC::RDAP::RMP::Server;
use APNIC::RDAP::RMP::Serial qw(new_serial);

use Test::More tests => 53;

my $pid;
my $client_pid;
{
    my $db_path_ft = File::Temp->new();
    my $json = JSON::XS->new();
    $json->allow_tags(1);
    write_file($db_path_ft,
        $json->encode({serial => new_serial(32, 4294967293)}));
    my $db_path_client_ft = File::Temp->new();
    write_file($db_path_client_ft, '{}');

    my $object_path_client = tempdir();

    my $object_path = tempdir();
    for my $type (qw(ip autnum domain nameserver entity)) {
        mkdir "$object_path/$type" or die $!;
    }

    my $data_path = tempdir();
    for my $data_type (qw(unf snapshot delta)) {
        mkdir "$data_path/$data_type" or die $!;
    }

    my $pk = Crypt::PK::ECC->new();
    $pk->generate_key('nistp256');
    my $public_pem = $pk->export_key_pem('public');
    my $private_pem = $pk->export_key_pem('private');

    my $server = APNIC::RDAP::RMP::Server->new(
        refresh     => 3600,
        db_path     => $db_path_ft->filename(),
        object_path => $object_path,
        data_path   => $data_path,
        key         => $private_pem,
        defaults    => { port43 => 'example.com' },
    );

    my $server_base = $server->{'url_base'};

    my $client = APNIC::RDAP::RMP::Client->new(
        unf_url     => $server_base.'/unf/unf.json',
        key         => $public_pem,
        db_path     => $db_path_client_ft->filename(),
        object_path => $object_path_client,
    );
    my $client_base = $client->{'url_base'};

    if (not ($pid = fork())) {
        $server->run();
        exit();
    }

    if (not ($client_pid = fork())) {
        $client->run();
        exit();
    }

    write_file("$object_path/entity/TP137-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP137-AP',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP137-AP' }
        ]
    }));
    write_file("$object_path/ip/10.0.0.0", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'ip network',
        handle          => 'RFC 1918 space',
        ipVersion       => 'v4',
        startAddress    => '10.0.0.0',
        endAddress      => '10.0.0.255',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/ip/10.0.0.0/24' }
        ]
    }));
    write_file("$object_path/ip/v6obj", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'ip network',
        handle          => 'zero',
        ipVersion       => 'v6',
        startAddress    => '::',
        endAddress      => '::',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/ip/::' }
        ]
    }));
    write_file("$object_path/autnum/AS1", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'autnum',
        handle          => 'AS1',
        startAutnum     => 1,
        endAutnum       => 1,
        links           => [
            { rel  => 'self',
              href => 'https://example.com/autnum/1' }
        ]
    }));
    write_file("$object_path/autnum/ASRANGE", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'autnum',
        handle          => 'AS1-AS1000',
        startAutnum     => 1,
        endAutnum       => 1000,
        links           => [
            { rel  => 'self',
              href => 'https://example.com/autnum/1-1000' }
        ]
    }));
    write_file("$object_path/domain/100.in-addr.arpa", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'domain',
        ldhName         => '100.in-addr.arpa',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/domain/100.in-addr.arpa' }
        ],
        entities        => [
            { objectClassName => 'entity',
              handle          => 'TP137-AP',
              links           => [
                  { rel => 'self',
                    href => 'https://example.com/entity/TP137-AP' }
              ] }
        ],
    }));
    write_file("$object_path/nameserver/ns2.apnic.net", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'nameserver',
        ldhName         => 'ns2.apnic.net',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/nameserver/ns2.apnic.net' }
        ]
    }));

    my $ua = LWP::UserAgent->new();
    my $res = $ua->get($client_base.'/invalid');
    ok((not $res->is_success()), 'Got 404 on invalid get');
    $res = $ua->post($client_base.'/invalid');
    ok((not $res->is_success()), 'Got 404 on invalid post');
    $res = $ua->put($client_base.'/invalid');
    ok((not $res->is_success()), 'Got 404 on invalid put');

    $res = $ua->post($server_base.'/snapshot/generate');
    ok($res->is_success(), 'Generated snapshot successfully');

    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully');

    $res = $ua->head($client_base.'/entity/TP137-AP');
    ok($res->is_success(), 'Retrieved entity from client (head)');
    ok((not $res->content()), 'No content returned for head request');

    $res = $ua->get($client_base.'/entity/TP137-AP');
    ok($res->is_success(), 'Retrieved entity from client');
    my $entity = decode_json($res->content());
    is($entity->{'handle'}, 'TP137-AP', 'Got entity from client (handle)');
    ok((not exists $entity->{'name'}), 'Entity has no name');

    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully (no changes)');

    $res = $ua->get($client_base.'/entity/TP137-AP');
    ok($res->is_success(), 'Retrieved entity from client');
    $entity = decode_json($res->content());
    is($entity->{'handle'}, 'TP137-AP', 'Got entity from client (handle)');

    $res = $ua->get($client_base.'/ip/10.0.0.0');
    my $result = ok($res->is_success(), 'Retrieved IP from client');
    $entity = decode_json($res->content());
    is($entity->{'startAddress'}, '10.0.0.0', 'Got start address for IP');

    write_file("$object_path/entity/TP137-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP137-AP',
        name            => 'name',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP137-AP' }
        ]
    }));
    write_file("$object_path/entity/TP138-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP138-AP',
        name            => 'name',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP138-AP' }
        ]
    }));
    write_file("$object_path/entity/TP139-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP139-AP',
        name            => 'name',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP139-AP' }
        ]
    }));
    unlink("$object_path/ip/10.0.0.0");

    $res = $ua->post($server_base.'/delta/generate');
    ok($res->is_success(), 'Generated snapshot successfully');

    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully');

    $res = $ua->get($client_base.'/entity/TP137-AP');
    ok($res->is_success(), 'Retrieved entity from client');
    $entity = decode_json($res->content());
    is($entity->{'handle'}, 'TP137-AP', 'Got entity from client (handle)');
    is($entity->{'name'}, 'name', 'Got updated entity from client (name)');

    $res = $ua->post($server_base.'/snapshot/generate');
    ok($res->is_success(), 'Generated snapshot successfully');

    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully');

    $res = $ua->get($client_base.'/entity/TP137-AP');
    ok($res->is_success(), 'Retrieved entity from client');
    $entity = decode_json($res->content());
    is($entity->{'handle'}, 'TP137-AP', 'Got entity from client (handle)');
    is($entity->{'name'}, 'name', 'Got updated entity from client (name)');

    $res = $ua->get($client_base.'/ip/::');
    ok($res->is_success(), 'Retrieved IP from client');
    $entity = decode_json($res->content());
    is($entity->{'startAddress'}, '::', 'Got start address for IP');

    $res = $ua->get($client_base.'/autnum/1');
    ok($res->is_success(), 'Retrieved autnum from client');
    $entity = decode_json($res->content());
    is($entity->{'endAutnum'}, 1, 'Got expected autnum');

    $res = $ua->get($client_base.'/autnum/2');
    ok($res->is_success(), 'Retrieved AS block from client');
    $entity = decode_json($res->content());
    is($entity->{'endAutnum'}, '1000', 'Got expected AS block');

    $res = $ua->get($client_base.'/domain/100.in-addr.arpa');
    ok($res->is_success(), 'Retrieved domain from client');
    $entity = decode_json($res->content());
    is($entity->{'ldhName'}, '100.in-addr.arpa', 'Got expected domain');

    $res = $ua->get($client_base.'/nameserver/ns2.apnic.net');
    ok($res->is_success(), 'Retrieved nameserver from client');
    $entity = decode_json($res->content());
    is($entity->{'ldhName'}, 'ns2.apnic.net', 'Got expected nameserver');
    is($entity->{'port43'}, 'example.com', 'port43 value set correctly');

    write_file("$object_path/entity/TP139-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP139-AP',
        name            => 'name139',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP139-AP' }
        ]
    }));

    $res = $ua->post($server_base.'/delta/generate');
    ok($res->is_success(), 'Generated delta successfully');

    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully');

    $res = $ua->get($client_base.'/entity/TP139-AP');
    ok($res->is_success(), 'Retrieved entity from client');
    $entity = decode_json($res->content());
    is($entity->{'handle'}, 'TP139-AP', 'Got entity from client (handle)');
    is($entity->{'name'}, 'name139', 'Got updated entity from client (name)');

    unlink "$object_path/entity/TP139-AP";
    unlink "$object_path/entity/TP138-AP";
    unlink "$object_path/entity/TP137-AP";
    unlink "$object_path/nameserver/ns2.apnic.net";
    unlink "$object_path/domain/100.in-addr.arpa";
    unlink "$object_path/autnum/ASRANGE";
    unlink "$object_path/autnum/AS1";
    unlink "$object_path/ip/v6obj";

    $res = $ua->post($server_base.'/delta/generate');
    ok($res->is_success(), 'Generated delta successfully');

    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully');

    $res = $ua->get($client_base.'/entity/TP139-AP');
    ok((not $res->is_success()), 'Entity removed');
    $res = $ua->get($client_base.'/domain/10.in-addr.arpa');
    ok((not $res->is_success()), 'Domain removed');
    $res = $ua->get($client_base.'/autnum/1');
    ok((not $res->is_success()), 'ASN removed');
    $res = $ua->get($client_base.'/autnum/10');
    ok((not $res->is_success()), 'AS range removed');
    $res = $ua->get($client_base.'/ip/::');
    ok((not $res->is_success()), 'IPv6 object removed');

    my $res2 = $ua->post($server_base.'/shutdown');
    waitpid($pid, 0);
    $pid = 0;

    my $res1 = $ua->post($client_base.'/shutdown');
    waitpid($client_pid, 0);
    $client_pid = 0;
}

END {
    if ($pid) {
        kill 15, $pid;
        waitpid $pid, 0;
    }
    if ($client_pid) {
        kill 15, $client_pid;
        waitpid $client_pid, 0;
    }
}

1;
