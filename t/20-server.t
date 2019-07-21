#!/usr/bin/perl

use warnings;
use strict;

use Crypt::JWT qw(decode_jwt);
use Crypt::PK::ECC;
use File::Slurp qw(read_file write_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json encode_json);
use LWP::UserAgent;

use APNIC::RDAP::RMP::Server;

use Test::More tests => 58;

my $pid;
{
    eval { APNIC::RDAP::RMP::Server->new() };
    my $error = $@;
    ok($error, 'Server requires db_path argument');
    like($error, qr/db_path is a required argument/,
        'Got correct error message');

    my $db_path_ft = File::Temp->new();
    unlink $db_path_ft;
    eval {
        APNIC::RDAP::RMP::Server->new(
            db_path => $db_path_ft->filename()
        )
    };
    $error = $@;
    ok($error, 'db_path must exist');
    like($error, qr/db_path does not exist/,
        'Got correct error message');

    write_file($db_path_ft->filename(), '{}');

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

    my $res = $server->save_db();
    ok($res, 'Saved server DB successfully');

    if (not ($pid = fork())) {
        local(*STDERR);
        open(STDERR, ">/dev/null");
        $server->run();
        exit();
    }

    my $ua = LWP::UserAgent->new();

    $res = $ua->post($server_base.'/invalid');
    is($res->code(), 404, 'Got 404 on invalid post');
    $res = $ua->get($server_base.'/invalid');
    is($res->code(), 404, 'Got 404 on invalid get');
    $res = $ua->put($server_base.'/invalid');
    is($res->code(), 404, 'Got 404 on invalid put');

    $res = $ua->post($server_base.'/unf/generate');
    ok((not $res->is_success()),
        'Unable to generate UNF where no snapshot is present');

    $res = $ua->post($server_base.'/snapshot/generate');
    ok($res->is_success(), 'Generated snapshot successfully');

    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    my $unf_res = $ua->get($server_base.'/unf/unf.json');
    ok($unf_res->is_success(), 'Retrieved UNF');
    my $unf_data = eval {
        decode_jwt(token => $unf_res->content(),
                   key   => \$public_pem)
    };
    ok((not $@), 'Decoded UNF successfully');

    my $snapshot = $unf_data->{'snapshot'};
    ok($snapshot, 'UNF contains snapshot data');
    is($snapshot->{'serial'}, 1,
        'Snapshot has correct serial');
    my $snapshot_uri = URI->new($snapshot->{'uri'});
    is($snapshot_uri->path(), '/snapshot/snapshot-1.json',
        'Snapshot has correct path');

    my $snapshot_res = $ua->get($snapshot_uri);
    ok($snapshot_res->is_success(), 'Retrieved snapshot');
    my $snapshot_data = eval {
        decode_jwt(token => $snapshot_res->content(),
                   key   => \$public_pem)
    };
    ok((not $@), 'Decoded snapshot successfully');

    my $objects = $snapshot_data->{'objects'};
    is((ref $objects), 'ARRAY', 'Snapshot contains object list');
    is_deeply($objects, [], 'Object list is empty');

    $res = $ua->post($server_base.'/delta/generate');
    ok($res->is_success(), 'Attempted to generate delta');
    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $unf_res = $ua->get($server_base.'/unf/unf.json');
    $unf_data =
        decode_jwt(token => $unf_res->content(),
                   key   => \$public_pem);
    my $deltas = $unf_data->{'deltas'};
    is((ref $deltas), 'ARRAY', 'UNF contains delta list');
    is_deeply($deltas, [], 'Delta list is empty '.
        '(no changes since snapshot generation)');

    write_file("$object_path/entity/TP137-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP137-AP',
    }));
    $res = $ua->post($server_base.'/delta/generate');
    ok((not $res->is_success()),
        'Unable to generate delta (no self link)');

    write_file("$object_path/entity/TP137-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP137-AP',
        links           => [ { rel => 'self' } ],
    }));
    $res = $ua->post($server_base.'/delta/generate');
    ok((not $res->is_success()),
        'Unable to generate delta (no self link href)');

    write_file("$object_path/entity/TP137-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP137-AP',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP137-AP' }
        ]
    }));

    $res = $ua->post($server_base.'/delta/generate');
    ok($res->is_success(), 'Generated delta successfully');
    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $unf_res = $ua->get($server_base.'/unf/unf.json');
    $unf_data =
        decode_jwt(token => $unf_res->content(),
                   key   => \$public_pem);
    $deltas = $unf_data->{'deltas'};
    is((ref $deltas), 'ARRAY', 'UNF contains delta list');
    is(@{$deltas}, 1, 'New delta present');

    my $delta_uri = URI->new($deltas->[0]->{'uri'});
    is($delta_uri->path(), '/delta/delta-2.json',
        'Delta has correct path');

    my $delta_res = $ua->get($delta_uri);
    my $delta_data =
        decode_jwt(token => $delta_res->content(),
                   key   => \$public_pem);

    my $new_objects = $delta_data->{'added_or_updated_objects'};
    is((ref $new_objects), 'ARRAY', 'Delta contains new objects');
    is(@{$new_objects}, 1, 'One new object present');
    like($new_objects->[0]->{'id'}, qr/.*\/TP137-AP/,
        'Delta contains correct object');

    $res = $ua->post($server_base.'/snapshot/generate');
    ok($res->is_success(), 'Generated snapshot successfully');
    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $unf_res = $ua->get($server_base.'/unf/unf.json');
    ok($unf_res->is_success(), 'Retrieved UNF');
    $unf_data =
        decode_jwt(token => $unf_res->content(),
                   key   => \$public_pem);

    $snapshot = $unf_data->{'snapshot'};
    ok($snapshot, 'UNF contains snapshot data');
    is($snapshot->{'serial'}, 3,
        'Snapshot has correct serial');

    $snapshot_res = $ua->get($snapshot->{'uri'});
    $snapshot_data =
        decode_jwt(token => $snapshot_res->content(),
                   key   => \$public_pem);
    $objects = $snapshot_data->{'objects'};

    is(@{$objects}, 1, 'Got one object in snapshot');
    like($objects->[0]->{'id'}, qr/.*\/TP137-AP/,
        'Snapshot contains correct object');

    write_file("$object_path/entity/TP137-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP137-AP',
        name            => 'name',
        links           => [
            { href => 'https://example.com/index.html' },
            { rel  => 'related',
              href => 'https://example.com/whois/TP137-AP' },
            { rel  => 'self',
              href => 'https://example.com/entity/TP137-AP' },

        ]
    }));

    $res = $ua->post($server_base.'/delta/generate');
    ok($res->is_success(), 'Generated delta successfully');
    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $unf_res = $ua->get($server_base.'/unf/unf.json');
    $unf_data =
        decode_jwt(token => $unf_res->content(),
                   key   => \$public_pem);
    $deltas = $unf_data->{'deltas'};
    is((ref $deltas), 'ARRAY', 'UNF contains delta list');
    is(@{$deltas}, 1, 'Delta for update is present');

    $delta_uri = URI->new($deltas->[0]->{'uri'});
    is($delta_uri->path(), '/delta/delta-4.json',
        'Delta has correct path');

    $delta_res = $ua->get($delta_uri);
    $delta_data =
        decode_jwt(token => $delta_res->content(),
                   key   => \$public_pem);

    $new_objects = $delta_data->{'added_or_updated_objects'};
    is((ref $new_objects), 'ARRAY', 'Delta contains new objects');
    is(@{$new_objects}, 1, 'One new object present');
    like($new_objects->[0]->{'id'}, qr/.*\/TP137-AP/,
        'Delta contains correct object');
    is($new_objects->[0]->{'object'}->{'name'}, 'name',
        'Object contains new field');

    unlink "$object_path/entity/TP137-AP";

    $res = $ua->post($server_base.'/delta/generate');
    ok($res->is_success(), 'Generated delta successfully');
    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');

    $unf_res = $ua->get($server_base.'/unf/unf.json');
    $unf_data =
        decode_jwt(token => $unf_res->content(),
                   key   => \$public_pem);
    $deltas = $unf_data->{'deltas'};
    is((ref $deltas), 'ARRAY', 'UNF contains delta list');
    is(@{$deltas}, 2, 'Delta for removal is present');

    $delta_uri = URI->new($deltas->[1]->{'uri'});
    is($delta_uri->path(), '/delta/delta-5.json',
        'Delta has correct path');

    $delta_res = $ua->get($delta_uri);
    $delta_data =
        decode_jwt(token => $delta_res->content(),
                   key   => \$public_pem);

    my $removed_objects = $delta_data->{'removed_objects'};
    is((ref $removed_objects), 'ARRAY', 'Delta contains removed objects');
    is(@{$removed_objects}, 1, 'One removed object present');
    like($removed_objects->[0], qr/.*\/TP137-AP/,
        'Delta contains correct object');

    my $res2 = $ua->post($server_base.'/shutdown');
    waitpid($pid, 0);
    $pid = 0;
}

END {
    if ($pid) {
        kill 15, $pid;
        waitpid $pid, 0;
    }
}

1;
