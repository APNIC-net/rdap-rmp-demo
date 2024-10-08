#!/usr/bin/perl

use warnings;
use strict;

use Crypt::JWT qw(decode_jwt);
use Crypt::PK::ECC;
use File::Slurp qw(read_file write_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json encode_json);
use List::Util qw(first);
use LWP::UserAgent;

use APNIC::RDAP::RMP::Server;

use Test::More tests => 18;

my $pid;
{
    my $db_path_ft = File::Temp->new();
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
        if (not $ENV{'APNIC_DEBUG'}) {
            local(*STDERR);
            open(STDERR, ">/dev/null");
        }
        $server->run();
        exit();
    }

    my $ua = LWP::UserAgent->new();

    # Server has no data.

    $res = $ua->get($server_base.'/nroBulkRdap1');
    ok($res->is_success(), 'Got bulk RDAP data');
    is($res->headers()->header('Content-Type'),
        'application/json-seq',
        'Got correct content type');
    my $content = $res->decoded_content();
    ok($content =~ /^\x1E/,
        'Content begins with ASCII record separated');
    $content =~ s/^.//;
    my @objects = map { decode_json($_) } split /\x0A\x1E/, $content;
    is(@objects, 1, 'Got one object (metadata)');
    my $metadata = $objects[0];
    my $version_id = $metadata->{'versionId'};
    ok($version_id, 'Metadata contains version ID');

    $res = $ua->get($server_base.'/nroBulkRdap1');
    ok($res->is_success(), 'Got bulk RDAP data (2)');
    $content = $res->decoded_content();
    $content =~ s/^.//;
    @objects = map { decode_json($_) } split /\x0A\x1E/, $content;
    is(@objects, 1, 'Still only one object (metadata)');
    $metadata = $objects[0];
    is($metadata->{'versionId'}, $version_id,
        'Version ID unchanged');

    # Add an object to the server.

    write_file("$object_path/entity/TP137-AP", encode_json({
        rdapConformance => ['rdap_level_0', 'nro_rdap_profile_0'],
        objectClassName => 'entity',
        handle          => 'TP137-AP',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP137-AP' }
        ]
    }));

    $res = $ua->get($server_base.'/nroBulkRdap1');
    ok($res->is_success(), 'Got bulk RDAP data (3)');
    $content = $res->decoded_content();
    $content =~ s/^.//;
    @objects = map { decode_json($_) } split /\x0A\x1E/, $content;
    is(@objects, 2, 'Got two objects in response');
    $metadata = $objects[0];
    isnt($metadata->{'versionId'}, $version_id,
        'Version ID now different');
    $version_id = $metadata->{'versionId'};
    ok((first { $_ eq 'nro_rdap_profile_0' }
        @{$metadata->{'rdapConformance'}}),
        'Metadata contains new conformance code');
    is($metadata->{'objectCount'}, 1,
        'Metadata object count is correct');
    my $entity = $objects[1];
    is($entity->{'handle'}, 'TP137-AP',
        'Got expected entity in response');

    # Get a specific type of object from the server.

    $res = $ua->get($server_base.'/nroBulkRdap1?objectClass=domain');
    ok($res->is_success(), 'Got bulk RDAP data (domain only)');
    $content = $res->decoded_content();
    $content =~ s/^.//;
    @objects = map { decode_json($_) } split /\x0A\x1E/, $content;
    is(@objects, 1, 'Got one object (metadata)');
    $metadata = $objects[0];
    is($metadata->{'versionId'}, $version_id,
        'Version ID unchanged');

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
