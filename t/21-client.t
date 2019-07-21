#!/usr/bin/perl

use warnings;
use strict;

use Crypt::JWT qw(encode_jwt decode_jwt);
use Crypt::PK::ECC;
use File::Slurp qw(read_file write_file);
use File::Temp qw(tempdir);
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json encode_json);
use LWP::UserAgent;

use APNIC::RDAP::RMP::Client;
use APNIC::RDAP::RMP::Serial qw(new_serial);

use Test::More tests => 35;

{
    my $db_path_client_ft = File::Temp->new();
    write_file($db_path_client_ft, '{}');

    my $object_path_client = tempdir();

    my $pk = Crypt::PK::ECC->new();
    $pk->generate_key('nistp256');
    my $public_pem = $pk->export_key_pem('public');
    my $private_pem = $pk->export_key_pem('private');

    my $encode_jwt = sub {
        my $data = encode_jwt(payload => encode_json($_[0]),
                              key => \$private_pem,
                              alg => 'ES256',
                              serialization => 'compact');
        return $data;
    };

    my $client = APNIC::RDAP::RMP::Client->new(
        unf_url     => 'http://test.alt/unf/unf.json',
        key         => $public_pem,
        db_path     => $db_path_client_ft->filename(),
        object_path => $object_path_client,
    );
    my $client_base = $client->{'url_base'};

    eval {
        $client->_object_to_link(
            { id => 'https://example.com/object',
              object => {} }
        );
    };
    my $error = $@;
    ok($error, 'Failed to get link for object (no object)');
    like($error, qr/objectClassName not set in object/,
        'Got correct error message');

    eval {
        $client->_object_to_link(
            { id => 'https://example.com/object',
              object => { objectClassName => 'unknown' } }
        );
    };
    $error = $@;
    ok($error, 'Failed to get link for object (unknown name)');
    like($error, qr/Unknown objectClassName/,
        'Got correct error message');

    eval {
        $client->_object_to_link(
            { id => 'https://example.com/object',
              object => { objectClassName => 'ip network' } }
        );
    };
    $error = $@;
    ok($error, 'Failed to get link for object (invalid URL)');
    like($error, qr/Name for object not found/,
        'Got correct error message');

    my %uri_lookup;
    {
        no warnings;
        no strict 'refs';
        *{'LWP::UserAgent::get'} = sub {
            my ($self, $uri) = @_;
            if ($uri_lookup{$uri}) {
                return $uri_lookup{$uri};
            } else {
                return HTTP::Response->new(HTTP_NOT_FOUND);
            }
        }
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({}));
        $uri_lookup{'http://test.alt/unf/unf.json'} = $res;

        eval { $client->_refresh(); };
        my $error = $@;
        ok($error, 'Got error on invalid UNF (no version)');
        like($error, qr/Unhandled UNF version/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({ version => 1 }));
        $uri_lookup{'http://test.alt/unf/unf.json'} = $res;

        eval { $client->_refresh(); };
        my $error = $@;
        ok($error, 'Got error on invalid UNF (no deltas)');
        like($error, qr/No deltas array in UNF/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version => 1,
            deltas  => [],
        }));
        $uri_lookup{'http://test.alt/unf/unf.json'} = $res;

        eval { $client->_refresh(); };
        my $error = $@;
        ok($error, 'Got error when no snapshot available');
        like($error, qr/Cannot initialise/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version  => 1,
            deltas   => [],
            snapshot => {
                uri    => 'http://test.alt/snapshot/snapshot.json',
                serial => 1
            },
        }));
        $uri_lookup{'http://test.alt/unf/unf.json'} = $res;

        my $ss_res = HTTP::Response->new(HTTP_OK);
        $ss_res->content($encode_jwt->({
            version => 1,
            serial  => 1,
            objects => [],
        }));
        $uri_lookup{'http://test.alt/snapshot/snapshot.json'} = $ss_res;

        eval { $client->_refresh(); };
        ok((not $@), 'Refreshed successfully');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version  => 1,
            deltas   => [],
            snapshot => {
                uri    => 'http://test.alt/snapshot/snapshot.json',
                serial => 1
            },
            deltas => [
                { uri    => 'http://test.alt/delta/delta3.json',
                  serial => 3 },
                { uri    => 'http://test.alt/delta/delta5.json',
                  serial => 5 },
            ],
        }));
        $uri_lookup{'http://test.alt/unf/unf.json'} = $res;

        eval { $client->_refresh(); };
        my $error = $@;
        ok($error, 'Got error when deltas do not form a sequence');
        like($error, qr/Deltas do not form a sequence/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version  => 1,
            deltas   => [],
            snapshot => {
                uri    => 'http://test.alt/snapshot/snapshot.json',
                serial => 1
            },
            deltas => [
                { uri    => 'http://test.alt/delta/delta3.json',
                  serial => 3 },
                { uri    => 'http://test.alt/delta/delta4.json',
                  serial => 4 },
            ],
        }));
        $uri_lookup{'http://test.alt/unf/unf.json'} = $res;

        eval { $client->_refresh(); };
        my $error = $@;
        ok($error, 'Got error on invalid snapshot serial');
        like($error, qr/Snapshot serial not in delta list, nor/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version  => 1,
            deltas   => [],
            deltas => [
                { uri    => 'http://test.alt/delta/delta3.json',
                  serial => 3 },
                { uri    => 'http://test.alt/delta/delta4.json',
                  serial => 4 },
            ],
        }));
        $uri_lookup{'http://test.alt/unf/unf.json'} = $res;

        eval { $client->_refresh(); };
        my $error = $@;
        ok($error, 'Got error on serial number gap (no snapshot)');
        like($error, qr/server must be reinitialised manually/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version  => 1,
            deltas   => [],
            snapshot => {
                uri    => 'http://test.alt/snapshot/snapshot.json',
                serial => 2
            },
            deltas => [
                { uri    => 'http://test.alt/delta/delta3.json',
                  serial => 3 },
                { uri    => 'http://test.alt/delta/delta4.json',
                  serial => 4 },
            ],
        }));
        $uri_lookup{'http://test.alt/unf/unf.json'} = $res;

        my $d3_res = HTTP::Response->new(HTTP_OK);
        $d3_res->content($encode_jwt->({
            version                  => 1,
            serial                   => 3,
            removed_objects          => [],
            added_or_updated_objects => []
        }));
        $uri_lookup{'http://test.alt/delta/delta3.json'} = $d3_res;

        my $d4_res = HTTP::Response->new(HTTP_OK);
        $d4_res->content($encode_jwt->({
            version                  => 1,
            serial                   => 4,
            removed_objects          => [],
            added_or_updated_objects => []
        }));
        $uri_lookup{'http://test.alt/delta/delta4.json'} = $d4_res;

        eval { $client->_refresh(); };
        ok((not $@), 'Refreshed successfully');
    }

    {
        eval { $client->_refresh(); };
        ok((not $@), 'Refreshed successfully (nothing to do)');
    }

    {
        eval { $client->_apply_delta({ uri => 'http://test.alt/invalid' }); };
        my $error = $@;
        ok($error, 'Got error on invalid delta URL');
        like($error, qr/Unable to fetch delta/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({}));
        my $uri = 'http://test.alt/delta/delta.json';
        $uri_lookup{$uri} = $res;

        eval { $client->_apply_delta({ uri => $uri }); };
        my $error = $@;
        ok($error, 'Got error on invalid delta (no version)');
        like($error, qr/Unhandled delta version/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({ version => 1 }));
        my $uri = 'http://test.alt/delta/delta.json';
        $uri_lookup{$uri} = $res;

        eval { $client->_apply_delta({ uri => $uri }); };
        my $error = $@;
        ok($error, 'Got error on invalid delta (no removed objects)');
        like($error, qr/No removed_objects array in delta/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version         => 1,
            removed_objects => [],
        }));
        my $uri = 'http://test.alt/delta/delta.json';
        $uri_lookup{$uri} = $res;

        eval { $client->_apply_delta({ uri => $uri }); };
        my $error = $@;
        ok($error, 'Got error on invalid delta (no updated objects)');
        like($error, qr/No added_or_updated_objects array in delta/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version                  => 1,
            removed_objects          => [],
            added_or_updated_objects => [],
            serial                   => (2 ** 32) + 1,
        }));
        my $uri = 'http://test.alt/delta/delta.json';
        $uri_lookup{$uri} = $res;

        eval { $client->_apply_delta({ uri => $uri }); };
        my $error = $@;
        ok($error, 'Got error on invalid delta (serial too large)');
        like($error, qr/Serial number.*is too large/,
            'Got correct error message');
    }

    {
        my $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version                  => 1,
            serial                   => 5,
            removed_objects          => [],
            added_or_updated_objects => [
              { id     => 'https://example.com/entity/TP137-AP',
                object => { rdapConformance => ['rdap_level_0'],
                            objectClassName => 'entity',
                            handle          => 'TP137-AP',
                            links           => [
                                { rel  => 'self',
                                  href => 'https://example.com/entity/TP137-AP' },
                                { rel  => 'related',
                                  href => 'https://example.com/entity/TP138-AP' },
                            ] } },
              { id     => 'https://example.com/entity/TP138-AP',
                object => { rdapConformance => ['rdap_level_0'],
                            objectClassName => 'entity',
                            handle          => 'TP138-AP',
                            links           => [
                                { rel  => 'self',
                                  href => 'https://example.com/entity/TP138-AP' },
                            ] } },
            ],
        }));
        my $uri = 'http://test.alt/delta/delta.json';
        $uri_lookup{$uri} = $res;

        eval { $client->_apply_delta({ uri => $uri }); };
        ok((not $@), 'Applied delta successfully');
        diag $@ if $@;

        $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version                  => 1,
            serial                   => 6,
            removed_objects          => [
                'https://example.com/entity/TP138-AP'
            ],
            added_or_updated_objects => []
        }));
        $uri = 'http://test.alt/delta/delta.json';
        $uri_lookup{$uri} = $res;

        eval { $client->_apply_delta({ uri => $uri }); };
        my $error = $@;
        ok($error, 'Got error on invalid delta (removing referenced object)');
        like($error, qr/object.*removed while link still needed/,
            'Got correct error message');

        $res = HTTP::Response->new(HTTP_OK);
        $res->content($encode_jwt->({
            version                  => 1,
            serial                   => 6,
            removed_objects          => [
                'https://example.com/entity/TP138-AP'
            ],
            added_or_updated_objects => [
              { id     => 'https://example.com/entity/TP138-AP',
                object => { rdapConformance => ['rdap_level_0'],
                            objectClassName => 'entity',
                            handle          => 'TP138-AP',
                            links           => [
                                { rel  => 'self',
                                  href => 'https://example.com/entity/TP138-AP' },
                            ] } },
            ],
        }));
        $uri = 'http://test.alt/delta/delta.json';
        $uri_lookup{$uri} = $res;

        eval { $client->_apply_delta({ uri => $uri }); };
        ok((not $@), 'Applied delta successfully (object re-added)');
    }
}

1;
