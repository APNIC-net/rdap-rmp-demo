#!/usr/bin/perl

use warnings;
use strict;

use Crypt::JWT qw(decode_jwt);
use Crypt::PK::ECC;
use Data::Dumper;
use File::Slurp qw(read_file write_file);
use File::Temp qw(tempdir);
use JSON::XS qw(decode_json encode_json);
use List::Util qw(first);
use LWP::UserAgent;

use APNIC::RDAP::RMP::Client;
use APNIC::RDAP::RMP::Server;
use APNIC::RDAP::RMP::Serial qw(new_serial);

use Test::More tests => 21;

my $pid;
my $client_pid;
{
    my $db_path_ft = File::Temp->new();
    my $json = JSON::XS->new();
    $json->allow_tags(1);
    write_file($db_path_ft,
        $json->encode({serial => new_serial(32, 1)}));
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
        local(*STDERR);
        open(STDERR, ">/dev/null");
        $server->run();
        exit();
    }

    if (not ($client_pid = fork())) {
        local(*STDERR);
        open(STDERR, ">/dev/null");
        $client->run();
        exit();
    }

    write_file("$object_path/entity/TP137-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP137-AP',
        vcardArray      => [
            'vcard',
            [
                [ "version", {}, "text", "4.0" ],
                [ "fn", {}, "text", "Joe User" ],
                [ "kind", {}, "text", "individual" ],
                [ "adr", {
                    "label" => "blah st\nAU\n"
                  },
                  "text",
                  [ "PO box", "ext address", "street", "city", "region",
                    "1235", "new zealand" ] ],
                [ "email", {}, "text", "joe.user\@example.com" ]
            ]
        ],
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP137-AP' }
        ]
    }));
    write_file("$object_path/entity/TP138-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP138-AP',
        vcardArray      => [
            'vcard',
            [
                [ "version", {}, "text", "4.0" ],
                [ "fn", {}, "text", "John Citizen" ],
                [ "kind", {}, "text", "individual" ],
                [ "adr", {
                    "label" => "blah st\nAU\n"
                  },
                  "text",
                  [ "PO box", "ext address", "road", "locality", "region",
                    "1234", "australia" ] ],
                [ "email", {}, "text", "john.citizen\@example.com" ]
            ]
        ],
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP138-AP' }
        ]
    }));
    write_file("$object_path/entity/TP139-AP", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'entity',
        handle          => 'TP139-AP',
        vcardArray      => [
            'vcard',
            [
                [ "version", {}, "text", "4.0" ],
                [ "fn", {}, "text", "Jim Citizen" ],
                [ "fn", {}, "text", "Jim Citizen 2" ],
                [ "kind", {}, "text", "individual" ],
                [ "adr", {
                    "label" => "blah st\nAU\n"
                  },
                  "text",
                  [ "PO box", "ext address", "road", "locality", "region",
                    "1234", "australia" ] ],
                [ "email", {}, "text", "john.citizen\@example.com" ]
            ]
        ],
        links           => [
            { rel  => 'self',
              href => 'https://example.com/entity/TP139-AP' }
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
              roles           => [ 'registrant' ],
              links           => [
                  { rel => 'self',
                    href => 'https://example.com/entity/TP137-AP' }
              ] },
            { objectClassName => 'entity',
              handle          => 'TP138-AP',
              roles           => [ 'administrative' ],
              links           => [
                  { rel => 'self',
                    href => 'https://example.com/entity/TP138-AP' }
              ] }
        ],
    }));
    write_file("$object_path/domain/101.in-addr.arpa", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'domain',
        ldhName         => '101.in-addr.arpa',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/domain/101.in-addr.arpa' }
        ],
        entities        => [
            { objectClassName => 'entity',
              handle          => 'TP137-AP',
              roles           => [ 'technical' ],
              links           => [
                  { rel => 'self',
                    href => 'https://example.com/entity/TP137-AP' }
              ] },
            { objectClassName => 'entity',
              handle          => 'TP138-AP',
              roles           => [ 'administrative' ],
              links           => [
                  { rel => 'self',
                    href => 'https://example.com/entity/TP138-AP' }
              ] }
        ],
    }));
    write_file("$object_path/domain/102.in-addr.arpa", encode_json({
        rdapConformance => ['rdap_level_0'],
        objectClassName => 'domain',
        ldhName         => '102.in-addr.arpa',
        links           => [
            { rel  => 'self',
              href => 'https://example.com/domain/102.in-addr.arpa' }
        ],
        entities        => [
            { objectClassName => 'entity',
              handle          => 'TP139-AP',
              roles           => [ 'technical' ],
              links           => [
                  { rel => 'self',
                    href => 'https://example.com/entity/TP139-AP' }
              ] },
        ],
    }));

    my $ua = LWP::UserAgent->new();

    my $res = $ua->post($server_base.'/snapshot/generate');
    ok($res->is_success(), 'Generated snapshot successfully');
    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');
    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully');

    my $uri = URI->new($client_base.'/help');
    $res = $ua->get($uri);
    ok($res->is_success(), 'Got help response');
    my $data = decode_json($res->content());
    my @rsps = @{$data->{'reverse_search_properties'}};
    my $found_rsp =
        first { $_->{'relatedResourceType'} eq 'entity'
                    and $_->{'searchableResourceType'} eq 'domains'
                    and $_->{'property'} eq 'fn' }
            @rsps;
    ok($found_rsp, 'Found one expected reverse search property');

    $uri = URI->new($client_base.'/domains/reverse_search/entity');
    $uri->query_form(
        handle => 'TP*',
        role   => 'registrant'
    );
    $res = $ua->get($uri);
    my $tr = ok($res->is_success(), 'Domain search completed successfully');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'domainSearchResults'}->[0]->{'ldhName'},
        '100.in-addr.arpa',
        'Got correct result in search results');
    is(@{$data->{'domainSearchResults'}}, 1,
        'Got correct number of results');

    my @mappings =
        sort { $a->{'property'} cmp $b->{'property'} }
            @{$data->{'reverse_search_properties_mapping'}};
    is(@mappings, 2, 'Got two mappings');
    is($mappings[0]->{'property'}, 'handle',
        'Handle mapping is present');
    is($mappings[1]->{'property'}, 'role',
        'Role handle is present');

    $uri = URI->new($client_base.'/domains/reverse_search/entity');
    $uri->query_form(
        fn => 'Citizen*'
    );
    $res = $ua->get($uri);
    ok($res->is_success(), 'Domain search completed successfully');
    $data = decode_json($res->content());
    is(@{$data->{'domainSearchResults'}}, 0, 'No results found');

    $uri = URI->new($client_base.'/domains/reverse_search/entity');
    $uri->query_form(
        fn => 'John*'
    );
    $res = $ua->get($uri);
    ok($res->is_success(), 'Domain search completed successfully');
    $data = decode_json($res->content());
    my @names =
        sort
        map { $_->{'ldhName'} }
            @{$data->{'domainSearchResults'}};
    is_deeply(\@names,
              [qw(100.in-addr.arpa
                  101.in-addr.arpa)],
            'Got correct set of search results');

    $uri = URI->new($client_base.'/domains/reverse_search/entity');
    $uri->query_form(
        role  => 'technical',
        email => 'joe.user@example.com'
    );
    $res = $ua->get($uri);
    ok($res->is_success(), 'Domain search completed successfully');
    $data = decode_json($res->content());
    @names =
        sort
        map { $_->{'ldhName'} }
            @{$data->{'domainSearchResults'}};
    is_deeply(\@names,
              [qw(101.in-addr.arpa)],
            'Got correct set of search results');

    $uri = URI->new($client_base.'/domains/reverse_search/entity');
    $uri->query_form(
        email => [ 'joe.user@example.com',
                   'some.other.email@example.com' ]
    );
    $res = $ua->get($uri);
    ok($res->is_success(), 'Domain search completed successfully');
    $data = decode_json($res->content());
    is_deeply($data->{'domainSearchResults'}, [],
        'No entity matches two different email addresses');

    $uri = URI->new($client_base.'/domains/reverse_search/entity');
    $uri->query_form(
        fn => [ 'Jim Citizen',
                'Jim Citizen 2' ]
    );
    $res = $ua->get($uri);
    ok($res->is_success(), 'Domain search completed successfully');
    $data = decode_json($res->content());
    @names =
        sort
        map { $_->{'ldhName'} }
            @{$data->{'domainSearchResults'}};
    is_deeply(\@names,
              [qw(102.in-addr.arpa)],
            'Got correct set of search results');

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
