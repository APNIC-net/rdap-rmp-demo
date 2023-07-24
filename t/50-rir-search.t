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

use Test::More tests => 86;

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
        if (not $ENV{'APNIC_DEBUG'}) {
            local(*STDERR);
            open(STDERR, ">/dev/null");
            $server->run();
            exit();
        } else {
            $server->run();
            exit();
        }
    }

    if (not ($client_pid = fork())) {
        if (not $ENV{'APNIC_DEBUG'}) {
            local(*STDERR);
            open(STDERR, ">/dev/null");
            $client->run();
            exit();
        } else {
            $client->run();
            exit();
        }
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

    my $make_ip = sub {
        my ($range, $name, $entity_role, $status) = @_;
        $entity_role ||= 'registrant';
        my $net_ip = Net::IP::XS->new($range);
        my $start_address = $net_ip->ip();
        my $end_address = $net_ip->last_ip();
        my $filename = $net_ip->prefix();
        $filename =~ s/\//-/g;
        write_file("$object_path/ip/$filename", encode_json({
            rdapConformance => ['rdap_level_0'],
            objectClassName => 'ip network',
            startAddress    => $start_address,
            endAddress      => $end_address,
            name            => $name,
            handle          => "HANDLE-".(uc $name),
            ipVersion       => (($net_ip->version() == 4) ? 'v4' : 'v6'),
            links           => [
                { rel  => 'self',
                  href => "https://example.com/ip/$range" }
            ],
            entities        => [
                { objectClassName => 'entity',
                  handle          => 'TP137-AP',
                  roles           => [ $entity_role ],
                  links           => [
                      { rel => 'self',
                        href => 'https://example.com/entity/TP137-AP' }
                  ] },
            ],
            ($status)
                ? (status => [ $status ])
                : ()
        }));
    };

    my $make_autnum = sub {
        my ($range, $name, $entity_role) = @_;
        $entity_role ||= 'registrant';
        my ($start, $end) =
            ($range =~ /(.*)-(.*)/)
                ? ($1, $2)
                : ($range, $range);
        write_file("$object_path/autnum/$range", encode_json({
            rdapConformance => ['rdap_level_0'],
            objectClassName => 'autnum',
            startAutnum     => $start,
            endAutnum       => $end,
            name            => $name,
            handle          => "HANDLE-".(uc $name),
            links           => [
                { rel  => 'self',
                  href => "https://example.com/autnum/$range" }
            ],
            entities        => [
                { objectClassName => 'entity',
                  handle          => 'TP137-AP',
                  roles           => [ $entity_role ],
                  links           => [
                      { rel => 'self',
                        href => 'https://example.com/entity/TP137-AP' }
                  ] },
            ],
        }));
    };

    my $make_domain = sub {
        my ($ldh_name, $name, $entity_role) = @_;
        $entity_role ||= 'registrant';
        write_file("$object_path/domain/$ldh_name", encode_json({
            rdapConformance => ['rdap_level_0'],
            objectClassName => 'domain',
            ldhName         => $ldh_name,
            name            => $name,
            handle          => "HANDLE-".(uc $name),
            links           => [
                { rel  => 'self',
                  href => "https://example.com/domain/$ldh_name" }
            ],
            entities        => [
                { objectClassName => 'entity',
                  handle          => 'TP137-AP',
                  roles           => [ $entity_role ],
                  links           => [
                      { rel => 'self',
                        href => 'https://example.com/entity/TP137-AP' }
                  ] },
            ],
        }));
    };

    $make_ip->('1.0.0.0/8', 'top', 'technical', 'inactive');

    $make_ip->('1.0.0.0/24', 'middle1', undef, 'active');
    $make_ip->('1.0.1.0/24', 'middle2', 'technical', 'active');
    $make_ip->('1.0.2.0/24', 'middle3', 'administrative', 'active');
    $make_ip->('1.0.3.0/24', 'middle4', 'administrative', 'inactive');

    $make_ip->('1.0.2.0/25', 'lower1', 'technical', 'active');
    $make_ip->('1.0.2.128/25', 'lower2', undef, 'active');

    $make_ip->('1.0.2.64/26', 'bottom', undef, 'active');

    $make_autnum->(1, 'first');
    $make_autnum->(2, 'second');
    $make_autnum->(3, 'third');
    $make_autnum->(4, 'fourth');

    $make_autnum->('10-19', 'top', 'technical');
    $make_autnum->('10-15', 'middle', 'technical');
    $make_autnum->('16-19', 'middle', 'technical');
    $make_autnum->(10, ',bottom', 'administrative');
    $make_autnum->(11, ',bottom', 'administrative');
    $make_autnum->(18, ',bottom', 'administrative');
    $make_autnum->(19, ',bottom', 'administrative');

    $make_domain->('1.in-addr.arpa', 'top', 'technical');
    $make_domain->('10.1.in-addr.arpa', 'middle');
    $make_domain->('20.1.in-addr.arpa', 'middle', 'technical');
    $make_domain->('10.10.1.in-addr.arpa', 'middle', 'administrative');
    $make_domain->('20.10.1.in-addr.arpa', 'middle', 'technical');

    my $ua = LWP::UserAgent->new();

    my $res = $ua->post($server_base.'/snapshot/generate');
    ok($res->is_success(), 'Generated snapshot successfully');
    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');
    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully');

    # ip-up.

    my $uri = URI->new($client_base.'/ips/rir_search/up/1.0.0.0/24');
    $res = $ua->get($uri);
    my $tr = ok($res->is_success(),
        'IP up fetch completed successfully for 1.0.0.0/24');
    if (not $tr) {
        warn Dumper($res);
    }

    my $data = decode_json($res->content());
    is($data->{'startAddress'}, '1.0.0.0',
        'Got correct start address');
    is($data->{'endAddress'}, '1.255.255.255',
        'Got correct end address');
    my $has_up_link =
        first { $_->{'rel'} eq 'up' }
            @{$data->{'links'}};
    ok((not $has_up_link), 'Object has no up link');
    my $has_down_link =
        first { $_->{'rel'} eq 'down' }
            @{$data->{'links'}};
    ok($has_down_link, 'Object has down link');

    $uri = URI->new($client_base.'/ips/rir_search/up/1.0.2.128/25');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP up fetch completed successfully for 1.0.2.128/25');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'startAddress'}, '1.0.2.0',
        'Got correct start address');
    is($data->{'endAddress'}, '1.0.2.255',
        'Got correct end address');
    $has_up_link =
        first { $_->{'rel'} eq 'up' }
            @{$data->{'links'}};
    ok($has_up_link, 'Object has up link');
    $has_down_link =
        first { $_->{'rel'} eq 'down' }
            @{$data->{'links'}};
    ok($has_down_link, 'Object has down link');

    # ip-top.

    $uri = URI->new($client_base.'/ips/rir_search/top/1.0.64.0/26');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP top fetch completed successfully for 1.0.64.0/26');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'startAddress'}, '1.0.0.0',
        'Got correct start address');
    is($data->{'endAddress'}, '1.255.255.255',
        'Got correct end address');

    # ip-top with status.

    $uri = URI->new($client_base.'/ips/rir_search/top/1.0.2.64/26'.
                                 '?status=active');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP top fetch completed successfully for 1.0.2.64/26 (active)');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'startAddress'}, '1.0.2.0',
        'Got correct start address');
    is($data->{'endAddress'}, '1.0.2.255',
        'Got correct end address');

    # ip-down.

    $uri = URI->new($client_base.'/ips/rir_search/down/1.0.0.0/8');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP down fetch completed successfully for 1.0.0.0/8');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    my @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
        @{$data->{'ipSearchResults'}};
    is_deeply(
        \@ranges,
        [qw(1.0.0.0/24
            1.0.1.0/24
            1.0.2.0/24
            1.0.3.0/24)],
        'Got correct results'
    );

    $uri = URI->new($client_base.'/ips/rir_search/down/1.0.2.0/24');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP down fetch completed successfully for 1.0.2.0/24');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
        @{$data->{'ipSearchResults'}};
    is_deeply(
        \@ranges,
        [qw(1.0.2.0/25
            1.0.2.128/25)],
        'Got correct results'
    );

    # ip-bottom.

    $uri = URI->new($client_base.'/ips/rir_search/bottom/1.0.0.0/8');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP bottom fetch completed successfully for 1.0.0.0/8');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
        @{$data->{'ipSearchResults'}};

    is_deeply(
        \@ranges,
        [qw(1.0.0.0/8
            1.0.0.0/24
            1.0.1.0/24
            1.0.2.0/25
            1.0.2.64/26
            1.0.2.128/25
            1.0.3.0/24)],
        'Got correct results'
    );

    # ip-bottom with status.

    $uri =
        URI->new($client_base.
                 '/ips/rir_search/bottom/1.0.0.0/8?status=active');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP bottom fetch completed successfully for 1.0.0.0/8');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
        @{$data->{'ipSearchResults'}};

    is_deeply(
        \@ranges,
        [qw(1.0.0.0/8
            1.0.0.0/24
            1.0.1.0/24
            1.0.2.0/25
            1.0.2.64/26
            1.0.2.128/25)],
        'Got correct results'
    );

    # ip-bottom where the argument isn't an existing object.

    $uri = URI->new($client_base.'/ips/rir_search/bottom/1.0.0.0/22');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP bottom fetch completed successfully for 1.0.0.0/22');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
        @{$data->{'ipSearchResults'}};

    is_deeply(
        \@ranges,
        [qw(1.0.0.0/24
            1.0.1.0/24
            1.0.2.0/25
            1.0.2.64/26
            1.0.2.128/25
            1.0.3.0/24)],
        'Got correct results'
    );

    # ip-bottom where the argument has nothing under it.

    $uri = URI->new($client_base.'/ips/rir_search/bottom/1.0.2.65');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP bottom fetch completed successfully for 1.0.2.65');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
        @{$data->{'ipSearchResults'}};

    is_deeply(
        \@ranges,
        [qw(1.0.2.64/26)],
        'Got correct results'
    );

    # IP links.

    $uri = URI->new($client_base.'/ip/1.0.2.0/25');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'IP fetch completed successfully for 1.0.2.0/25');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    my @links = @{$data->{'links'}};
    my %processed;
    for my $link (@links) {
        my ($rel, $href) = @{$link}{qw(rel href)};
        if ($rel eq 'self') {
            next;
        }
        my $link_res = $ua->get($href);
        my $link_data = decode_json($link_res->decoded_content());
        if ($link_data->{'startAddress'}) {
            $processed{$rel} = $link_data->{'startAddress'}.'-'.
                               $link_data->{'endAddress'};
        } elsif ($link_data->{'ipSearchResults'}) {
            $processed{$rel} = [
                map { $_->{'startAddress'}.'-'.
                      $_->{'endAddress'} }
                    @{$link_data->{'ipSearchResults'}}
            ];
        }
    }
    is_deeply(\%processed,
              { 'up'         => '1.0.2.0-1.0.2.255',
                'top'        => '1.0.0.0-1.255.255.255',
                'up-active'  => '1.0.2.0-1.0.2.255',
                'top-active' => '1.0.2.0-1.0.2.255',
                'down'       => [ '1.0.2.64-1.0.2.127' ],
                'bottom'     => [ '1.0.2.0-1.0.2.127',
                                  '1.0.2.64-1.0.2.127' ] },
              'Got complete set of links');

    # autnum-up.

    $uri = URI->new($client_base.'/autnums/rir_search/up/10-10');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Autnum up fetch completed successfully for 10');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'startAutnum'}, '10',
        'Got correct start autnum');
    is($data->{'endAutnum'}, '15',
        'Got correct end autnum');
    $has_up_link =
        first { $_->{'rel'} eq 'up' }
            @{$data->{'links'}};
    ok($has_up_link, 'Object has up link');
    $has_down_link =
        first { $_->{'rel'} eq 'down' }
            @{$data->{'links'}};
    ok($has_down_link, 'Object has down link');

    $uri = URI->new($client_base.'/autnums/rir_search/up/19-19');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Autnum up fetch completed successfully for 19');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'startAutnum'}, '16',
        'Got correct start autnum');
    is($data->{'endAutnum'}, '19',
        'Got correct end autnum');
    $has_up_link =
        first { $_->{'rel'} eq 'up' }
            @{$data->{'links'}};
    ok($has_up_link, 'Object has up link');
    $has_down_link =
        first { $_->{'rel'} eq 'down' }
            @{$data->{'links'}};
    ok($has_down_link, 'Object has down link');

    # autnum-top.

    $uri = URI->new($client_base.'/autnums/rir_search/top/18');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Autnum top fetch completed successfully for 18');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'startAutnum'}, '10',
        'Got correct start autnum');
    is($data->{'endAutnum'}, '19',
        'Got correct end autnum');

    # autnum-down.

    $uri = URI->new($client_base.'/autnums/rir_search/down/10-19');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Autnum down fetch completed successfully for 10-19');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { [ $_->{'startAutnum'},
                $_->{'endAutnum'} ] }
            @{$data->{'autnumSearchResults'}};
    is_deeply(
        \@ranges,
        [[10, 15],
         [16, 19]],
        'Got correct results'
    );

    $uri = URI->new($client_base.'/autnums/rir_search/down/16-19');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Autnum down fetch completed successfully for 16-19');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { [ $_->{'startAutnum'},
                $_->{'endAutnum'} ] }
            @{$data->{'autnumSearchResults'}};
    is_deeply(
        \@ranges,
        [[18, 18],
         [19, 19]],
        'Got correct results'
    );

    # autnum-bottom.

    $uri = URI->new($client_base.'/autnums/rir_search/bottom/10-19');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Autnum bottom fetch completed successfully for 10-19');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { [ $_->{'startAutnum'},
                $_->{'endAutnum'} ] }
            @{$data->{'autnumSearchResults'}};
    is_deeply(
        \@ranges,
        [[10, 15],
         [10, 10],
         [11, 11],
         [16, 19],
         [18, 18],
         [19, 19]],
        'Got correct results'
    );

    $uri = URI->new($client_base.'/autnums/rir_search/bottom/1-1000');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Autnum bottom fetch completed successfully for 1-1000');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { [ $_->{'startAutnum'},
                $_->{'endAutnum'} ] }
            @{$data->{'autnumSearchResults'}};
    is_deeply(
        \@ranges,
        [[1,  1],
         [2,  2],
         [3,  3],
         [4,  4],
         [10, 15],
         [10, 10],
         [11, 11],
         [16, 19],
         [18, 18],
         [19, 19]],
        'Got correct results'
    );

    $uri = URI->new($client_base.'/autnums/rir_search/bottom/20000');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Autnum bottom fetch completed successfully for 20000');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { [ $_->{'startAutnum'},
                $_->{'endAutnum'} ] }
            @{$data->{'autnumSearchResults'}};
    is_deeply(
        \@ranges,
        [],
        'Got correct results (empty)'
    );

    # domain.

    $uri = URI->new($client_base.'/domain/1.1.10.1.in-addr.arpa');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Domain fetch completed successfully for 1.1.10.1.in-addr.arpa');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'ldhName'}, '10.1.in-addr.arpa',
        'Got correct LDH name');

    # domain-up.

    $uri = URI->new($client_base.'/domains/rir_search/up/10.1.in-addr.arpa');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Domain up fetch completed successfully for 10.1.in-addr.arpa');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'ldhName'}, '1.in-addr.arpa',
        'Got correct LDH name');
    $has_up_link =
        first { $_->{'rel'} eq 'up' }
            @{$data->{'links'}};
    ok((not $has_up_link), 'Object has no up link');
    $has_down_link =
        first { $_->{'rel'} eq 'down' }
            @{$data->{'links'}};
    ok($has_down_link, 'Object has down link');

    $uri = URI->new($client_base.'/domains/rir_search/up/20.10.1.in-addr.arpa');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Domain up fetch completed successfully for 20.10.1.in-addr.arpa');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'ldhName'}, '10.1.in-addr.arpa',
        'Got correct LDH name');
    $has_up_link =
        first { $_->{'rel'} eq 'up' }
            @{$data->{'links'}};
    ok($has_up_link, 'Object has up link');
    $has_down_link =
        first { $_->{'rel'} eq 'down' }
            @{$data->{'links'}};
    ok($has_down_link, 'Object has no down link');

    # domain-top.

    $uri = URI->new($client_base.'/domains/rir_search/top/20.10.1.in-addr.arpa');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Domain top fetch completed successfully for 20.10.1.in-addr.arpa');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    is($data->{'ldhName'}, '1.in-addr.arpa',
        'Got correct LDH name');

    # domain-down.

    $uri = URI->new($client_base.'/domains/rir_search/down/1.in-addr.arpa');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Domain down fetch completed successfully for 1.in-addr.arpa');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { $_->{'ldhName'} }
            @{$data->{'domainSearchResults'}};
    is_deeply(
        \@ranges,
        [qw(10.1.in-addr.arpa
            20.1.in-addr.arpa)],
        'Got correct results'
    );

    $uri = URI->new($client_base.'/domains/rir_search/down/10.1.in-addr.arpa');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Domain down fetch completed successfully for 10.1.in-addr.arpa');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { $_->{'ldhName'} }
            @{$data->{'domainSearchResults'}};
    is_deeply(
        \@ranges,
        [qw(10.10.1.in-addr.arpa
            20.10.1.in-addr.arpa)],
        'Got correct results'
    );

    # domain-bottom.

    $uri = URI->new($client_base.'/domains/rir_search/bottom/1.in-addr.arpa');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        'Domain bottom fetch completed successfully for 1.in-addr.arpa');
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { $_->{'ldhName'} }
            @{$data->{'domainSearchResults'}};
    is_deeply(
        \@ranges,
        [qw(1.in-addr.arpa
            10.1.in-addr.arpa
            10.10.1.in-addr.arpa
            20.10.1.in-addr.arpa
            20.1.in-addr.arpa)],
        'Got correct results'
    );

    # IP by name.

    $uri = URI->new($client_base.'/ips?name=top');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        "IP name search completed successfully for 'top'");
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
        @{$data->{'ipSearchResults'}};
    is_deeply(\@ranges, [qw(1.0.0.0/8)],
              'Got correct results for name search');

    # IP by handle.

    $uri = URI->new($client_base.'/ips?handle=HANDLE-LOWER*');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        "IP handle search completed successfully for 'HANDLE-LOWER*'");
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
        @{$data->{'ipSearchResults'}};
    # ip-down's implementation returns results in order, but the same
    # is not true of general searches, hence the sort here.
    is_deeply([sort @ranges],
              [qw(1.0.2.0/25
                  1.0.2.128/25)],
              'Got correct results for name search');

    # Autnum by name.

    $uri = URI->new($client_base.'/autnums?name=first');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        "Autnum name search completed successfully for 'first'");
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { $_->{'startAutnum'}.'-'.$_->{'endAutnum'} }
            @{$data->{'autnumSearchResults'}};
    is_deeply(\@ranges, [qw(1-1)],
              'Got correct results for name search');

    # Autnum by handle.

    $uri = URI->new($client_base.'/autnums?handle=HANDLE-*F*');
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        "Autnum handle search completed successfully for 'HANDLE-*F*'");
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { $_->{'startAutnum'}.'-'.$_->{'endAutnum'} }
            @{$data->{'autnumSearchResults'}};
    is_deeply([sort @ranges],
              [qw(1-1
                  4-4)],
              'Got correct results for name search');

    # IP reverse search.

    $uri = URI->new($client_base.'/ips/reverse/entity');
    $uri->query_form(
        handle => 'TP*',
        role   => 'administrative'
    );
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        "IP reverse search completed successfully");
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { Net::IP::XS->new(
                $_->{'startAddress'}.'-'.
                $_->{'endAddress'}
              )->prefix() }
            @{$data->{'ipSearchResults'}};
    is_deeply([sort @ranges],
              [qw(1.0.2.0/24
                  1.0.3.0/24)],
              'Got correct results for reverse search');

    # Autnum reverse search.

    $uri = URI->new($client_base.'/autnums/reverse/entity');
    $uri->query_form(
        handle => 'TP*',
        role   => 'registrant'
    );
    $res = $ua->get($uri);
    $tr = ok($res->is_success(),
        "Autnum reverse search completed successfully");
    if (not $tr) {
        warn Dumper($res);
    }

    $data = decode_json($res->content());
    @ranges =
        map { $_->{'startAutnum'}.'-'.$_->{'endAutnum'} }
            @{$data->{'autnumSearchResults'}};
    is_deeply([sort @ranges],
              [qw(1-1
                  2-2
                  3-3
                  4-4)],
              'Got correct results for reverse search');

    # Shut down the servers.

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
