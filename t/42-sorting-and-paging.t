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

use APNIC::RDAP::RMP::Client;
use APNIC::RDAP::RMP::Server;
use APNIC::RDAP::RMP::Serial qw(new_serial);

use Test::More tests => 55;

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
        #local(*STDERR);
        #open(STDERR, ">/dev/null");
        $server->run();
        exit();
    }

    if (not ($client_pid = fork())) {
        #local(*STDERR);
        #open(STDERR, ">/dev/null");
        $client->run();
        exit();
    }

    for my $num (100..200) {
        my $year = 2000 + (200 - $num);
        write_file("$object_path/domain/$num.in-addr.arpa", encode_json({
            rdapConformance => ['rdap_level_0'],
            objectClassName => 'domain',
            ldhName         => $num.'.in-addr.arpa',
            links           => [
                { rel  => 'self',
                  href => 'https://example.com/domain/'.$num.'.in-addr.arpa' }
            ],
            entities        => [
                { objectClassName => 'entity',
                  handle          => 'TP137-AP',
                  links           => [
                      { rel => 'self',
                        href => 'https://example.com/entity/TP137-AP' }
                  ] }
            ],
            events          => [
                { eventAction => 'last changed',
                  eventDate   => "$year-01-01T00:00:00Z" },
                { eventAction => 'last changed',
                  eventDate   => "3000-01-01T00:00:00Z" },
                { eventAction => 'transfer',
                  eventDate   => "$year-05-05T00:00:00Z" },
                { eventAction => 'transfer',
                  eventDate   => "1000-05-05T00:00:00Z" },
            ],
        }));
    }

    for my $num (100..200) {
        my $year = 2000 + (200 - $num);
        my $id = "TP$num-AP";
        my $num1 = 200 - $num;
        my $num2 = (($num + 50) % 100) + 100;
        my $num3 = (($num + 60) % 100) + 100;
        my $num4 = (($num + 70) % 100) + 100;
        my $num5 = (($num + 80) % 100) + 100;
        write_file("$object_path/entity/$id", encode_json({
            rdapConformance => ['rdap_level_0'],
            objectClassName => 'entity',
            handle          => $id,
            links           => [
                { rel  => 'self',
                  href => "https://example.com/entity/$id" }
            ],
            vcardArray => [
                'vcard',
                [ [ 'version', {}, 'text', '4.0' ],
                  [ 'fn', {}, 'text', "Test $num1 User" ],
                  [ 'tel', { type => [ 'voice' ] },
                    'text', "+61-0000-0$num2" ],
                  [ 'tel', { pref => 1 },
                    'text', "+61-0000-0000" ],
                  [ 'adr', { cc => $num3 },
                    'text', [ '', '', '', $num5, '', '', $num4 ] ] ],
            ],
        }));
    }

    my $ua = LWP::UserAgent->new();
    my $res = $ua->post($server_base.'/snapshot/generate');
    ok($res->is_success(), 'Generated snapshot successfully');
    $res = $ua->post($server_base.'/unf/generate');
    ok($res->is_success(), 'Generated UNF successfully');
    $res = $ua->post($client_base.'/refresh');
    ok($res->is_success(), 'Refreshed client successfully');

    my $uri = URI->new($client_base.'/domains');
    $uri->query_form(name => '10*in-addr.arpa');
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Got paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'domainSearchResults'}};
    is(@results, 2, 'Got two results');
    my %ldh_names = map { $_->{'ldhName'} => 1 } @results;

    is($data->{'paging_metadata'}->{'pageSize'}, 2,
        'Two results returned');
    is($data->{'paging_metadata'}->{'totalCount'}, 10,
        'Ten results in total');
    is($data->{'paging_metadata'}->{'pageNumber'}, 1,
        'On page one of the results');

    my $next = $data->{'paging_metadata'}->{'links'}->[0]->{'href'};
    $res = $ua->get($next);

    ok($res->is_success(), 'Got next paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'domainSearchResults'}};
    is(@results, 2, 'Got two results');
    my %new_ldh_names = map { $_->{'ldhName'} => 1 } @results;
    my %all_ldh_names = (%ldh_names, %new_ldh_names);
    is((keys %all_ldh_names), 4, 'Next page contains new results');

    is($data->{'paging_metadata'}->{'pageSize'}, 2,
        'Two results returned');
    is($data->{'paging_metadata'}->{'totalCount'}, 10,
        'Ten results in total');
    is($data->{'paging_metadata'}->{'pageNumber'}, 2,
        'On page two of the results');

    my $uri = URI->new($client_base.'/domains');
    $uri->query_form(name => '10*in-addr.arpa',
                     sort => 'name');
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Got paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'domainSearchResults'}};
    is(@results, 2, 'Got two results');
    is($results[0]->{'ldhName'}, '100.in-addr.arpa',
        'First result has correct ldhName');
    is($results[1]->{'ldhName'}, '101.in-addr.arpa',
        'Second result has correct ldhName');

    $next = $data->{'paging_metadata'}->{'links'}->[0]->{'href'};
    $res = $ua->get($next);

    ok($res->is_success(), 'Got next paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'domainSearchResults'}};
    is(@results, 2, 'Got two results');
    is($results[0]->{'ldhName'}, '102.in-addr.arpa',
        'First result has correct ldhName');
    is($results[1]->{'ldhName'}, '103.in-addr.arpa',
        'Second result has correct ldhName');

    my $uri = URI->new($client_base.'/domains');
    $uri->query_form(name => '10*in-addr.arpa',
                     sort => 'name:d');
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Got paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'domainSearchResults'}};
    is(@results, 2, 'Got two results');
    is($results[0]->{'ldhName'}, '109.in-addr.arpa',
        'First result has correct ldhName');
    is($results[1]->{'ldhName'}, '108.in-addr.arpa',
        'Second result has correct ldhName');

    my $uri = URI->new($client_base.'/domains');
    $uri->query_form(name => '10*in-addr.arpa',
                     sort => 'lastChangedDate:d');
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Got paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'domainSearchResults'}};
    is(@results, 2, 'Got two results');
    my $lc0 =
        first { $_->{'eventAction'} eq 'last changed' }
            @{$results[0]->{'events'}};
    my $lc1 =
        first { $_->{'eventAction'} eq 'last changed' }
            @{$results[1]->{'events'}};
    ok(($lc0->{'eventDate'} gt $lc1->{'eventDate'}),
        'Last-changed date is in correct order');
    is($lc0->{'eventDate'}, '2100-01-01T00:00:00Z',
        'Got correct first last-changed event date');
    is($lc1->{'eventDate'}, '2099-01-01T00:00:00Z',
        'Got correct second last-changed event date');

    my $uri = URI->new($client_base.'/entities');
    $uri->query_form(fn   => 'Test * User',
                     sort => 'fn');
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Got paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'entitySearchResults'}};
    is(@results, 2, 'Got two results');
    is($results[0]->{'vcardArray'}->[1]->[1]->[3], 'Test 0 User',
        'Got correct first record (fn)');
    is($results[0]->{'handle'}, 'TP200-AP',
        'Got correct first record (handle)');
    is($results[1]->{'vcardArray'}->[1]->[1]->[3], 'Test 1 User',
        'Got correct second record (fn)');
    is($results[1]->{'handle'}, 'TP199-AP',
        'Got correct second record (handle)');

    my $uri = URI->new($client_base.'/entities');
    $uri->query_form(fn   => 'Test * User',
                     sort => 'cc:d');
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Got paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'entitySearchResults'}};
    is(@results, 2, 'Got two results');
    is($results[0]->{'handle'}, 'TP139-AP',
        'Got correct first record (handle)');
    is($results[0]->{'vcardArray'}->[1]->[4]->[1]->{'cc'}, '199',
        'Got correct first record (cc)');
    is($results[1]->{'handle'}, 'TP138-AP',
        'Got correct second record (handle)');
    is($results[1]->{'vcardArray'}->[1]->[4]->[1]->{'cc'}, '198',
        'Got correct second record (cc)');

    my $uri = URI->new($client_base.'/entities');
    $uri->query_form(fn   => 'Test * User',
                     sort => 'voice:a');
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Got paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'entitySearchResults'}};
    is(@results, 2, 'Got two results');
    is($results[0]->{'handle'}, 'TP150-AP',
        'Got correct first record (handle)');
    is($results[0]->{'vcardArray'}->[1]->[2]->[3], '+61-0000-0100',
        'Got correct first record (phone)');
    is($results[1]->{'handle'}, 'TP151-AP',
        'Got correct second record (handle)');
    is($results[1]->{'vcardArray'}->[1]->[2]->[3], '+61-0000-0101',
        'Got correct second record (phone)');

    my $uri = URI->new($client_base.'/entities');
    $uri->query_form(fn   => 'Test * User',
                     sort => 'city');
    $res = $ua->get($uri->as_string());
    ok($res->is_success(), 'Got paged search results');
    my $data = decode_json($res->content());
    my @results = @{$data->{'entitySearchResults'}};
    is(@results, 2, 'Got two results');
    is($results[0]->{'handle'}, 'TP120-AP',
        'Got correct first record (handle)');
    is($results[0]->{'vcardArray'}->[1]->[4]->[3]->[3], '100',
        'Got correct first record (city)');
    is($results[1]->{'handle'}, 'TP121-AP',
        'Got correct second record (handle)');
    is($results[1]->{'vcardArray'}->[1]->[4]->[3]->[3], '101',
        'Got correct second record (city)');

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
