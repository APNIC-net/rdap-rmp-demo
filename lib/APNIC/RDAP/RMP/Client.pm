package APNIC::RDAP::RMP::Client;

use warnings;
use strict;

use Crypt::JWT qw(decode_jwt);
use Digest::MD5 qw(md5_hex);
use File::Find;
use File::Slurp qw(read_file write_file);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json encode_json);
use List::Util qw(first);
use LWP::UserAgent;
use Net::IP::XS;
use Net::Patricia;
use Set::IntervalTree;

use APNIC::RDAP::RMP::Serial qw(new_serial);

my %OBJECT_CLASS_NAME_TO_PATH = (
    'ip network' => 'ip',
    'autnum'     => 'autnum',
    'domain'     => 'domain',
    'nameserver' => 'nameserver',
    'entity'     => 'entity',
);

my $MAX_SERIAL = (2 ** 32) - 1;

our $VERSION = '0.1';

sub new
{
    my $class = shift;
    my %args = @_;
    my $self = \%args;
    bless $self, $class;

    my $d = HTTP::Daemon->new(
        LocalPort => $self->{"port"},
        ReuseAddr => 1,
        ReusePort => 1
    );
    if (not $d) {
        die "Unable to start server: $!";
    }
    $self->{"d"} = $d;
    $self->{"port"} = $d->sockport();
    if (not $self->{'url_base'}) {
        $self->{'url_base'} = 'http://localhost:'.$self->{'port'};
    }

    bless $self, $class;
    $self->{"db"} = {};
    return $self;
}

sub _adjust_links
{
    my ($self, $id, $object_data) = @_;

    if ((ref $object_data eq 'HASH')
            and ($object_data->{'links'})) {
        for my $link (@{$object_data->{'links'}}) {
            my $potential_id = $link->{'href'};
            if ($self->{'db'}->{'id_to_link'}->{$potential_id}) {
                $link->{'href'} =
                    $self->{'db'}->{'id_to_link'}->{$potential_id};
                $self->{'db'}->{'id_to_used_links'}->{$id}
                    ->{$potential_id} = 1;
            }
        }
        for my $value (values %{$object_data}) {
            $self->_adjust_links($id, $value);
        }
    } elsif (ref $object_data eq 'ARRAY') {
        for my $value (@{$object_data}) {
            $self->_adjust_links($id, $value);
        }
    }

    return 1;
}

sub _object_to_link
{
    my ($self, $object) = @_;

    my $id = $object->{'id'};
    my $object_data = $object->{'object'};
    my $object_class_name = $object_data->{'objectClassName'};

    if (not $object_class_name) {
        die "objectClassName not set in object";
    }

    my $path = $OBJECT_CLASS_NAME_TO_PATH{$object_class_name};
    if (not $path) {
        die "Unknown objectClassName '$object_class_name'";
    }

    my ($name) = ($id =~ /.*\/$path\/(.*)/);
    if (not $name) {
        die "Name for object not found (ID is '$id')";
    }

    return $self->{'url_base'}."/$path/$name";
}

sub _add_object
{
    my ($self, $object) = @_;

    warn "Adding object...\n";

    warn "  Object: ".encode_json($object)."\n";

    my $id = $object->{'id'};
    if (not URI->new($id)) {
        die "Object ID must be a valid URI";
    }
    my $object_data = $object->{'object'};
    if (not exists $object_data->{'rdapConformance'}) {
        die "rdapConformance not set in object";
    }

    $self->_adjust_links($id, $object_data);
    my $filename = md5_hex($id);
    my $object_path = $self->{'object_path'};
    my $path = "$object_path/$filename";
    write_file($path, encode_json($object_data));
    my $db = $self->{'db'};
    $db->{'by_id'}->{$id} = $path;

    my $object_class_name = $object_data->{'objectClassName'};
    if ($object_class_name eq 'ip network') {
        my $version = $object_data->{'ipVersion'};
        if (not $version) {
            die "No ipVersion in IP object";
        }
        my $tree = ($version eq 'v4') ? $db->{'ipv4'} : $db->{'ipv6'};
        my $net_ip =
            Net::IP::XS->new($object_data->{'startAddress'}.'-'.
                             $object_data->{'endAddress'});
        if (not $net_ip) {
            die "Invalid startAddress/endAddress";
        }
        $tree->add_string($net_ip->prefix(), \$path);
    } elsif ($object_class_name eq 'autnum') {
        if (not exists $object_data->{'startAutnum'}
                or not exists $object_data->{'endAutnum'}) {
            die "No startAutnum/endAutnum";
        }
        $db->{'autnum'}->insert(
            $path,
            $object_data->{'startAutnum'},
            $object_data->{'endAutnum'}+1
        );
    } elsif ($object_class_name eq 'domain') {
        $db->{'domain'}->{$object_data->{'ldhName'}} = $path;
    } elsif ($object_class_name eq 'nameserver') {
        $db->{'nameserver'}->{$object_data->{'ldhName'}} = $path;
    } elsif ($object_class_name eq 'entity') {
        $db->{'entities'}->{$object_data->{'handle'}} = $path;
    }

    warn "Finished adding object.\n";

    return 1;
}

sub _remove_object
{
    my ($self, $id) = @_;

    warn "Removing object...\n";

    warn "  Object ID: $id\n";

    my $db = $self->{'db'};
    if (not $db->{'by_id'}->{$id}) {
        warn "Object '$id' not present";
        next;
    }

    my $object_data = decode_json(read_file($db->{'by_id'}->{$id}));
    my $object_class_name = $object_data->{'objectClassName'};
    if ($object_class_name eq 'ip network') {
        my $net_ip =
            Net::IP::XS->new($object_data->{'startAddress'}.'-'.
                             $object_data->{'endAddress'});
        my $prefix = $net_ip->prefix();
        my $tree =
            ($net_ip->version() == 4)
                ? $db->{'ipv4'}
                : $db->{'ipv6'};
        $tree->remove_string($prefix);
    } elsif ($object_class_name eq 'autnum') {
        $db->{'autnum'}->remove(
            $object_data->{'startAutnum'},
            $object_data->{'endAutnum'}+1,
        );
    } elsif ($object_class_name eq 'domain') {
        delete $db->{'domain'}->{$object_data->{'ldhName'}};
    } elsif ($object_class_name eq 'nameserver') {
        delete $db->{'nameserver'}->{$object_data->{'ldhName'}};
    } elsif ($object_class_name eq 'entity') {
        delete $db->{'entities'}->{$object_data->{'handle'}};
    }

    unlink($db->{'by_id'}->{$id});
    delete $db->{'by_id'}->{$id};
    delete $db->{'id_to_link'}->{$id};
    delete $db->{'id_to_used_links'}->{$id};

    warn "Finished removing object.\n";

    return 1;
}

sub _apply_snapshot
{
    my ($self, $snapshot) = @_;

    warn "Applying snapshot...\n";

    my ($key, $object_path) =
        @{$self}{qw(key object_path)};

    my $ua = LWP::UserAgent->new();
    my $snapshot_res = $ua->get($snapshot->{'uri'});
    if (not $snapshot_res->is_success()) {
        die "Unable to fetch snapshot: ".$snapshot_res->status_line();
    }

    my $snapshot_data =
        decode_jwt(token => $snapshot_res->content(),
                   key   => \$key);

    my $version = $snapshot_data->{'version'} || '';
    if ($version != 1) {
        die "Unhandled snapshot version '$version'";
    }

    my $serial = $snapshot_data->{'serial'};
    if ($serial > $MAX_SERIAL) {
        die "Serial number '$serial' is too large";
    }
    $serial = new_serial(32, $serial);

    my $db = $self->{'db'};
    for my $path (values %{$db->{'by_id'}}) {
        unlink $path;
    }
    my %defaults = (
        entities         => {},
        by_id            => {},
        id_to_link       => {},
        id_to_used_links => {},
        ipv4             => Net::Patricia->new(AF_INET),
        ipv6             => Net::Patricia->new(AF_INET6),
        autnum           => Set::IntervalTree->new(),
        domain           => {},
        nameserver       => {},
    );
    for my $key (keys %defaults) {
        $db->{$key} = $defaults{$key};
    }

    if ((not $snapshot_data->{'objects'})
            or ((ref $snapshot_data->{'objects'}) ne 'ARRAY')) {
        die "No object array in snapshot";
    }

    for my $object (@{$snapshot_data->{'objects'}}) {
        my $id = $object->{'id'};
        my $link = $self->_object_to_link($object);
        $self->{'db'}->{'id_to_link'}->{$id} = $link;
    }

    for my $object (@{$snapshot_data->{'objects'}}) {
        $self->_add_object($object);
    }

    if ($snapshot_data->{'defaults'}) {
        $self->{'defaults'} = $snapshot_data->{'defaults'};
    }

    warn "Finished applying snapshot.\n";

    return $serial;
}

sub _apply_delta
{
    my ($self, $delta) = @_;

    warn "Applying delta...\n";

    my $db = $self->{'db'};
    my ($key, $object_path) = @{$self}{qw(key object_path)};

    my $ua = LWP::UserAgent->new();
    my $delta_res = $ua->get($delta->{'uri'});
    if (not $delta_res->is_success()) {
        die "Unable to fetch delta: ".$delta_res->status_line();
    }

    my $delta_data = decode_jwt(token => $delta_res->content(),
                                key => \$key);

    my $version = $delta_data->{'version'} || '';
    if ($version != 1) {
        die "Unhandled delta version '$version'";
    }

    if ((not $delta_data->{'removed_objects'})
            or ((ref $delta_data->{'removed_objects'}) ne 'ARRAY')) {
        die "No removed_objects array in delta";
    }
    if ((not $delta_data->{'added_or_updated_objects'})
            or ((ref $delta_data->{'added_or_updated_objects'}) ne 'ARRAY')) {
        die "No added_or_updated_objects array in delta";
    }

    my $serial = $delta_data->{'serial'};
    if ($serial > $MAX_SERIAL) {
        die "Serial number '$serial' is too large";
    }
    $serial = new_serial(32, $serial);

    my %added_or_updated_ids =
        map { $_->{'id'} => 1 }
            @{$delta_data->{'added_or_updated_objects'}};
    my %removed_ids =
        map { $_ => 1 }
            @{$delta_data->{'removed_objects'}};

    for my $id (@{$delta_data->{'removed_objects'}}) {
        if ($added_or_updated_ids{$id}) {
            next;
        }
        for my $other_id (keys %{$db->{'id_to_used_links'}}) {
            if ($other_id eq $id) {
                next;
            }
            if ($removed_ids{$other_id}) {
                next;
            }
            if (exists $db->{'id_to_used_links'}->{$other_id}->{$id}) {
                die "Unable to apply delta: object '$id' removed ".
                    "while link still needed by '$other_id'";
            }
        }
    }

    for my $id (@{$delta_data->{'removed_objects'}}) {
        $self->_remove_object($id);
    }

    for my $object (@{$delta_data->{'added_or_updated_objects'}}) {
        my $id = $object->{'id'};
        my $link = $self->_object_to_link($object);
        $self->{'db'}->{'id_to_link'}->{$id} = $link;
    }

    for my $object (@{$delta_data->{'added_or_updated_objects'}}) {
        $self->_add_object($object);
    }

    if ($delta_data->{'defaults'}) {
        $self->{'defaults'} = $delta_data->{'defaults'};
    }

    warn "Finished applying delta.\n";

    return $serial;
}

sub _is_sequence
{
    my ($deltas) = @_;

    for (my $i = 0; $i < (@{$deltas} - 1); $i++) {
        my $delta1 = $deltas->[$i];
        my $delta2 = $deltas->[$i + 1];
        if (($delta1->{'serial'} + 1) != $delta2->{'serial'}) {
            return 0;
        }
    }
    return 1;
}

sub _refresh
{
    my ($self) = @_;

    warn "Refreshing...\n";

    my ($unf_url, $key, $object_path) =
        @{$self}{qw(unf_url key object_path)};

    my $db = $self->{'db'};

    my $ua = LWP::UserAgent->new();
    my $unf_res = $ua->get($unf_url);
    if (not $unf_res->is_success()) {
        die "Unable to fetch UNF: ".$unf_res->status_line();
    }

    my $unf_data = decode_jwt(token => $unf_res->content(),
                              key   => \$key);
    my $version = $unf_data->{'version'} || '';
    if ($version != 1) {
        die "Unhandled UNF version '$version'";
    }
    if ((not $unf_data->{'deltas'})
            or ((ref $unf_data->{'deltas'}) ne 'ARRAY')) {
        die "No deltas array in UNF";
    }

    my $serial = $db->{'serial'};
    if (not defined $serial) {
        if (not $unf_data->{'snapshot'}) {
            die "Cannot initialise, because there is no ".
                "snapshot in the UNF: server must be ".
                "reinitialised manually";
        }
        $serial = $self->_apply_snapshot($unf_data->{'snapshot'});
    }
    if (not @{$unf_data->{'deltas'}}) {
        if ($unf_data->{'snapshot'}) {
            if ($serial != new_serial(32, $unf_data->{'snapshot'}->{'serial'})) {
                $serial = $self->_apply_snapshot($unf_data->{'snapshot'});
            }
        }
        $db->{'serial'} = $serial;
        warn "Finished refreshing.\n";
        return HTTP::Response->new(HTTP_OK);
    }

    for my $delta (@{$unf_data->{'deltas'}}) {
        $delta->{'serial'} = new_serial(32, $delta->{'serial'});
    }
    if (not _is_sequence($unf_data->{'deltas'})) {
        die "Deltas do not form a sequence";
    }

    my @deltas =
        sort { $a->{'serial'} <=> $b->{'serial'} }
            @{$unf_data->{'deltas'}};

    if ($unf_data->{'snapshot'}) {
        if (not defined $unf_data->{'snapshot'}->{'serial'}) {
            die "Snapshot serial not defined";
        }
        my $snapshot_serial =
            new_serial(32, $unf_data->{'snapshot'}->{'serial'});
        if (not first { $_->{'serial'} == $snapshot_serial } @deltas) {
            if (($snapshot_serial + 1) != ($deltas[0]->{'serial'})) {
                die "Snapshot serial not in delta list, nor ".
                    "one less than smallest delta serial";
            }
        }
    }

    my @rel_deltas = grep { $_->{'serial'} > $serial } @deltas;
    if (not @rel_deltas) {
        $db->{'serial'} = $serial;
        warn "Finished refreshing.\n";
        return HTTP::Response->new(HTTP_OK);
    }

    if ($deltas[0]->{'serial'} != ($serial + 1)) {
        if (not $unf_data->{'snapshot'}) {
            die "Serial inconsistency, but no snapshot in UNF: ".
                "server must be reinitialised manually";
        }
        $serial = $self->_apply_snapshot($unf_data->{'snapshot'});
        @rel_deltas = grep { $_->{'serial'} > $serial } @deltas;
        if (not @rel_deltas) {
            $db->{'serial'} = $serial;
            warn "Finished refreshing.\n";
            return HTTP::Response->new(HTTP_OK);
        }
    }

    for my $delta (@rel_deltas) {
        $self->_apply_delta($delta);
    }

    my $new_serial = $rel_deltas[$#rel_deltas]->{'serial'};
    $db->{'serial'} = $new_serial;

    warn "Finished refreshing.\n";

    return HTTP::Response->new(HTTP_OK);
}

sub _get_entity
{
    my ($self, $r) = @_;

    my $db = $self->{'db'};

    my $path = $r->uri()->path();
    my ($handle) = ($path =~ /\/entity\/(.+)/);
    if (not $handle) {
        return HTTP::Response->new(HTTP_BAD_REQUEST);
    }

    my $object_path = $db->{'entities'}->{$handle};
    if (not $object_path or not -e $object_path) {
        return HTTP::Response->new(HTTP_NOT_FOUND);
    }

    my $data = read_file($object_path);
    return HTTP::Response->new(HTTP_OK, undef, [], $data);
}

sub _get_ip
{
    my ($self, $r) = @_;

    my $db = $self->{'db'};

    my $path = $r->uri()->path();
    my ($ip) = ($path =~ /\/ip\/(.+)/);
    if (not $ip) {
        return HTTP::Response->new(HTTP_BAD_REQUEST);
    }

    my $net_ip = Net::IP::XS->new($ip);
    if (not $net_ip) {
        return HTTP::Response->new(HTTP_BAD_REQUEST);
    }

    my $tree = ($net_ip->version() == 4) ? $db->{'ipv4'} : $db->{'ipv6'};
    my $prefix = $net_ip->prefix();
    my $res = $tree->match_string($prefix);
    if (not $res) {
        return HTTP::Response->new(HTTP_NOT_FOUND);
    }

    my $data = read_file($$res);
    return HTTP::Response->new(HTTP_OK, undef, [], $data);
}

sub _get_autnum
{
    my ($self, $r) = @_;

    my $db = $self->{'db'};

    my $path = $r->uri()->path();
    my ($autnum) = ($path =~ /\/autnum\/(.+)/);
    if (not defined $autnum) {
        return HTTP::Response->new(HTTP_BAD_REQUEST);
    }

    my $tree = $db->{'autnum'};
    my @results =
        map { decode_json(read_file($_)) }
            @{$tree->fetch($autnum, $autnum + 1)};
    if (not @results) {
        return HTTP::Response->new(HTTP_NOT_FOUND);
    }

    my @ordered =
        sort {      ($a->{'endAutnum'} - $a->{'startAutnum'})
                <=> ($b->{'endAutnum'} - $a->{'startAutnum'}) }
            @results;
    my $smallest = $ordered[0];

    return HTTP::Response->new(HTTP_OK, undef, [],
                               encode_json($smallest));
}

sub _get_domain
{
    my ($self, $r) = @_;

    my $db = $self->{'db'};

    my $path = $r->uri()->path();
    my ($domain) = ($path =~ /\/domain\/(.+)/);
    if (not defined $domain) {
        return HTTP::Response->new(HTTP_BAD_REQUEST);
    }

    if (not exists $db->{'domain'}->{$domain}) {
        return HTTP::Response->new(HTTP_NOT_FOUND);
    }

    $path = $db->{'domain'}->{$domain};
    my $data = read_file($path);

    return HTTP::Response->new(HTTP_OK, undef, [], $data);
}

sub _get_nameserver
{
    my ($self, $r) = @_;

    my $db = $self->{'db'};

    my $path = $r->uri()->path();
    my ($nameserver) = ($path =~ /\/nameserver\/(.+)/);
    if (not defined $nameserver) {
        return HTTP::Response->new(HTTP_BAD_REQUEST);
    }

    if (not exists $db->{'nameserver'}->{$nameserver}) {
        return HTTP::Response->new(HTTP_NOT_FOUND);
    }

    $path = $db->{'nameserver'}->{$nameserver};
    my $data = read_file($path);

    return HTTP::Response->new(HTTP_OK, undef, [], $data);
}

sub _event_mapper
{
    my ($object, $sort_name) = @_;

    $sort_name =~ s/Date$//;
    if ($sort_name eq 'lastChanged') {
        $sort_name = 'last changed';
    }
    my $event_name = $sort_name;

    my $event =
        first { ($_->{'eventAction'} eq $sort_name)
                    and $_->{'eventDate'} }
            @{$object->{'events'}};

    return $event->{'eventDate'};
}

sub _vcard_mapper_normal
{
    my ($object, $sort_name) = @_;

    my @elements = @{$object->{'vcardArray'}->[1]};
    my @relevant_elements =
        sort { ($a->[1]->{'pref'} || '')
                cmp ($b->[1]->{'pref'} || '') }
        grep { $_->[0] eq $sort_name }
            @elements;
    return $relevant_elements[0]->[3];
}

sub _vcard_mapper_address
{
    my ($object, $sort_name) = @_;

    my @elements = @{$object->{'vcardArray'}->[1]};
    my @relevant_elements =
        sort { ($a->[1]->{'pref'} || '')
                cmp ($b->[1]->{'pref'} || '') }
        grep { $_->[0] eq 'adr' }
            @elements;
    my $adr = $relevant_elements[0];
    if (not $adr) {
        return;
    }
    my $index =
        ($sort_name eq 'country') ? 6
      : ($sort_name eq 'city')    ? 3
                                  : undef;
    if (not $index) {
        return;
    }
    return $adr->[3]->[$index];
}

sub _vcard_mapper_voice
{
    my ($object) = @_;

    my @elements = @{$object->{'vcardArray'}->[1]};
    my @relevant_elements =
        sort { ($a->[1]->{'pref'} || '')
                cmp ($b->[1]->{'pref'} || '') }
        grep { $_->[0] eq 'tel'
                and first { $_ eq 'voice' } @{$_->[1]->{'type'} || []} }
            @elements;
    my $tel = $relevant_elements[0];
    if (not $tel) {
        return;
    }

    return $tel->[3];
}

sub _vcard_mapper_cc
{
    my ($object) = @_;

    my @elements = @{$object->{'vcardArray'}->[1]};
    my @relevant_elements =
        sort { ($a->[1]->{'pref'} || '')
                cmp ($b->[1]->{'pref'} || '') }
        grep { $_->[0] eq 'adr' and $_->[1]->{'cc'} }
            @elements;
    my $adr = $relevant_elements[0];
    if (not $adr) {
        return;
    }
    return $adr->[1]->{'cc'};
}

my %common_mappers = (
    map { my $name = $_;
          $name => sub { _event_mapper($_[0], $name) } }
        qw(registrationDate
           reregistrationDate
           lastChangedDate
           expirationDate
           deletionDate
           reinstantiationDate
           transferDate
           lockedDate
           unlockedDate)
);

my %domain_mappers = (
    %common_mappers,
    name => sub { $_[0]->{'ldhName'} },
);

my %entity_mappers = (
    %common_mappers,
    (map { my $name = $_;
          $name => sub { _vcard_mapper_normal($_[0], $name) } }
        qw(fn
           handle
           org
           email)),
    (map { my $name = $_;
          $name => sub { _vcard_mapper_address($_[0], $name) } }
        qw(country
           city)),
    voice => sub { _vcard_mapper_voice($_[0]) },
    cc    => sub { _vcard_mapper_cc($_[0]) },
);

sub _search_entities
{
    my ($self, $r) = @_;

    my %query_form = $r->uri()->query_form();
    my $fn_search = $query_form{'fn'} || '';
    $fn_search =~ s/\*/\.*/g;
    my $sort = $query_form{'sort'} || '';
    my @sort_details =
        map { my $value = $_;
              if ($value !~ /:/) {
                  $value .= ':a';
              }
              [ split /:/, $value ] }
            split /\s*,\s*/, $sort;

    my @results;
    for my $path (sort values %{$self->{'db'}->{'entities'}}) {
        my $entity_obj = decode_json(read_file($path));
        my $fn =
            first { $_->[0] eq 'fn' }
                @{$entity_obj->{'vcardArray'}->[1]};
        if ($fn->[3] =~ /^$fn_search$/) {
            push @results, $entity_obj;
        }
    }
    @results =
        sort { my $result = 0;
               for my $sort_detail (@sort_details) {
                   my ($field, $order) = @{$sort_detail};
                   my $mapper = $entity_mappers{$field};
                   if (not $mapper) {
                       return HTTP::Response->new(HTTP_BAD_REQUEST);
                   }
                   my ($a_value, $b_value) =
                       map { $mapper->($_) }
                           ($a, $b);
                   if ($order eq 'a') {
                       $result = $a_value cmp $b_value;
                   } else {
                       $result = $b_value cmp $a_value;
                   }
                   if ($result != 0) {
                       last;
                   }
               }
               $result }
            @results;

    my $cursor = $query_form{'cursor'};
    if (not $cursor) {
        $cursor = 1;
    }
    my $current_page_number = $cursor;
    my $per_page = 2;
    my $index = ($cursor - 1) * $per_page;

    my @page_results =
        grep { $_ } @results[$index..($index + $per_page - 1)];

    my $result_count = scalar @results;
    my $page_count = $result_count / $per_page;
    if (int($page_count) != $page_count) {
        $page_count++;
    }
    my $value = $self->{'url_base'}.$r->uri()->as_string();

    $query_form{'cursor'} = $cursor + 1;
    my $new_uri = URI->new($r->uri());
    $new_uri->query_form(%query_form);
    my $next = $self->{'url_base'}.$new_uri->as_string();

    my $sort_uri = URI->new($r->uri());
    my %s_query_form = $sort_uri->query_form();
    delete $s_query_form{'sort'};
    delete $s_query_form{'cursor'};
    my $make_link = sub {
        my ($sort_value) = @_;
        $s_query_form{'sort'} = $sort_value;
        my $new_uri = URI->new($r->uri());
        $new_uri->query_form(%s_query_form);
        return $self->{'url_base'}.'/'.$new_uri->as_string();
    };

    my $data = {
        rdapConformance => [qw(rdap_level_0
                               paging_level_0
                               sorting_level_0)],
        entitySearchResults => \@page_results,
        paging_metadata => {
            totalCount => (scalar @results),
            pageSize   => (scalar @page_results),
            pageNumber => $current_page_number,
            links      => [
                { value => $value,
                  rel   => 'next',
                  href  => $next,
                  title => 'Result pagination link',
                  type  => 'application/rdap+json' }
            ]
        },
        ($sort)
            ? (sorting_metadata => {
                currentSort => $sort,
                availableSorts => [
                    { property => 'fn',
                      jsonPath => '$.entitySearchResults[*].vcardArray[1][?(@[0]="fn")][3]',
                      default  => \0,
                      links    => [
                          { value => $value,
                            rel   => 'alternate',
                            href  => $make_link->('fn:a'),
                            title => 'Result Ascending Sort Link' },
                          { value => $value,
                            rel   => 'alternate',
                            href  => $make_link->('fn:d'),
                            title => 'Result Descending Sort Link' }
                      ] }
                ]
              })
            : ()
    };

    if ($page_count == $cursor) {
        delete $data->{'paging_metadata'}->{'links'};
    }

    # totalCount is included by default, which is why there is no
    # check for the true values for the count parameter.
    if (exists $query_form{'count'}) {
        my $value = $query_form{'count'} || '';
        if ((not $value)
                or ($value eq 'false')
                or ($value eq 'no')) {
            delete $data->{'paging_metadata'}->{'totalCount'};
        }
    }

    return HTTP::Response->new(HTTP_OK, undef, [],
                               encode_json($data));
}

sub _search_domains
{
    my ($self, $r) = @_;

    my %query_form = $r->uri()->query_form();
    my $name = $query_form{'name'} || '';
    $name =~ s/\*/\.*/g;
    my $sort = $query_form{'sort'} || '';
    my @sort_details =
        map { my $value = $_;
              if ($value !~ /:/) {
                  $value .= ':a';
              }
              [ split /:/, $value ] }
            split /\s*,\s*/, $sort;

    my @results;
    for my $path (sort values %{$self->{'db'}->{'domain'}}) {
        my $domain_obj = decode_json(read_file($path));
        if ($domain_obj->{'ldhName'} =~ /^$name$/) {
            push @results, $domain_obj;
        }
    }
    @results =
        sort { my $result = 0;
               for my $sort_detail (@sort_details) {
                   my ($field, $order) = @{$sort_detail};
                   my $mapper = $domain_mappers{$field};
                   if (not $mapper) {
                       return HTTP::Response->new(HTTP_BAD_REQUEST);
                   }
                   my ($a_value, $b_value) =
                       map { $mapper->($_) }
                           ($a, $b);
                   if ($order eq 'a') {
                       $result = $a_value cmp $b_value;
                   } else {
                       $result = $b_value cmp $a_value;
                   }
                   if ($result != 0) {
                       last;
                   }
               }
               $result }
            @results;

    my $cursor = $query_form{'cursor'};
    if (not $cursor) {
        $cursor = 1;
    }
    my $current_page_number = $cursor;
    my $per_page = 2;
    my $index = ($cursor - 1) * $per_page;

    my @page_results =
        grep { $_ } @results[$index..($index + $per_page - 1)];

    my $result_count = scalar @results;
    my $page_count = $result_count / $per_page;
    if (int($page_count) != $page_count) {
        $page_count++;
    }
    my $value = $self->{'url_base'}.$r->uri()->as_string();

    $query_form{'cursor'} = $cursor + 1;
    my $new_uri = URI->new($r->uri());
    $new_uri->query_form(%query_form);
    my $next = $self->{'url_base'}.$new_uri->as_string();

    my $sort_uri = URI->new($r->uri());
    my %s_query_form = $sort_uri->query_form();
    delete $s_query_form{'sort'};
    delete $s_query_form{'cursor'};
    my $make_link = sub {
        my ($sort_value) = @_;
        $s_query_form{'sort'} = $sort_value;
        my $new_uri = URI->new($r->uri());
        $new_uri->query_form(%s_query_form);
        return $self->{'url_base'}.'/'.$new_uri->as_string();
    };

    my $data = {
        rdapConformance => [qw(rdap_level_0
                               paging_level_0
                               sorting_level_0)],
        domainSearchResults => \@page_results,
        paging_metadata => {
            totalCount => (scalar @results),
            pageSize   => (scalar @page_results),
            pageNumber => $current_page_number,
            links      => [
                { value => $value,
                  rel   => 'next',
                  href  => $next,
                  title => 'Result pagination link',
                  type  => 'application/rdap+json' }
            ]
        },
        ($sort)
            ? (sorting_metadata => {
                currentSort => $sort,
                availableSorts => [
                    { property => 'name',
                      jsonPath => '$.domainSearchResults[*].ldhName',
                      default  => \0,
                      links    => [
                          { value => $value,
                            rel   => 'alternate',
                            href  => $make_link->('name:a'),
                            title => 'Result Ascending Sort Link' },
                          { value => $value,
                            rel   => 'alternate',
                            href  => $make_link->('name:d'),
                            title => 'Result Descending Sort Link' }
                      ] }
                ]
              })
            : ()
    };

    if ($page_count == $cursor) {
        delete $data->{'paging_metadata'}->{'links'};
    }
    if ((exists $query_form{'count'})
            and (not $query_form{'count'})) {
        delete $data->{'paging_metadata'}->{'totalCount'};
    }

    return HTTP::Response->new(HTTP_OK, undef, [],
                               encode_json($data));
}

sub _add_defaults
{
    my ($self, $res) = @_;

    if (not $res->content()) {
        return 1;
    }

    my $data = decode_json($res->content());
    my $defaults = $self->{'defaults'};
    for my $key (keys %{$defaults}) {
        if (not exists $data->{$key}) {
            $data->{$key} = $defaults->{$key};
        }
    }

    $res->content(encode_json($data));
    return 1;
}

sub run
{
    my ($self) = @_;

    my $d = $self->{"d"};
    while (my $c = $d->accept()) {
        while (my $r = $c->get_request()) {
            my $method = $r->method();
            my $path = $r->uri()->path();
            my $res;
            eval {
                if ($method eq 'POST') {
                    if ($path eq '/refresh') {
                        $res = $self->_refresh();
                    } elsif ($path eq '/shutdown') {
                        $c->send_response(HTTP::Response->new(HTTP_OK));
                        goto done;
                    }
                } elsif ($method eq 'HEAD' or $method eq 'GET') {
                    if ($path =~ /\/entity\/.*/) {
                        $res = $self->_get_entity($r);
                    } elsif ($path =~ /\/ip\/.*/) {
                        $res = $self->_get_ip($r);
                    } elsif ($path =~ /\/autnum\/.*/) {
                        $res = $self->_get_autnum($r);
                    } elsif ($path =~ /\/domain\/.*/) {
                        $res = $self->_get_domain($r);
                    } elsif ($path =~ /\/nameserver\/.*/) {
                        $res = $self->_get_nameserver($r);
                    } elsif ($path eq '/domains') {
                        $res = $self->_search_domains($r);
                    } elsif ($path eq '/entities') {
                        $res = $self->_search_entities($r);
                    }
                }
                if ($res) {
                    $self->_add_defaults($res);
                }
            };
            if (my $error = $@) {
                warn $error;
                $res = HTTP::Response->new(HTTP_INTERNAL_SERVER_ERROR);
            } elsif (not $res) {
                $res = HTTP::Response->new(HTTP_NOT_FOUND);
            }
            if ($method eq 'HEAD') {
                $res->content('');
            }
            $c->send_response($res);
        }
    }

    done:
    return 1;
}

1;

__END__

=head1 NAME

APNIC::RDAP::RMP::Client

=head1 DESCRIPTION

Client implementation for the RDAP Mirroring Protocol (RMP).  This
also provides RDAP service for the objects that it retrieves via
mirroring.  See draft-harrison-regext-rdap-mirroring.

=head1 CONSTRUCTOR

=over 4

=item B<new>

Parameters (hash):

=over 8

=item port

The port number for the client's RDAP server.

=item url_base

The base URL for the client's RDAP server.  This
is used to construct links from RDAP objects to
other RDAP objects.  If not set, it will default
to "http://localhost:$port".

=item object_path

The path to the directory where RDAP objects will
be written by the client.

=item unf_url

The URL of the mirroring server's update
notification file.

=item key

The mirroring server's public key (PEM-encoded),
for verifying the signatures on the files returned
by that server.

=back

=head1 PUBLIC METHODS

=over 4

=item B<run>

Run the client.

=back

=head1 ENDPOINTS

=over 4

=item B<POST /refresh>

Refresh the mirroring state by fetching the update notification file
from the mirroring server and processing the snapshot and/or deltas
accordingly.

=item B<GET /{object-type}/...>

RDAP service endpoints for the objects retrieved via mirroring.
The currently-supported object types are C<ip network>, C<autnum>,
C<domain>, C<entity> and C<nameserver>.  Search endpoints are not
supported at the moment.

=back

=cut
