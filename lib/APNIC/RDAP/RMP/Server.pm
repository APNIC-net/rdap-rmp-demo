package APNIC::RDAP::RMP::Server;

use warnings;
use strict;

use Crypt::JWT qw(encode_jwt);
use Digest::MD5 qw(md5_hex);
use File::Find;
use File::Slurp qw(read_file write_file);
use HTTP::Daemon;
use HTTP::Status qw(:constants);
use JSON::XS qw(decode_json encode_json);
use List::Util qw(first);

use APNIC::RDAP::RMP::Serial qw(new_serial);

our $VERSION = '0.1';

sub new
{
    my $class = shift;
    my %args = @_;
    if (not $args{'db_path'}) {
        die "db_path is a required argument";
    }

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
    $self->_load_db();
    return $self;
}

sub _load_db
{
    my ($self) = @_;

    if (not -e $self->{'db_path'}) {
        die "db_path does not exist";
    }

    my $json = JSON::XS->new();
    $json->allow_tags(1);
    $self->{'db'} = $json->decode(read_file($self->{'db_path'}));
    if (not keys %{$self->{'db'}}) {
        $self->{'db'}->{'serial'} = new_serial(32, 0);
    }

    return 1;
}

sub save_db
{
    my ($self) = @_;

    my $json = JSON::XS->new();
    $json->allow_tags(1);
    write_file($self->{'db_path'}, $json->encode($self->{'db'}));
    return 1;
}

sub _snapshot_generate
{
    my ($self) = @_;

    warn "Generating snapshot...\n";

    my ($url_base, $object_path, $data_path, $defaults, $key) =
        @{$self}{qw(url_base object_path data_path defaults key)};

    my $db = $self->{'db'};
    $db->{'serial'}++;

    my %hashes;
    my @objects;
    find(sub {
        my $path = $File::Find::name;
        if (-d $path) {
            return;
        }

        my $content = read_file($path);
        my $object_data = decode_json($content);
        my $id = _get_self_link($path, $object_data);
        push @objects, { id => $id, object => $object_data };
        warn "  Adding object to snapshot: $id\n";

        my $digest = md5_hex($content);
        $hashes{$path} = [ $digest, $id ];
    }, $object_path);
    $db->{'hashes'} = \%hashes;

    my %snapshot = (
        version  => 1,
        serial   => $db->{'serial'}->to_string(),
        defaults => $defaults,
        objects  => \@objects,
    );

    use Data::Dumper;
    warn "  Snapshot content: ".encode_json(\%snapshot)."\n";

    my $data = encode_jwt(payload => encode_json(\%snapshot),
                          key => \$key,
                          alg => 'ES256',
                          serialization => 'compact');

    my $snapshot_post =
        '/snapshot/snapshot-'.$db->{'serial'}->to_string().'.json';
    my $snapshot_path = $data_path.$snapshot_post;
    write_file($snapshot_path, $data);

    my $snapshot_uri = $url_base.$snapshot_post;

    $db->{'snapshot_serial'} = $db->{'serial'};
    $db->{'snapshot_uri'} = $snapshot_uri;
    $db->{'deltas'} = [];

    warn "Finished generating snapshot.\n";

    return HTTP::Response->new(HTTP_OK);
}

sub _unf_generate
{
    my ($self) = @_;

    warn "Generating UNF...\n";

    my ($url_base, $refresh, $data_path, $key) =
        @{$self}{qw(url_base refresh data_path key)};

    my $db = $self->{'db'};
    if (not $db->{'snapshot_uri'}) {
        die "No current snapshot, cannot generate UNF";
    }

    my %unf = (
        version => 1,
        refresh => $refresh,
        snapshot => {
            uri    => $db->{'snapshot_uri'},
            serial => $db->{'snapshot_serial'}->to_string(),
        },
        deltas => $db->{'deltas'},
    );

    warn "  UNF content: ".encode_json(\%unf)."\n";

    my $data = encode_jwt(payload => encode_json(\%unf),
                          key => \$key,
                          alg => 'ES256',
                          serialization => 'compact');

    my $unf_post = '/unf/unf.json';
    my $unf_path = $data_path.$unf_post;
    write_file($unf_path, $data);

    my $unf_uri = $url_base.$unf_post;
    $db->{'unf_uri'} = $unf_uri;

    warn "Finished generating UNF.\n";

    return HTTP::Response->new(HTTP_OK);
}

sub _get_self_link
{
    my ($path, $object_data) = @_;

    my $self_link =
        first { (($_->{'rel'} || '') eq 'self') }
            @{$object_data->{'links'} || []};
    if (not $self_link) {
        die "Object '$path' has no self link";
    }
    my $id = $self_link->{'href'};
    if (not $id) {
        die "Object '$path' has no href in self link";
    }

    return $id;
}

sub _delta_generate
{
    my ($self) = @_;

    warn "Generating delta...\n";

    my ($url_base, $object_path, $data_path, $defaults, $key) =
        @{$self}{qw(url_base object_path data_path defaults key)};

    my $db = $self->{'db'};
    my %hashes = %{$db->{'hashes'} || {}};

    my %new_hashes;
    find(sub {
        my $path = $File::Find::name;
        if (-d $path) {
            return;
        }

        my $content = read_file($path);
        my $object_data = decode_json($content);
        my $id = _get_self_link($path, $object_data);

        my $digest = md5_hex($content);
        $new_hashes{$path} = [ $digest, $id ];
    }, $object_path);

    my @removed_ids =
        map  { $hashes{$_}->[1] }
        grep { not $new_hashes{$_} }
            keys %hashes;

    my @added_paths =
        grep { not $hashes{$_} }
            keys %new_hashes;

    my @updated_paths =
        grep { $new_hashes{$_}
                and $hashes{$_}->[0] ne $new_hashes{$_}->[0] }
            keys %hashes;

    if (@removed_ids) {
        warn "  Removed objects:\n";
        for my $removed_id (@removed_ids) {
            warn "    $removed_id\n";
        }
    } else {
        warn "  No objects removed.\n";
    }
    if (@added_paths) {
        warn "  Added objects:\n";
        for my $added_path (@added_paths) {
            warn "    $added_path\n";
        }
    } else {
        warn "  No objects added.\n";
    }
    if (@updated_paths) {
        warn "  Updated objects:\n";
        for my $updated_path (@updated_paths) {
            warn "    $updated_path\n";
        }
    } else {
        warn "  No objects updated.\n";
    }

    if (not @removed_ids and not @added_paths and not @updated_paths) {
        warn "No changed detected, delta generation not required.\n";
        return HTTP::Response->new(HTTP_OK);
    }

    $db->{'serial'}++;

    my %delta = (
        version  => 1,
        serial   => $db->{'serial'}->to_string(),
        defaults => $defaults,
        removed_objects => \@removed_ids,
        added_or_updated_objects => [
            map { my $path = $_;
                  my $object_data = decode_json(read_file($path));
                  my $id = _get_self_link($path, $object_data);
                  +{ id => $id, object => $object_data } }
                (@added_paths, @updated_paths)
        ],
    );

    warn "  Delta content: ".encode_json(\%delta);

    my $data = encode_jwt(payload => encode_json(\%delta),
                          key => \$key,
                          alg => 'ES256',
                          serialization => 'compact');

    my $delta_post =
        '/delta/delta-'.$db->{'serial'}->to_string().'.json';
    my $delta_path = $data_path.$delta_post;
    write_file($delta_path, $data);

    my $delta_uri = $url_base.$delta_post;

    $db->{'delta_serial'} = $db->{'serial'}->to_string();
    $db->{'delta_uri'} = $delta_uri;
    push @{$db->{'deltas'}}, {
        uri    => $delta_uri,
        serial => $db->{'serial'}->to_string(),
    };

    warn "Finished generating delta.\n";

    return HTTP::Response->new(HTTP_OK);
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
                    if ($path eq '/snapshot/generate') {
                        $res = $self->_snapshot_generate();
                    } elsif ($path eq '/delta/generate') {
                        $res = $self->_delta_generate();
                    } elsif ($path eq '/unf/generate') {
                        $res = $self->_unf_generate();
                    } elsif ($path eq '/shutdown') {
                        $c->send_response(HTTP::Response->new(HTTP_OK));
                        goto done;
                    }
                } elsif ($method eq 'GET') {
                    if ($path !~ /^\/(unf|snapshot|delta)\//) {
                        return HTTP::Response->new(HTTP_NOT_FOUND);
                    }
                    my $data_path = $self->{'data_path'};
                    my $request_path = $data_path.$path;
                    $res = HTTP::Response->new(HTTP_OK, undef,
                                               [], read_file($request_path));
                }
            };
            if (my $error = $@) {
                warn $error;
                $res = HTTP::Response->new(HTTP_INTERNAL_SERVER_ERROR);
            } elsif (not $res) {
                $res = HTTP::Response->new(HTTP_NOT_FOUND);
            }
            $c->send_response($res);
            $self->save_db();
        }
    }

    done:
    return 1;
}

1;

__END__

=head1 NAME

APNIC::RDAP::RMP::Server

=head1 DESCRIPTION

Server implementation for the RDAP Mirroring Protocol (RMP).  See
draft-harrison-regext-rdap-mirroring.

=head1 CONSTRUCTOR

=over 4

=item B<new>

Parameters (hash):

=over 8

=item port

The port number for the server.

=item refresh

The refresh time (in seconds) that should be
included in the update notification file.

=item defaults

The object defaults that should be included in
snapshot and delta files.

=item url_base

The base URL for the server.  This is used to
construct links from the update notification file
to snapshots/deltas.  If not set, it will default
to "http://localhost:$port".

=item db_path

The path to the server's database file.  For a new
server, create a file at this path with the
content '{}'.

=item data_path

The path where the server will write update
notification files, snapshots, and deltas.  This
directory must contain directories named 'unf',
'snapshot', and 'delta'.

=item object_path

The path to the directory where RDAP objects will
be written.  The server will search this
directory (including any subdirectories) for
objects when it is generating snapshots and
deltas.

=item key

The server's private key (PEM-encoded), for
signing the files returned by the server.

=back

=head1 PUBLIC METHODS

=over 4

=item B<save_db>

Save the server's database to the C<db_path>
specified during construction.

=item B<run>

Run the server.

=back

=head1 ENDPOINTS

=over 4

=item B<POST /snapshot/generate>

Generate a new snapshot based on the objects that have been
written to the object path.

=item B<POST /delta/generate>

Generate a new delta (if necessary), based on the objects that
have been written to the object path.

=item B<POST /unf/generate>

Generate a new update notification file.

=item B<GET /unf/unf.json>

Fetch the current update notification file.

=item B<GET /snapshot/...>

Fetch snapshots.  The snapshot links are managed by the application:
the user will see the links in the update notification file.

=item B<GET /delta/...>

Fetch deltas.  As with snapshots, the links are managed by the
application, and the user will see the links in the update
notification file.

=back

=cut
