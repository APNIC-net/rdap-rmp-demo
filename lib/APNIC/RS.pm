package APNIC::RS;

use warnings;
use strict;

use Clone qw(clone);
use List::Util qw(max);
use Net::IP::XS qw($IP_PARTIAL_OVERLAP
                   $IP_NO_OVERLAP
                   $IP_A_IN_B_OVERLAP
                   $IP_B_IN_A_OVERLAP
                   $IP_IDENTICAL
                   ip_inttobin
                   ip_bintoip
                   ip_compress_address);
use Number::Range;

sub new
{
    my $class = shift;
    my @args = @_;

    my $self = {
        ipv4 => [],
        ipv6 => [],
        asn  => Number::Range->new(),
    };
    bless $self, $class;
    for my $arg (@args) {
        $self->_add($arg);
    }
    return $self;
}

sub _net_ip_from_ints
{
    my ($v, $begin, $end) = @_;

    return
        Net::IP::XS->new(
            ip_bintoip(ip_inttobin($begin, $v) || 0, $v).
            '-'.
            ip_bintoip(ip_inttobin($end, $v) || 0, $v)
        );
}

sub _net_ip_as_string
{
    my ($net_ip) = @_;

    my $v = $net_ip->version();
    my $s = $net_ip->size();
    my $p = $net_ip->prefix();
    if ($v == 4) {
        if ($s == 1) {
            return $net_ip->ip();
        } elsif ($p) {
            return $p;
        } else {
            return $net_ip->ip().'-'.$net_ip->last_ip();
        }
    } else {
        if ($s == 1) {
            return ip_compress_address($net_ip->ip(), $v);
        } elsif ($p) {
            return ip_compress_address($net_ip->ip(), $v).'/'.
                   $net_ip->prefixlen();
        } else {
            return ip_compress_address($net_ip->ip(), $v).'-'.
                   ip_compress_address($net_ip->last_ip(), $v);
        }
    }
}

sub _normalise
{
    my ($self) = @_;

    for my $v (4, 6) {
        my $list_key = 'ipv'.$v;
        my @net_ips =
            sort { $a->intip() <=> $b->intip() }
                @{$self->{$list_key}};
        my @new_net_ips = @net_ips;
        for (;;) {
            @net_ips = @new_net_ips;
            @new_net_ips = ();
            my $changed = 0;
            for (my $i = 0; $i < @net_ips; $i++) {
                my $f = $net_ips[$i];
                if ($i == (@net_ips - 1)) {
                    push @new_net_ips, $f;
                } else {
                    my $s = $net_ips[$i + 1];
                    my $overlap = $f->overlaps($s);
                    if ($overlap == $IP_IDENTICAL) {
                        push @new_net_ips, $f;
                        $i++;
                        $changed = 1;
                    } elsif ($overlap == $IP_A_IN_B_OVERLAP) {
                        push @new_net_ips, $s;
                        $i++;
                        $changed = 1;
                    } elsif ($overlap == $IP_B_IN_A_OVERLAP) {
                        push @new_net_ips, $f;
                        $i++;
                        $changed = 1;
                    } elsif ($overlap == $IP_PARTIAL_OVERLAP) {
                        my $begin = $f->intip();
                        my $end = max($f->last_int(), $s->last_int());
                        my $new = _net_ip_from_ints($v, $begin, $end);
                        push @new_net_ips, $new;
                        $i++;
                        $changed = 1;
                    } elsif (($f->last_int() + 1) == ($s->intip())) {
                        my $begin = $f->intip();
                        my $end = $s->last_int();
                        my $new = _net_ip_from_ints($v, $begin, $end);
                        push @new_net_ips, $new;
                        $i++;
                        $changed = 1;
                    } elsif ($overlap == $IP_NO_OVERLAP) {
                        push @new_net_ips, $f;
                    }
                }
            }
            if (not $changed) {
                last;
            }
        }
        $self->{$list_key} = \@new_net_ips;
    }
}

sub _add
{
    my ($self, $arg) = @_;

    if (ref $arg) {
        my @parts = split /,/, $arg->as_string();
        for my $part (@parts) {
            $self->_add($part);
        }
    } elsif ($arg =~ /\./ or $arg =~ /:/) {
        my $net_ip = Net::IP::XS->new($arg);
        if (not $net_ip) {
            die $Net::IP::XS::ERROR;
        }
        my $v = $net_ip->version();
        my $list_key = 'ipv'.$v;
        push @{$self->{$list_key}}, $net_ip;
        $self->_normalise();
    } elsif ($arg =~ /^\d+$/) {
        no warnings;
        $self->{'asn'}->addrange($arg);
    } elsif ($arg =~ /^(\d+)-(\d+)$/) {
        no warnings;
        $self->{'asn'}->addrange("$1..$2");
    }
}

sub union
{
    my ($self, $other) = @_;

    if (not ref($other)) {
        $other = APNIC::RS->new($other);
    }

    my $new_rs = APNIC::RS->new();
    my $self_str = $self->as_string();
    my $other_str = $other->as_string();

    my @parts =
        ((split /,/, $self_str),
         (split /,/, $other_str));
    for my $part (@parts) {
        $new_rs->_add($part);
    }
    return $new_rs;
}

sub intersection
{
    my ($self, $other) = @_;

    if (not ref($other)) {
        $other = APNIC::RS->new($other);
    }

    my %ips;
    $ips{4} = [];
    $ips{6} = [];
    for my $v (4, 6) {
        my $list_key = "ipv".$v;
        for my $net_ip (@{$self->{$list_key}}) {
            for my $other_net_ip (@{$other->{$list_key}}) {
                my $overlap = $net_ip->overlaps($other_net_ip);
                if ($overlap == $IP_IDENTICAL) {
                    push @{$ips{$v}}, $net_ip;
                } elsif ($overlap == $IP_A_IN_B_OVERLAP) {
                    push @{$ips{$v}}, $net_ip;
                } elsif ($overlap == $IP_B_IN_A_OVERLAP) {
                    push @{$ips{$v}}, $other_net_ip;
                } elsif ($overlap == $IP_PARTIAL_OVERLAP) {
                    if ($net_ip->intip() < $other_net_ip->intip()) {
                        my $begin = $net_ip->intip();
                        my $end   = $other_net_ip->last_int();
                        my $new = _net_ip_from_ints($v, $begin, $end);
                        push @{$ips{$v}}, $new;
                    } else {
                        my $begin = $other_net_ip->intip();
                        my $end   = $net_ip->last_int();
                        my $new = _net_ip_from_ints($v, $begin, $end);
                        push @{$ips{$v}}, $new;
                    }
                } elsif ($overlap == $IP_NO_OVERLAP) {
                    # No-op.
                }
            }
        }
    }

    my $asn = clone($self->{'asn'});
    my $other_asn = clone($other->{'asn'});

    my $a_ranges = ($asn->size() ? $asn->range() : '');
    my $b_ranges = ($other_asn->size() ? $other_asn->range() : '');
    {
        no warnings;
        $asn->delrange($b_ranges);
    }
    {
        no warnings;
        $other_asn->delrange($a_ranges);
    }
    my $a_pls_b = clone($self->{'asn'});
    {
        no warnings;
        $a_pls_b->addrange($b_ranges);
        if ($asn->size()) {
            my $a_sub_b = $asn->range();
            $a_pls_b->delrange($a_sub_b);
        }
        if ($other_asn->size()) {
            my $b_sub_a = $other_asn->range();
            $a_pls_b->delrange($b_sub_a);
        }
    }

    my $new_rs = APNIC::RS->new();
    $new_rs->{'ipv4'} = $ips{'4'};
    $new_rs->{'ipv6'} = $ips{'6'};
    $new_rs->{'asn'}  = $a_pls_b;
    $new_rs->_normalise();
    return $new_rs;
}

sub subtract
{
    my ($self, $other) = @_;

    if (not ref($other)) {
        $other = APNIC::RS->new($other);
    }

    my %ips;
    $ips{4} = [];
    $ips{6} = [];
    for my $v (4, 6) {
        my $list_key = "ipv".$v;
        for my $net_ip (@{$self->{$list_key}}) {
            for my $other_net_ip (@{$other->{$list_key}}) {
                my $overlap = $net_ip->overlaps($other_net_ip);
                if ($overlap == $IP_IDENTICAL) {
                    # No-op.
                } elsif ($overlap == $IP_A_IN_B_OVERLAP) {
                    # No-op.
                } elsif ($overlap == $IP_B_IN_A_OVERLAP) {
                    {
                        no warnings;
                        my $begin = $net_ip->intip();
                        my $end   = $other_net_ip->intip() - 1;
                        my $new = _net_ip_from_ints($v, $begin, $end);
                        if (defined $new) {
                            push @{$ips{$v}}, $new;
                        }
                    }
                    {
                        no warnings;
                        my $begin = $other_net_ip->last_int() + 1;
                        my $end   = $net_ip->last_int();
                        my $new = _net_ip_from_ints($v, $begin, $end);
                        if (defined $new) {
                            push @{$ips{$v}}, $new;
                        }
                    }
                } elsif ($overlap == $IP_PARTIAL_OVERLAP) {
                    if ($net_ip->intip() < $other_net_ip->intip()) {
                        my $begin = $net_ip->intip();
                        my $end   = $other_net_ip->intip() - 1;
                        my $new = _net_ip_from_ints($v, $begin, $end);
                        if (defined $new) {
                            push @{$ips{$v}}, $new;
                        }
                    } else {
                        my $begin = $other_net_ip->intip();
                        my $end   = $net_ip->intip() - 1;
                        my $new = _net_ip_from_ints($v, $begin, $end);
                        if (defined $new) {
                            push @{$ips{$v}}, $new;
                        }
                    }
                } elsif ($overlap == $IP_NO_OVERLAP) {
                    push @{$ips{$v}}, $net_ip;
                }
            }
        }
    }

    my $asn = clone($self->{'asn'});
    if ($other->{'asn'}->size()) {
        my $b_ranges = $other->{'asn'}->range();
        {
            no warnings;
            $asn->delrange($b_ranges);
        }
    }

    my $new_rs = APNIC::RS->new();
    $new_rs->{'ipv4'} = $ips{'4'};
    $new_rs->{'ipv6'} = $ips{'6'};
    $new_rs->{'asn'}  = $asn;
    $new_rs->_normalise();
    return $new_rs;
}

sub as_string
{
    my ($self) = @_;

    my @parts =
        map { _net_ip_as_string($_) }
            (@{$self->{'ipv4'}},
             @{$self->{'ipv6'}});
    push @parts, (map { @{$_} == 1
                        ? $_->[0]
                        : $_->[0].'-'.$_->[1] }
                            $self->{'asn'}->rangeList());

    return (join ',', @parts);
}

sub equals
{
    my ($self, $other) = @_;

    return ($self->as_string() eq $other->as_string());
}

sub is_empty
{
    my ($self) = @_;

    return ($self->as_string() eq '');
}

1;
