package APNIC::RDAP::RMP::Serial;

use warnings;
use strict;

use overload '=='   => 'equals',
             '!='   => 'not_equals',
             '<'    => 'less_than',
             '>'    => 'greater_than',
             '<=>'  => 'compare',
             '+'    => 'add',
             '""'   => 'to_string';

use Exporter qw(import);
use Scalar::Util qw(blessed);

our @EXPORT_OK = qw(new_serial);

our $VERSION = do { my ($v) = q$Rev: 1382836393 - $ =~ /(d+)/; sprintf "2.%04d", ($v || 1) };

sub new_serial
{
    my ($bits, $value) = @_;

    if ($value !~ /^\d+$/) {
        die "Value ($value) must be a positive number.";
    }
    if ($value > ((2 ** $bits) - 1)) {
        die "Value ($value) is too large to fit within $bits bits.";
    }

    my $self = {
        bits  => $bits,
        value => $value,
    };

    bless $self, 'APNIC::RDAP::RMP::Serial';

    return $self;
}

sub _verify_operands
{
    my ($obj1, $obj2) = @_;

    for my $obj ($obj1, $obj2) {
        if (not blessed $obj or not $obj->isa('APNIC::RDAP::RMP::Serial')) {
            die "Both operands must be serial numbers.";
        }
    }

    if ($obj1->{'bits'} ne $obj2->{'bits'}) {
        die "Operands must have the same bitsize.";
    }

    return 1;
}

sub _less_than
{
    my ($self, $other) = @_;

    my ($svalue, $ovalue) = map { $_->{'value'} } ($self, $other);

    my $half_space = (2 ** ($self->{'bits'} - 1));

    return
            (($svalue < $ovalue and ($ovalue - $svalue < $half_space))
          or ($svalue > $ovalue and ($svalue - $ovalue > $half_space)));
}

sub _greater_than
{
    my ($self, $other) = @_;

    my ($svalue, $ovalue) = map { $_->{'value'} } ($self, $other);

    my $half_space = (2 ** ($self->{'bits'} - 1));

    return
            (($svalue < $ovalue and ($ovalue - $svalue > $half_space))
         or  ($svalue > $ovalue and ($svalue - $ovalue < $half_space)));
}

sub add
{
    my ($self, $other) = @_;

    if (not blessed $other) {
        $other = new_serial($self->{'bits'}, $other);
    }
    _verify_operands($self, $other);

    my ($svalue, $ovalue) = ($self->{'value'}, $other->{'value'});
    my $max = (2 ** ($self->{'bits'} - 1)) - 1;

    my $new_value = ($svalue + $ovalue) % (2 ** $self->{'bits'});

    return new_serial($self->{'bits'}, $new_value);
}

sub equals
{
    my ($self, $other) = @_;

    _verify_operands($self, $other);

    return ($self->{'value'} == $other->{'value'});
}

sub not_equals
{
    my ($self, $other) = @_;

    _verify_operands($self, $other);

    return ($self->{'value'} != $other->{'value'});
}

sub less_than
{
    my ($self, $other) = @_;

    _verify_operands($self, $other);
    my ($svalue, $ovalue) = map { $_->{'value'} } ($self, $other);

    if (_less_than($self, $other)) {
        return 1;
    }
    elsif ($self == $other) {
        return 0;
    }
    elsif (_greater_than($self, $other)) {
        return 0;
    }

    die "Comparison of serials $svalue and $ovalue ".
        "(bitsize ".$self->{'bits'}.") is undefined.";
}

sub greater_than
{
    my ($self, $other) = @_;

    _verify_operands($self, $other);
    my ($svalue, $ovalue) = map { $_->{'value'} } ($self, $other);

    if (_greater_than($self, $other)) {
        return 1;
    }
    elsif ($self == $other) {
        return 0;
    }
    elsif (_less_than($self, $other)) {
        return 0;
    }
    die "Comparison of serials $svalue and $ovalue ".
        "(bitsize ".$self->{'bits'}.") is undefined.";
}

sub compare
{
    my ($self, $other) = @_;

    _verify_operands($self, $other);
    my ($svalue, $ovalue) = map { $_->{'value'} } ($self, $other);

    if (_greater_than($self, $other)) {
        return 1;
    }
    elsif ($self == $other) {
        return 0;
    }
    elsif (_less_than($self, $other)) {
        return -1;
    }
    die "Comparison of serials $svalue and $ovalue ".
        "(bitsize ".$self->{'bits'}.") is undefined.";
}

sub to_string
{
    return $_[0]->{'value'};
}

sub FREEZE
{
    return ($_[0]->{'bits'}, $_[0]->{'value'});
}

sub THAW
{
    return new_serial($_[2], $_[3]);
}

1;

__END__

=head1 NAME

APNIC::RDAP::RMP::Serial

=head1 DESCRIPTION

Library for serial number arithmetic (per RFC 1982).  If a comparison
or addition would yield an undefined result (see [3.2]), an exception
will be thrown.

Each of the public operators defined below has a corresponding
overload (e.g. C<+> for C<add>).

=head1 CONSTRUCTOR

=over 4

=item B<new_serial>

Takes the size of the serial number (in bits) and the value of the
serial number, and returns a new serial number object.

=back

=head1 PUBLIC OPERATORS

=over 4

=item B<add>

Takes an instance of L<APNIC::RDAP::RMP::Serial> as its first argument and
either a positive integer or another instance of
L<APNIC::RDAP::RMP::Serial> as its second argument.

=item B<equals>

Takes two instances of L<APNIC::RDAP::RMP::Serial> as its arguments.
Returns true if the underlying values of the two arguments are equal.

=item B<not_equals>

Self-explanatory.

=item B<less_than>

Takes two instances of L<APNIC::RDAP::RMP::Serial> as its arguments.
Returns true if the second value is less than the first in accordance
with serial number arithmetic.  Dies if the result is not defined (as
per [3.2]).

=item B<greater_than>

Takes two instances of L<APNIC::RDAP::RMP::Serial> as its arguments.
Returns true if the second value is greater than the first in
accordance with serial number arithmetic.  Dies if the result is not
defined (as per [3.2]).

=item B<compare>

Takes two instances of L<APNIC::RDAP::RMP::Serial> as its arguments.
Compares the two arguments and returns -1, 0, or 1 depending on
whether the first argument is less than, equal to, or greater than the
second argument.

=item B<to_string>

The string representation of a serial number is the underlying
integral value (bitsize is ignored).

=back
