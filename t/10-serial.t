#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 40;

use APNIC::RDAP::RMP::Serial qw(new_serial);

{
    my $serial = eval { new_serial(8, -1); };
    my $error = $@;
    ok($error, 'Unable to instantiate negative serial number');
    like($error, qr/Value.*must be a positive number/,
        'Got correct error message');

    $serial = eval { new_serial(8, 1024); };
    $error = $@;
    ok($error, 'Unable to instantiate number that is too large');
    like($error, qr/Value.*is too large/,
        'Got correct error message');
}

{
    my $serial = new_serial(8, 1);
    my $res = eval { $serial < 24 };
    my $error = $@;
    ok($error, 'Unable to compare serial to non-serial');
    like($error, qr/Both operands must be serial numbers/,
        'Got correct error message');

    my $number = 24;
    my $number_obj = bless \$number, 'Package';
    $res = eval { $serial < $number_obj };
    $error = $@;
    ok($error, 'Unable to compare serial to non-serial');
    like($error, qr/Both operands must be serial numbers/,
        'Got correct error message');

    my $other_serial = new_serial(9, 1);
    $res = eval { $serial < $other_serial };
    $error = $@;
    ok($error, 'Unable to compare serials of different widths');
    like($error, qr/Operands must have the same bitsize/,
        'Got correct error message');
}

{
    my $serial0   = new_serial(8, 0);
    my $serial1   = new_serial(8, 1);
    my $serial2   = new_serial(8, 2);
    my $serial127 = new_serial(8, 127);
    my $serial128 = new_serial(8, 128);
    my $serial129 = new_serial(8, 129);
    my $serial255 = new_serial(8, 255);

    ok($serial1 == $serial1,       '1 equals 1 (8 bits)');
    ok((not $serial1 == $serial2), '1 does not equal 2 (8 bits)');
    ok($serial1 != $serial2,       '1 does not equal 2 (8 bits) (2)');
    ok((not $serial1 < $serial1),  '1 is not less than 1 (8 bits)');
    ok($serial1 < $serial2,        '1 is less than 2 (8 bits)');
    ok((not $serial1 > $serial1),  '1 is not greater than 1 (8 bits)');
    ok($serial2 > $serial1,        '2 is greater than 1 (8 bits)');
    is($serial1 <=> $serial2, -1,  '1 compares less than 2 (8 bits)');
    is($serial2 <=> $serial1,  1,  '2 compares greater than 1 (8 bits)');
    is($serial1 <=> $serial1,  0,  '1 compares equal to 1 (8 bits)');

    ok($serial0 > $serial255,      '0 compares greater than 255 (8 bits)');
    ok($serial255 < $serial0,      '255 compares less than 0 (8 bits)');

    ok($serial127 > $serial0,       '127 is greater than 0 (8 bits)');
    my $res = eval { $serial128 > $serial0 };
    my $error = $@;
    ok($error, 'Unable to compare serials where result is undefined');
    like($error, qr/Comparison.*is undefined/,
        'Got correct error message');
    ok((not $serial129 > $serial0),
        '129 is not greater than 0 (8 bits)');
    ok($serial129 < $serial0,
        '129 is less than 0 (8 bits)');

    ok($serial0 < $serial127,       '0 is less than 127 (8 bits)');
    $res = eval { $serial0 < $serial128 };
    $error = $@;
    ok($error, 'Unable to compare serials where result is undefined');
    like($error, qr/Comparison.*is undefined/,
        'Got correct error message');
    ok((not $serial0 < $serial129),
        '0 is not less than 129 (8 bits)');
    ok($serial0 > $serial129,
        '0 is greater than 129 (8 bits)');

    $res = eval { $serial0 <=> $serial128 };
    $error = $@;
    ok($error, 'Unable to compare serials where result is undefined (2)');
    like($error, qr/Comparison.*is undefined/,
        'Got correct error message');
}

{
    my $serial1 = new_serial(8, 1);
    my $serial2 = new_serial(8, 2);
    my $serial3 = new_serial(8, 3);

    my $serial_add = $serial1 + $serial2;
    ok($serial_add, 'Added one serial number to another');
    ok(($serial3 == $serial_add), 'Got correct result from addition');

    $serial_add = $serial1 + 2;
    ok($serial_add, 'Added an integer to a serial number');
    ok(($serial3 == $serial_add), 'Got correct result from addition');

    $serial_add = eval { $serial1 + 1000 };
    my $error = $@;
    ok($error, 'Unable to add integer to serial where integer is too large');
    like($error, qr/too large/,
        'Got correct error message');

}

1;
