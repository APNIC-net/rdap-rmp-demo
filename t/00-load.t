#!/usr/bin/perl

use warnings;
use strict;

use Test::More tests => 3;

BEGIN {
    use_ok("APNIC::RDAP::RMP::Serial");
    use_ok("APNIC::RDAP::RMP::Client");
    use_ok("APNIC::RDAP::RMP::Server");
}

1;
