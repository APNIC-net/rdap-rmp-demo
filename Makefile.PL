use strict;
use warnings;

use ExtUtils::MakeMaker;
use ExtUtils::MakeMaker::Config;

my $output = WriteMakefile(
    NAME           => 'APNIC::RDAP::RMP::Server',
    AUTHOR         => 'Software <software@apnic.net>',
    LICENSE        => 'bsd',
    VERSION_FROM   => 'lib/APNIC/RDAP/RMP/Server.pm',
    META_MERGE     => {
        resources => {
            repository => 'https://github.com/APNIC-net/rdap-rmp-demo'
        }
    },
    EXE_FILES      => [ qw(bin/rdap-rmp-server
                           bin/rdap-rmp-client
                           bin/rdap-rmp-generate-key
                           bin/rdap-rmp-test-setup) ],
    PREREQ_PM      => { 'Crypt::JWT'             => 0,
                        'JSON::XS'               => 0,
                        'Net::IP::XS'            => 0,
                        'Set::IntervalTree'      => 0,
                        'Net::Patricia'          => 0,
                        'Test::More'             => 0,
                        'HTTP::Daemon'           => 0,
                        'LWP::UserAgent'         => 0 },
);

1;
