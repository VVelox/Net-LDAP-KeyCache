#!perl
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Net::LDAP::KeyCache' ) || print "Bail out!\n";
}

diag( "Testing Net::LDAP::KeyCache $Net::LDAP::KeyCache::VERSION, Perl $], $^X" );
