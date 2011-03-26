#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'Mojolicious::Plugin::Authentication' ) || print "Bail out!
";
}

diag( "Testing Mojolicious::Plugin::Authentication $Mojolicious::Plugin::Authentication::VERSION, Perl $], $^X" );
