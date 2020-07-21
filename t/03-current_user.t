#!/usr/bin/env perl
use strict;
use warnings;

# Disable IPv6, epoll and kqueue
BEGIN { $ENV{MOJO_NO_IPV6} = $ENV{MOJO_POLL} = 1 }

use Test::More;
plan tests => 6;

use Mojo::File qw(path);
use lib path(qw(t lib))."";
use TestUtils qw(load_user_t validate_user_t);

# testing code starts here
use Mojolicious::Lite;
use Test::Mojo;

plugin 'Authentication', {
    autoload_user => 1,
    load_user => \&load_user_t,
    validate_user => \&validate_user_t,
};

get '/other/endpoint' => sub {
    my $self = shift;
    $self->authenticate( 'foo', 'bar' );
    $self->render( text => $self->current_user->{username} );
};

under '/api' => sub {
    my $self = shift;
    $self->current_user( { username => 'custom' } );
    return 1;
};

get '/endpoint' => sub {
    my $self = shift;
    $self->render( text => $self->current_user->{username} );
};

my $t = Test::Mojo->new;
$t->get_ok( '/other/endpoint' )->status_is( 200 )->content_is( 'foo' );
$t->get_ok( '/api/endpoint' )->status_is( 200 )->content_is( 'custom' );

