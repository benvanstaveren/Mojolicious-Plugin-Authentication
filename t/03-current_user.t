#!/usr/bin/env perl
use strict;
use warnings;

# Disable IPv6, epoll and kqueue
BEGIN { $ENV{MOJO_NO_IPV6} = $ENV{MOJO_POLL} = 1 }

use Test::More;

use Mojo::File qw(path);
use lib path(qw(t lib))."";
use TestUtils qw(load_user_t validate_user_t load_user_t_p validate_user_t_p);

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
under '/'; # reset

my $t = Test::Mojo->new;
$t->get_ok( '/other/endpoint' )->status_is( 200 )->content_is( 'foo' );
$t->get_ok( '/api/endpoint' )->status_is( 200 )->content_is( 'custom' );

plugin 'Authentication', {
    autoload_user => 1,
    load_user_p => \&load_user_t_p,
    validate_user_p => \&validate_user_t_p,
};
get '/other/endpoint_p' => sub {
    my $c = shift;
    $c->authenticate_p( 'foo', 'bar' )
        ->then(sub { $c->current_user_p })
        ->then(sub { $c->render( text => $_[0]->{username} ) });
};
under '/api_p' => sub {
    my $c = shift;
    $c->current_user_p( { username => 'custom' } )->then(sub { $c->continue });
    return undef;
};
get '/endpoint_p' => sub {
    my $c = shift;
    $c->current_user_p->then(sub {
        $c->render( text => $_[0]->{username} );
    });
};

$t = Test::Mojo->new;
$t->get_ok( '/other/endpoint_p' )->status_is( 200 )->content_is( 'foo' );
$t->get_ok( '/api_p/endpoint_p' )->status_is( 200 )->content_is( 'custom' );

done_testing;
