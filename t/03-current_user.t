#!/usr/bin/env perl
use strict;
use warnings;

# Disable IPv6, epoll and kqueue
BEGIN { $ENV{MOJO_NO_IPV6} = $ENV{MOJO_POLL} = 1 }

use Test::More;
plan tests => 6;

# testing code starts here
use Mojolicious::Lite;
use Test::Mojo;

plugin 'authentication', {
    autoload_user => 1,
    load_user => sub {
        my $self = shift;
        my $uid  = shift;

        return {
            'username' => 'foo',
            'password' => 'bar',
            'name'     => 'Foo'
            } if($uid eq 'userid' || $uid eq 'useridwithextradata');
        return undef;
    },
    validate_user => sub {
        my $self = shift;
        my $username = shift || '';
        my $password = shift || '';
        my $extradata = shift || {};

        return 'useridwithextradata' if($username eq 'foo' && $password eq 'bar' && ( $extradata->{'ohnoes'} || '' ) eq 'itsameme');
        return 'userid' if($username eq 'foo' && $password eq 'bar');
        return undef;
    },
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

