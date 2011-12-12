#!/usr/bin/env perl
use strict;
use warnings;

# Disable IPv6, epoll and kqueue
BEGIN { $ENV{MOJO_NO_IPV6} = $ENV{MOJO_POLL} = 1 }

use Test::More;
plan tests => 38;

# testing code starts here
use Mojolicious::Lite;
use Test::Mojo;

plugin 'authentication', {
    lazy_mode => 1,
    load_user => sub {
        my $self = shift;
        my $uid  = shift;

        return {
            'username' => 'foo',
            'password' => 'bar',
            'name'     => 'Foo'
          }
          if ( $uid eq 'userid' );
        return undef;
    },
    validate_user => sub {
        my $self      = shift;
        my $username  = shift || '';
        my $password  = shift || '';
        my $extradata = shift || {};

        return 'userid' if ( $username eq 'foo' && $password eq 'bar' );
        return undef;
    },
};

get '/' => sub {
    my $self = shift;
    $self->render( text => 'index page' );
};

post '/login' => sub {
    my $self = shift;
    my $u    = $self->req->param('u');
    my $p    = $self->req->param('p');

    $self->render(
        text => ( $self->authenticate( $u, $p ) ) ? 'ok' : 'failed' );
};

get '/authonly' => sub {
    my $self = shift;
    $self->render( text => ( $self->user_exists )
        ? 'authenticated'
        : 'not authenticated' );
};

get '/condition/authonly' => ( authenticated => 1 ) => sub {
    my $self = shift;
    $self->render( text => 'authenticated condition' );
};

get '/authonly/lazy' => sub {
    my $self = shift;
    $self->render( text => ( $self->signature_exists )
        ? 'sign authenticated'
        : 'sign not authenticated' );
};

get '/condition/authonly/lazy' => ( signed => 1 ) => sub {
    my $self = shift;
    $self->render( text => 'signed authenticated condition' );
};

get '/logout' => sub {
    my $self = shift;

    $self->logout();
    $self->render( text => 'logout' );
};

my $t = Test::Mojo->new;

$t->get_ok('/')->status_is(200)->content_is('index page');
$t->get_ok('/authonly/lazy')->status_is(200)
  ->content_is('sign not authenticated');
$t->get_ok('/condition/authonly/lazy')->status_is(404);

# let's try this
$t->post_form_ok( '/login', { u => 'fnark', p => 'fnork' } )->status_is(200)
  ->content_is('failed');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');

$t->post_form_ok( '/login', { u => 'foo', p => 'bar' } )->status_is(200)
  ->content_is('ok');

# try original auth in lazy mode
$t->get_ok('/authonly')->status_is(200)->content_is('authenticated');
$t->get_ok('/condition/authonly')->status_is(200)
  ->content_is('authenticated condition');

# try lazy auth - is user just signed
$t->get_ok('/authonly/lazy')->status_is(200)->content_is('sign authenticated');
$t->get_ok('/condition/authonly/lazy')->status_is(200)
  ->content_is('signed authenticated condition');

$t->get_ok('/logout')->status_is(200)->content_is('logout');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');
$t->get_ok('/authonly/lazy')->status_is(200)
  ->content_is('sign not authenticated');
