#!/usr/bin/env perl
use strict;
use warnings;

# Disable IPv6, epoll and kqueue
BEGIN { $ENV{MOJO_NO_IPV6} = $ENV{MOJO_POLL} = 1 }

use Test::More;
plan tests => 23;

# testing code starts here
use Mojolicious::Lite;
use Test::Mojo;


plugin 'authentication', {
    load_user => sub {
        my $self = shift;
        my $uid  = shift;

        return {
            'username' => 'foo',
            'password' => 'bar',
            'name'     => 'Foo'
            } if($uid eq 'userid');
        return undef;
    },
    validate_user => sub {
        my $self = shift;
        my $username = shift;
        my $password = shift;

        return 'userid' if($username eq 'foo' && $password eq 'bar');
        return undef;
    },
};

get '/' => sub {
    my $self = shift;
    $self->render(text => 'index page');
};

post '/login' => sub {
    my $self = shift;
    my $u    = $self->req->param('u');
    my $p    = $self->req->param('p');

    $self->render(text => ($self->authenticate($u, $p)) ? 'ok' : 'failed');
};

get '/authonly' => sub {
    my $self = shift;
    $self->render(text => ($self->user_exists) ? 'authenticated' : 'not authenticated');
};

get '/condition/authonly' => (authenticated => 1) => sub {
    my $self = shift;
    $self->render(text => 'authenticated condition');
};

my $t = Test::Mojo->new;

$t->get_ok('/')->status_is(200)->content_is('index page');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');
$t->get_ok('/condition/authonly')->status_is(404);

# let's try this
$t->post_form_ok('/login', { u => 'fnark', p => 'fnork' })->status_is(200)->content_is('failed');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');

$t->post_form_ok('/login', { u => 'foo', p => 'bar' })->status_is(200)->content_is('ok');
$t->get_ok('/authonly')->status_is(200)->content_is('authenticated');
$t->get_ok('/condition/authonly')->status_is(200)->content_is('authenticated condition');

