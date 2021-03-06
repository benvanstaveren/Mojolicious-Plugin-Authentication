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
    validate_user => \&validate_user_t,,
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

post '/login2' => sub {
    my $self = shift;
    my $u    = $self->req->param('u');
    my $p    = $self->req->param('p');

    $self->render(text => ($self->authenticate($u, $p, { 'ohnoes' => 'itsameme' })) ? 'ok' : 'failed');
};

get '/authonly' => sub {
    my $self = shift;
    $self->render(text => ($self->is_user_authenticated) ? 'authenticated' : 'not authenticated');
};

get '/condition/authonly' => (authenticated => 1) => sub {
    my $self = shift;
    $self->render(text => 'authenticated condition');
};

get '/logout' => sub {
    my $self = shift;

    $self->logout();
    $self->render(text => 'logout');
};

my $t = Test::Mojo->new;

$t->get_ok('/')->status_is(200)->content_is('index page');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');
$t->get_ok('/condition/authonly')->status_is(404);

# let's try this
$t->post_ok('/login' => form =>  { u => 'fnark', p => 'fnork' })->status_is(200)->content_is('failed');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');

$t->post_ok('/login' => form => { u => 'foo', p => 'bar' })->status_is(200)->content_is('ok');
$t->get_ok('/authonly')->status_is(200)->content_is('authenticated');
$t->get_ok('/condition/authonly')->status_is(200)->content_is('authenticated condition');

$t->get_ok('/logout')->status_is(200)->content_is('logout');
$t->get_ok('/authonly')->status_is(200)->content_is('not authenticated');

$t->post_ok('/login2' => form => { u => 'foo', p => 'bar' })->status_is(200)->content_is('ok');
$t->get_ok('/authonly')->status_is(200)->content_is('authenticated');
$t->get_ok('/condition/authonly')->status_is(200)->content_is('authenticated condition');

plugin 'Authentication', {
    autoload_user => 1,
    fail_render => { status => 401, json => { message => 'Unauthorized' } },
    load_user => \&load_user_t,
    validate_user => \&validate_user_t,
};

get '/condition/authonly' => (authenticated => 1) => sub {
    my $self = shift;
    $self->render(text => 'authenticated condition');
};

$t = Test::Mojo->new;

$t->get_ok('/condition/authonly')
    ->status_is(401)
    ->json_is('/message' => 'Unauthorized');

plugin 'Authentication', {
    autoload_user => 1,
    fail_render => { status => 401, json => { message => 'Unauthorized' } },
    load_user_p => \&load_user_t_p,
    validate_user_p => \&validate_user_t_p,
};
get '/condition/authonly_p' => (authenticated => 1) => sub {
    my $self = shift;
    $self->render(text => 'authenticated condition');
};
$t->get_ok('/condition/authonly_p')
    ->status_is(401)
    ->json_is('/message' => 'Unauthorized');

done_testing;
