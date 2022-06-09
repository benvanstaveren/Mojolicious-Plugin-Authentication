#!/usr/bin/env perl
use strict;
use warnings;

# Disable IPv6, epoll and kqueue
BEGIN { $ENV{MOJO_NO_IPV6} = $ENV{MOJO_POLL} = 1 }

use Test::More;

use Test::Mojo;
use Mojo::File 'path';

use lib path(qw( t lib ))->to_string;
use TestUtils;

package Local::App::Base {
    use Mojolicious::Lite -signatures;

    plugin Authentication => {
        autoload_user => 1,
        load_user     => \&TestUtils::load_user_t,
        validate_user => \&TestUtils::validate_user_t,
    };

    get '/' => sub ( $self ) {
        $self->render(text => 'index page');
    };

    post '/login' => sub ( $self ) {
        my $u = $self->req->param('u');
        my $p = $self->req->param('p');

        $self->render(
            text => $self->authenticate( $u, $p ) ? 'ok' : 'failed'
        );
    };

    post '/login2' => sub ( $self ) {
        my $u = $self->req->param('u');
        my $p = $self->req->param('p');

        my $ok = $self->authenticate( $u, $p, { 'ohnoes' => 'itsameme' } );
        $self->render( text => $ok ? 'ok' : 'failed');
    };

    get '/authonly' => sub ( $self ) {
        $self->render(
            text => $self->is_user_authenticated
                ? 'authenticated'
                : 'not authenticated'
        );
    };

    get '/condition/authonly' => ( authenticated => 1 ) => sub ( $self ) {
        $self->render( text => 'authenticated condition' );
    };

    get '/logout' => sub ( $self ) {
        $self->logout;
        $self->render( text => 'logout' );
    };
}

subtest 'Basic tests' => sub {
    my $t = Test::Mojo->new('Local::App::Base');

    subtest 'Not logged in' => sub {
        $t->get_ok('/')
            ->status_is(200)
            ->content_is('index page');

        $t->get_ok('/authonly')
            ->status_is(200)
            ->content_is('not authenticated');

        $t->get_ok('/condition/authonly')
            ->status_is(404);
    };

    subtest 'Failed login' => sub {
        $t->post_ok('/login' => form =>  { u => 'fnark', p => 'fnork' } )
            ->status_is(200)
            ->content_is('failed');

        $t->get_ok('/authonly')
            ->status_is(200)
            ->content_is('not authenticated');
    };

    subtest 'Logged in' => sub {
        $t->post_ok('/login' => form => { u => 'foo', p => 'bar' } )
            ->status_is(200)
            ->content_is('ok');

        $t->get_ok('/authonly')
            ->status_is(200)
            ->content_is('authenticated');

        $t->get_ok('/condition/authonly')
            ->status_is(200)
            ->content_is('authenticated condition');

        $t->get_ok('/logout')
            ->status_is(200)
            ->content_is('logout');

        # Make sure we're no longer authenticated
        $t->get_ok('/authonly')
            ->status_is(200)
            ->content_is('not authenticated');
    };

    subtest 'Logged in with extra data' => sub {
        $t->post_ok('/login2' => form => { u => 'foo', p => 'bar' } )
            ->status_is(200)
            ->content_is('ok');

        $t->get_ok('/authonly')
            ->status_is(200)
            ->content_is('authenticated');

        $t->get_ok('/condition/authonly')
            ->status_is(200)
            ->content_is('authenticated condition');
    };
};

package Local::App::Unauthorized {
    use Mojolicious::Lite -signatures;

    plugin Authentication => {
        autoload_user => 1,
        fail_render   => { status => 401, json => { message => 'Unauthorized' } },
        load_user     => \&TestUtils::load_user_t,
        validate_user => \&TestUtils::validate_user_t,
    };

    get '/condition/authonly' => ( authenticated => 1 ) => sub ( $self ) {
        $self->render( text => 'authenticated condition' );
    };
}

subtest 'Tests with fail_render' => sub {
    my $t = Test::Mojo->new('Local::App::Unauthorized');

    $t->get_ok('/condition/authonly')
        ->status_is(401)
        ->json_is('/message' => 'Unauthorized');
};

package Local::App::Promise {
    use Mojolicious::Lite -signatures;

    plugin Authentication => {
        autoload_user   => 1,
        load_user_p     => \&TestUtils::load_user_t_p,
        validate_user_p => \&TestUtils::validate_user_t_p,
    };

    get '/condition/authonly' => ( authenticated => 1 ) => sub ( $self ) {
        $self->render( text => 'authenticated condition' );
    };
}

subtest 'Tests with async handlers' => sub {
    my $t = Test::Mojo->new('Local::App::Promise');

    $t->get_ok('/condition/authonly')
        ->status_is(404);
};

done_testing;
