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

package Local::App::Blocking {
    use Mojolicious::Lite;

    plugin Authentication => {
        autoload_user => 0,
        load_user     => \&TestUtils::load_user_t,
        validate_user => \&TestUtils::validate_user_t,
    };

    get '/' => sub {
        shift->render( text => 'index page' );
    };

    post '/login' => sub {
        my $self = shift;
        my $u    = $self->req->param('u');
        my $p    = $self->req->param('p');

        $self->render(
            text => ( $self->authenticate( $u, $p ) ) ? 'ok' : 'failed'
        );
    };

    get '/authonly' => sub {
        my $self = shift;
        $self->render( text => ( $self->is_user_authenticated )
            ? 'authenticated'
            : 'not authenticated' );
    };

    get '/condition/authonly' => ( authenticated => 1 ) => sub {
        shift->render( text => 'authenticated condition' );
    };

    get '/authonly/lazy' => sub {
        my $self = shift;
        $self->render( text => ( $self->signature_exists )
            ? 'sign authenticated'
            : 'sign not authenticated' );
    };

    get '/condition/authonly/lazy' => ( signed => 1 ) => sub {
        shift->render( text => 'signed authenticated condition' );
    };

    get '/logout' => sub {
        my $self = shift;
        $self->logout;
        $self->render( text => 'logout' );
    };

    get '/auto_validate' => sub {
        my $self = shift;

        eval {
            $self->authenticate( undef, undef, { auto_validate => 'userid' } );
            1;
        } or return $self->reply->exception('failed');

        $self->render( text => 'ok' );
    };
}

subtest 'Blocking  tests' => sub {
    my $t = Test::Mojo->new('Local::App::Blocking');

    subtest 'Unauthenticated' => sub {
        $t->get_ok('/')
            ->status_is(200)
            ->content_is('index page');

        $t->get_ok('/authonly/lazy')
            ->status_is(200)
            ->content_is('sign not authenticated');

        $t->get_ok('/condition/authonly/lazy')
            ->status_is(404);
    };

    subtest 'Login failed' => sub {
        $t->post_ok( '/login' => form => { u => 'fnark', p => 'fnork' } )
            ->status_is(200)
            ->content_is('failed');

        $t->get_ok('/authonly')
            ->status_is(200)
            ->content_is('not authenticated');
    };

    subtest 'Logged in' => sub {
        $t->post_ok( '/login' => form => { u => 'foo', p => 'bar' } )
            ->status_is(200)
            ->content_is('ok');

        $t->get_ok('/authonly')
            ->status_is(200)
            ->content_is('authenticated');

        $t->get_ok('/condition/authonly')
            ->status_is(200)
            ->content_is('authenticated condition');

        subtest 'Lazy authentication' => sub {
            $t->get_ok('/authonly/lazy')
                ->status_is(200)
                ->content_is('sign authenticated');

            $t->get_ok('/condition/authonly/lazy')
                ->status_is(200)
                ->content_is('signed authenticated condition');
        };

        # Make sure we're logged out
        $t->get_ok('/logout')
            ->status_is(200)
            ->content_is('logout');

        $t->get_ok('/authonly')
            ->status_is(200)
            ->content_is('not authenticated');

        $t->get_ok('/authonly/lazy')
            ->status_is(200)
            ->content_is('sign not authenticated');
    };

    subtest 'Auto-validate' => sub {
        $t->get_ok('/auto_validate')
            ->status_is(200);
    };
};

package Local::App::Async {
    use Mojolicious::Lite;

    plugin Authentication => {
        autoload_user => 0,
        load_user_p => \&TestUtils::load_user_t_p,
        validate_user_p => \&TestUtils::validate_user_t_p,
    };

    post '/login' => sub {
        my $self = shift;
        my $u    = $self->req->param('u');
        my $p    = $self->req->param('p');

        $self->authenticate_p( $u, $p )->then( sub {
            $self->render( text => $_[0] ? 'ok' : 'failed' );
        });
    };

    get '/authonly' => sub {
        my $self = shift;
        $self->is_user_authenticated_p->then( sub {
            $self->render( text => $_[0] ? 'authenticated' : 'not authenticated' );
        });
    };
}

subtest 'Non blocking tests' => sub {
    my $t = Test::Mojo->new('Local::App::Async');

    $t->post_ok( '/login' => form => { u => 'fnark', p => 'fnork' } )
        ->status_is(200)
        ->content_is('failed');

    $t->get_ok('/authonly')
        ->status_is(200)
        ->content_is('not authenticated');

    $t->post_ok( '/login' => form => { u => 'foo', p => 'bar' } )
        ->status_is(200)
        ->content_is('ok');
};

done_testing;
