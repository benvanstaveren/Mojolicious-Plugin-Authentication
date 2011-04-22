package Mojolicious::Plugin::Authentication;
use warnings;
use strict;
use Mojo::Base 'Mojolicious::Plugin';

our $VERSION = '0.5.0';

sub register {
    my ($self, $app, $args) = @_;

    $args ||= {};

    die __PACKAGE__, ": missing 'load_user' subroutine ref in parameters\n" unless($args->{load_user});
    die __PACKAGE__, ": missing 'validate_user' subroutine ref in parameters\n" unless($args->{validate_user});

    my $session_key     = $args->{session_key} || ref($app);
    my $expire_delta    = $args->{expire_delta} || 86400;
    my $our_stash_key   = $args->{stash_key} || '__authentication__'; 
    my $load_user_f     = $args->{load_user};
    my $validate_user_f = $args->{validate_user};


    $app->routes->add_condition(authenticated => sub {
        my ($r, $c, $captures, $required) = (@_);
        return ($required && $c->user_exists) ? 1 : 0;
    });

    $app->plugins->add_hook(before_dispatch => sub {
        my $self    = shift;
        my $c       = shift;
        my $session = $c->app->sessions->{$session_key};

        $session->{expires} ||= 0;

        if($session->{expires} < time()) {
            # it's expired
            delete($c->app->sessions->{$session_key});
            $c->app->sessions->{$session_key} = { expires => time() + $expire_delta };
        } else {
            if(my $uid = $session->{__uid__}) {
                my $user;
                if($uid && ($user = $load_user_f->($self, $uid))) {
                    $c->stash->{$our_stash_key}->{user} = $user;
                    $c->app->sessions->{$session_key}->{expires} += $expire_delta;
                }
            }
        }
    });
    $app->helper(user_exists => sub {
        my $self = shift;
        return (defined($self->stash->{$our_stash_key}->{user})) ? 1 : 0;
    });
    $app->helper(user => sub {
        my $self = shift;
        return $self->stash->{$our_stash_key}->{user} || undef;
    });
    $app->helper(logout => sub {
        my $self = shift;
        delete($self->stash->{$our_stash_key}->{user});
        delete($self->stash->{$session_key}->{__uid__});
    });
    $app->helper(authenticate => sub {
        my $self = shift;
        my $user = shift;
        my $pass = shift;

        if(my $uid = $validate_user_f->($self, $user, $pass)) {
            $self->app->sessions->{$session_key}->{'__uid__'} = $uid;
            $self->stash->{$our_stash_key}->{user} = $load_user_f->($self, $uid);
            $self->app->sessions->{$session_key}->{expires} += $expire_delta;
            return 1;
        } else {
            return 0;
        }
    });
}

1;
__END__
=head1 NAME

Mojolicious::Plugin::Authentication - A plugin to make authentication a bit easier

=head1 VERSION

Version 0.5.0

=head1 SYNOPSIS

    use Mojolicious::Plugin::Authentication

    $self->plugin('authentication' => {
        'session_key' => 'wickedapp',
        'load_user' => sub { ... },
        'validate_user' => sub { ... },
    });

    if($self->authenticate('username', 'password')) {
        ... 
    }


=head1 METHODS

=head2 authenticate($username, $password)

    Authenticate will use the supplied load_user and validate_user subroutine refs to see whether a user exists with the given username and password, and will set up the session accordingly.
    Returns true when the user has been successfully authenticated, false otherwise.

=head2 user_exists

    Returns true if an authenticated user exists, false otherwise.

=head2 user

    Returns the user object as it was returned from the supplied 'load_user' subroutine ref.

=head2 logout

    Removes the session data for authentication, and effectively logs a user out.

=head1 CONFIGURATION

The following options can be set for the plugin:

    session_key     (optional)  The name of the session key in $app->sessions
    load_user       (REQUIRED)  A coderef for user loading (see USER LOADING)
    validate_user   (REQUIRED)  A coderef for user validation (see USER VALIDATION)

=head1 USER LOADING

The coderef you pass to the load_user configuration key has the following signature:

    sub { 
        my $app = shift; 
        my $uid = shift
        ...
        return $user;
    }

The uid is the value that was originally returned from the validate_user coderef. You must return
either a user object (it can be a hashref, arrayref, or a blessed object) or undef. 

=head1 USER VALIDATION

User validation is what happens when we need to authenticate someone. The coderef you pass to the validate_user configuration key has the following signatre:

    sub {
        my $app = shift;
        my $username = shift;
        my $password = shift;
        ...
        return $uid;
    }

You must return either a user id or undef. The user id can be numerical or a string. Do not return hashrefs, arrayrefs or objects, since the behaviour of this plugin could get a little bit on the odd side of weird.


=head1 EXAMPLE

    use Mojolicious::Lite;

    plugin 'authentication' => { 
        session_key => 'lite-example', 
        stash_key => 'auth', 
        load_user => sub {
            my $self = shift;
            my $uid = shift;
            # assume we have a db helper that also uses DBI
            my $sth = $self->db->prepare('SELECT * FROM user WHERE user_id = ?');
            $sth->execute($uid);
            if(my $res = $sth->fetchrow_hashref) {
                return $res;
            } else {
                return undef;
            }
        },
        validate_user => sub {
            my $self = shift;
            my $username = shift;
            my $password = shift;

            # assume we have a db helper that also uses DBI
            my $sth = $self->db->prepare('SELECT * FROM user WHERE username = ?');
            if(my $res = $sth->fetchrow_hashref) {
                my $salt = substr($res->{password}, 0, 2);
                return (crypt($password, $salt) eq $res->{password})
                    ? $res->{user_id}
                    : undef;
            } else {
                return undef;
            }
        },
    };

    get '/foo' => sub {
        my $self = shift;

        if(!$self->user_exists) {
            $self->render(template => 'loginform');
        } else {
            $self->render(template => 'loggedin');
        }
    };
    get '/login' => sub {
        my $self = shift;
        my $u    = $self->req->param('username');
        my $p    = $self->req->param('password');

        if($self->authenticate($u, $p)) {
            $self->redirect_to('/foo');
        } else {
            $self->render(text => 'Invalid credentials');
        }
    };

=head1 ROUTING VIA CONDITION

This plugin also exports a routing condition you can use in order to limit access to certain documents to only authenticated users.

    $r->route('/foo')->over(authenticated => 1)->to('mycontroller#foo');
    my $authenticated_only = $r->route('/members')->over(authenticated => 1)->to('members#index');
    $authenticated_only->route('online')->to('members#online');

This does not let you easily redirect users to a login page, however.

=head1 ROUTING VIA BRIDGE

If you want to be able to send people to a login page, you will have to use the following:

    my $members_only = $r->route('/members')->to(cb => sub {
        my $self = shift;

        $self->redirect_to('/login') and return 0 unless($self->user_exists);
        return 1;
    });

    $members_only->route('online')->to('members#online');

=head1 AUTHOR

Ben van Staveren, C<< <madcat at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests through the web interface at L<https://bitbucket.org/xirinet/mojolicious-plugin-authentication/issues>.


=head1 CONTRIBUTING

If you want to contribute changes or otherwise involve yourself in development, feel free to fork the Mercurial repository from
L<http://bitbucket.org/xirinet/mojolicious-plugin-authentication/> and make pull requests for any patches you have.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Mojolicious::Plugin::Authentication


You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Mojolicious-Plugin-Authentication>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Mojolicious-Plugin-Authentication>

=item * Search CPAN

L<http://search.cpan.org/dist/Mojolicious-Plugin-Authentication/>

=back


=head1 ACKNOWLEDGEMENTS

Andrew Parker   -   For pointing out some bugs that crept in; a silent reminder not to code while sleepy

=head1 LICENSE AND COPYRIGHT

Copyright 2011 Ben van Staveren.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut
