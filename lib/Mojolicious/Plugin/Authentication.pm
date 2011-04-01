package Mojolicious::Plugin::Authentication;
use warnings;
use strict;
use version;
use Mojo::Base 'Mojolicious::Plugin';

our $VERSION = qv(0.03);

sub register {
    my ($self, $app, $args) = @_;

    $args ||= {};

    die __PACKAGE__, ": missing 'load_user' subroutine ref in parameters\n" unless($args->{load_user});
    die __PACKAGE__, ": missing 'validate_user' subroutine ref in parameters\n" unless($args->{validate_user});

    my $session_stash_key = $args->{session_stash_key} || 'mojox-session';
    my $our_stash_key     = $args->{stash_key} || '__authentication__'; 

    $args->{session} ||= {};

    $app->plugin(session => $args->{session});
    $app->plugins->add_hook(before_dispatch => sub {
        my $self = shift;
        my $session = $self->stash->{$session_stash_key};
        if($session->load) {
            if($session->is_expired) {
                $session->flush;
                $session->create;
            } else {
                my $uid = $session->data('__uid__'); 
                my $user;
                if($uid && ($user = $args->{load_user}->($self, $uid))) {
                    $self->stash->{$our_stash_key}->{user} = $user;
                    $session->extend_expires;
                    $session->flush;
                }
            }
        } else {
            $session->create;
            $session->flush;
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
        $self->stash->{$session_stash_key}->clear('__uid__');
        $self->stash->{$session_stash_key}->flush;
    });
    # this replaces the mojolicious built-in session helper
    $app->helper(session => sub { return shift->stash->{$session_stash_key}->data });
    $app->helper(authenticate => sub {
        my $self = shift;
        my $user = shift;
        my $pass = shift;

        if(my $uid = $self->stash->{$our_stash_key}->{validate_user}->($self, $user, $pass)) {
            $self->stash->{$session_stash_key}->data('__uid__' => $uid);
            $self->stash->{$our_stash_key}->{user} = $args->{load_user}->($uid);
            $self->stash->{$session_stash_key}->extend_expires;
            $self->stash->{$session_stash_key}->flush;
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

Version 0.03

=head1 SYNOPSIS

    use Mojolicious::Plugin::Authentication
    use Mojolicious::Plugin::Session;

    $self->plugin('authentication' => {
        session => {
            'stash_key' => 'mojox-session',
        },
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

=head2 session
    
    Returns a hashref containing all session data. Changes made here are automatically committed when the request ends.

=head1 CONFIGURATION

You must supply 2 subroutines, namely 'load_user' and 'validate_user'. load_user is called when the plugin needs to load a user from the user store. It's done this way to give you maximum flexibility whilst making life a little easier in the long run. load_user is expected to return a valid user object/hash/array/thingamajig. validate_user is called from the authenticate module and is passed a username and password, and is expected to return either a user id or undef, depending on whether the user is logged in or not. 

=head1 EXAMPLE

    use Mojolicious::Lite;

    plugin 'session' => { stash_key => 'session', store => 'dbi', expires_delta => 5 };
    plugin 'authentication' => { 
        session_stash_key => 'session', 
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
                if(crypt($password, $salt) eq $res->{password}) {
                    return $res->{user_id};
                } else {
                    return undef;
                }
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


=head1 AUTHOR

Ben van Staveren, C<< <madcat at cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-mojolicious-plugin-authentication at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Mojolicious-Plugin-Authentication>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.



=head1 CONTRIBUTING

If you want to contribute changes or otherwise involve yourself in development, feel free to fork the Mercurial repository from
L<http://bitbucket.org/xirinet/mojolicious-plugin-authentication/>.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Mojolicious::Plugin::Authentication


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Mojolicious-Plugin-Authentication>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Mojolicious-Plugin-Authentication>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Mojolicious-Plugin-Authentication>

=item * Search CPAN

L<http://search.cpan.org/dist/Mojolicious-Plugin-Authentication/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2011 Ben van Staveren.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut
