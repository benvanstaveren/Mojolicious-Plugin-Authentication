package Mojolicious::Plugin::Authentication;
use warnings;
use strict;
use Mojo::Base 'Mojolicious::Plugin';

our $VERSION = '1.10';

sub register {
    my ($self, $app, $args) = @_;

    $args ||= {};

    die __PACKAGE__, ": missing 'load_user' subroutine ref in parameters\n" unless($args->{load_user});
    die __PACKAGE__, ": missing 'validate_user' subroutine ref in parameters\n" unless($args->{validate_user});

    my $session_key     = $args->{session_key} || 'session_' . ref($app);
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
        if(my $uid = $c->session->{$session_key}) {
            my $user;
            $c->stash->{$our_stash_key}->{user} = $user if($uid && ($user = $load_user_f->($self, $uid)));
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
            $self->session->{$session_key} = $uid;
            $self->stash->{$our_stash_key}->{user} = $load_user_f->($self, $uid);
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

Version 1.10

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

    load_user       (REQUIRED)  A coderef for user loading (see USER LOADING)
    validate_user   (REQUIRED)  A coderef for user validation (see USER VALIDATION)
    session_key     (optional)  The name of the session key

In order to set the session expiry time, use the following in your startup routine:

    $app->plugin('authentication', { ... });
    $app->sessions->default_expiration(86400); # set expiry to 1 day
    $app->sessions->default_expiration(3600); # set expiry to 1 hour


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

=head1 EXAMPLES

For a code example using this, see the t/01-functional.t test, it uses Mojolicious::Lite and this plugin.

=head1 ROUTING VIA CONDITION

This plugin also exports a routing condition you can use in order to limit access to certain documents to only authenticated users.

    $r->route('/foo')->over(authenticated => 1)->to('mycontroller#foo');

    my $authenticated_only = $r->route('/members')->over(authenticated => 1)->to('members#index');
    $authenticated_only->route('online')->to('members#online');

If someone is not authenticated, these routes will not be considered by the dispatcher and unless you have set up a catch-all route, a 404 Not Found will be generated instead. 

=head1 ROUTING VIA BRIDGE

If you want to be able to send people to a login page, you will have to use the following:

    my $members_only = $r->route('/members')->to(cb => sub {
        my $self = shift;

        $self->redirect_to('/login') and return 0 unless($self->user_exists);
        return 1;
    });

    $members_only->route('online')->to('members#online');

=head1 SEE ALSO

L<Mojolicious::Sessions>

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
