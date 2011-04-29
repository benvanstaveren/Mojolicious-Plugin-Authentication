package Mojolicious::Plugin::Authentication;
use Mojo::Base 'Mojolicious::Plugin';

sub register {
    my ($self, $app, $args) = @_;

    $args ||= {};

    die __PACKAGE__, ": missing 'load_user' subroutine ref in parameters\n"
        unless $args->{load_user} && ref($args->{load_user}) eq 'CODE';
    die __PACKAGE__, ": missing 'validate_user' subroutine ref in parameters\n"         unless $args->{validate_user} && ref($args->{validate_user}) eq 'CODE';

    my $session_key     = $args->{session_key}  || 'auth_data';
    my $our_stash_key   = $args->{stash_key}    || '__authentication__'; 
    my $load_user_f     = $args->{load_user};
    my $validate_user_f = $args->{validate_user};

    $app->routes->add_condition(authenticated => sub {
        my ($r, $c, $captures, $required) = @_;
        return ($required && $c->user_exists) ? 1 : 0;
    });

    $app->plugins->add_hook(before_dispatch => sub {
        my ($self, $c) = @_;
        if (my $uid = $c->session($session_key)) {
            my $user = $load_user_f->($c, $uid);
            $c->stash($our_stash_key => { user => $user }) if $user;
        }
    });

    $app->helper(user_exists => sub {
        my $c = shift;
        return (
            defined($c->stash($our_stash_key)) && 
            defined($c->stash($our_stash_key)->{user})
            ) ? 1 : 0;

    });

    $app->helper(user => sub {
        my $c = shift;
        return ($c->stash($our_stash_key))
            ? $c->stash($our_stash_key)->{user}
            : undef;
    });

    $app->helper(logout => sub {
        my $c = shift;
        delete $c->stash->{$our_stash_key};
        delete $c->session->{$session_key};

    });

    $app->helper(authenticate => sub {
        my ($c, $user, $pass) = @_;
        if (my $uid = $validate_user_f->($c, $user, $pass)) {
            $c->session($session_key => $uid);
            $c->session->{$session_key} = $uid;
            $c->stash->{$our_stash_key}->{user} = $load_user_f->($c, $uid);
            return 1;
        }
        return;
    });
}

1;
__END__
=head1 NAME

Mojolicious::Plugin::Authentication - A plugin to make authentication a bit easier

=head1 SYNOPSIS

    use Mojolicious::Plugin::Authentication

    $self->plugin('authentication' => {
        'session_key' => 'wickedapp',
        'load_user' => sub { ... },
        'validate_user' => sub { ... },
    });

    if ($self->authenticate('username', 'password')) {
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
        my ($app, $uid) = @_;
        ...
        return $user;
    }

The uid is the value that was originally returned from the validate_user coderef. You must return
either a user object (it can be a hashref, arrayref, or a blessed object) or undef. 

=head1 USER VALIDATION

User validation is what happens when we need to authenticate someone. The coderef you pass to the validate_user configuration key has the following signatre:

    sub {
        my ($app, $username, $password) = @_;
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

=head1 BUGS / CONTRIBUTING

Please report any bugs or feature requests through the web interface at L<https://github.com/benvanstaveren/mojolicious-plugin-authentication/issues>.

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
