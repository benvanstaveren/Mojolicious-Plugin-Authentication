use warnings;
use strict;

package Mojolicious::Plugin::Authentication;

our $VERSION = '1.37';

use Mojo::Base 'Mojolicious::Plugin';
use Mojo::Promise;

sub register {
    my ($self, $app, $args) = @_;

    $args = { %{ $args || {} } }; # copy as mutating

    for my $cb_name (qw(load_user validate_user)) {
        my $p_name = $cb_name."_p";
        die __PACKAGE__, ": missing '$cb_name' subroutine ref in parameters\n"
            unless grep ref eq 'CODE', @$args{$cb_name, $p_name};
        $args->{$p_name} = sub {
            my @r = eval { $args->{$cb_name}->(@_) };
            $@ ? Mojo::Promise->reject($@) : Mojo::Promise->resolve(@r);
        } if !$args->{$p_name};
    }

    if (defined $args->{lazy}) {
        warn __PACKAGE__,
            ": the 'lazy' option is deprecated, ",
            "use 'autoload_user' instead\n";

        $args->{autoload_user} = delete $args->{lazy};
    }

    my $autoload_user     = $args->{autoload_user}   // 0;
    my $session_key       = $args->{session_key}     || 'auth_data';
    my $our_stash_key     = $args->{stash_key}       || '__authentication__';
    my $current_user_fn   = $args->{current_user_fn} || 'current_user';
    my $load_user_cb      = $args->{load_user};
    my $validate_user_cb  = $args->{validate_user};
    my $load_user_cb_p    = $args->{load_user_p};
    my $validate_user_cb_p= $args->{validate_user_p};

    my $fail_render = ref $args->{fail_render} eq 'CODE'
       ? $args->{fail_render} : sub { $args->{fail_render} };

    my $user_loader_sub = user_loader_closure(
        $our_stash_key, $session_key, $load_user_cb,
    );
    my $user_loader_sub_p = user_loader_closure_p(
        $our_stash_key, $session_key, $load_user_cb_p,
    );

    my $current_user = user_stash_extractor_closure(
        $our_stash_key, $user_loader_sub,
    );
    my $current_user_p = user_stash_extractor_closure_p(
        $our_stash_key, $user_loader_sub_p,
    );

    $app->helper(authenticate => authenticate_closure(
        $our_stash_key, $session_key, $validate_user_cb, $current_user,
    ));
    $app->helper(authenticate_p => authenticate_closure_p(
        $our_stash_key, $session_key, $validate_user_cb_p, $current_user_p,
    ));

    $app->hook(before_dispatch => $user_loader_sub_p) if $autoload_user;

    $app->routes->add_condition(authenticated => sub {
        my ($r, $c, $captures, $required) = @_;
        my $res = (!$required or $c->is_user_authenticated);

        unless ($res) {
          my $fail = $fail_render->(@_);
          $c->render(%{$fail}) if $fail;
        }
        return $res;
    });

    $app->routes->add_condition(signed => sub {
        my ($r, $c, $captures, $required) = @_;
        return (!$required or $c->signature_exists);
    });

    # deprecation handling
    $app->helper(user_exists => sub {
        warn __PACKAGE__,
            ": the 'user_exists' helper is deprecated, ",
            "use 'is_user_authenticated' instead\n";
        return shift->is_user_authenticated(@_);
    });

    $app->helper(user => sub {
        warn __PACKAGE__,
            ": the 'user' helper is deprecated, ",
            "use '$current_user_fn' instead\n";
        return shift->$current_user_fn(@_);
    });

    $app->helper(reload_user => sub {
        my $c = shift;
        # Clear stash to force a reload of the user object
        delete $c->stash->{$our_stash_key};
        return $current_user->($c);
    });
    $app->helper(reload_user_p => sub {
        my $c = shift;
        # Clear stash to force a reload of the user object
        delete $c->stash->{$our_stash_key};
        return $current_user_p->($c);
    });

    $app->helper(signature_exists => sub {
        my $c = shift;
        return !!$c->session($session_key);
    });

    $app->helper(is_user_authenticated => sub {
        my $c = shift;
        return defined $current_user->($c);
    });
    $app->helper(is_user_authenticated_p => sub {
        my $c = shift;
        $current_user_p->($c)->then(sub {
            return defined $_[0];
        });
    });

    $app->helper($current_user_fn => $current_user);
    $app->helper($current_user_fn."_p" => $current_user_p);

    $app->helper(logout => sub {
        my $c = shift;
        delete $c->stash->{$our_stash_key};
        delete $c->session->{$session_key};
        return 1;
    });
}

# Unconditionally load the user based on uid in session
sub user_loader_closure {
    my ($our_stash_key, $session_key, $load_user_cb) = @_;
    sub {
        my $c = shift;
        my $uid = $c->session($session_key);
        return if !defined $uid;
        my $user = $load_user_cb->($c, $uid);
        if ($user) {
            $c->stash($our_stash_key => { user => $user });
        }
        else {
            # cache result that user does not exist
            $c->stash($our_stash_key => { no_user => 1 });
        }
    };
}
sub user_loader_closure_p {
    my ($our_stash_key, $session_key, $load_user_cb_p) = @_;
    sub {
        my $c = shift;
        my $uid = $c->session($session_key);
        return Mojo::Promise->resolve if !defined $uid;
        $load_user_cb_p->($c, $uid)->then(sub {
            my $user = $_[0];
            if ($user) {
                $c->stash($our_stash_key => { user => $user });
            }
            else {
                # cache result that user does not exist
                $c->stash($our_stash_key => { no_user => 1 });
            }
        });
    };
}

# Fetch the current user object from the stash - loading it if
# not already loaded
sub user_stash_extractor_closure {
    my ($our_stash_key, $user_loader_sub) = @_;
    sub {
        my ($c, $user) = @_;
        # Allow setting the current_user
        if ( defined $user ) {
            $c->stash($our_stash_key => { user => $user });
            return;
        }
        my $stash = $c->stash($our_stash_key);
        $user_loader_sub->($c)
            unless $stash->{no_user} or defined $stash->{user};
        $stash = $c->stash($our_stash_key);
        return $stash->{user};
    };
}
sub user_stash_extractor_closure_p {
    my ($our_stash_key, $user_loader_sub_p) = @_;
    sub {
        my ($c, $user) = @_;
        # Allow setting the current_user
        if ( defined $user ) {
            return Mojo::Promise->resolve->then(sub {
                $c->stash($our_stash_key => { user => $user });
            });
        }
        my $stash = $c->stash($our_stash_key);
        my $promise = ($stash->{no_user} or defined $stash->{user})
            ? Mojo::Promise->resolve
            : $user_loader_sub_p->($c);
        $promise->then(sub {
            $stash = $c->stash($our_stash_key);
            return $stash->{user};
        });
    };
}

sub authenticate_closure {
    my ($our_stash_key, $session_key, $validate_user_cb, $current_user) = @_;
    sub {
        my ($c, $user, $pass, $extradata) = @_;
        # if extradata contains "auto_validate", assume the passed username
        # is in fact valid, and auto_validate contains the uid; used for
        # OAuth and other stuff that does not work with usernames and
        # passwords; use this with extreme care if you must
        $extradata ||= {};
        my $uid = $extradata->{auto_validate} //
            $validate_user_cb->($c, $user, $pass, $extradata);
        return undef if !defined $uid;
        $c->session($session_key => $uid);
        # Clear stash to force reload of any already loaded user object
        delete $c->stash->{$our_stash_key};
        return 1 if defined $current_user->($c);
        return undef;
    };
}
sub authenticate_closure_p {
    my ($our_stash_key, $session_key, $validate_user_cb_p, $current_user_p) = @_;
    sub {
        my ($c, $user, $pass, $extradata) = @_;
        $extradata ||= {};
        my $promise = defined($extradata->{auto_validate})
            ? Mojo::Promise->resolve($extradata->{auto_validate})
            : $validate_user_cb_p->($c, $user, $pass, $extradata);
        $promise->then(sub {
            my ($uid) = @_;
            return undef if !defined $uid;
            $c->session($session_key => $uid);
            # Clear stash to force reload of any already loaded user object
            delete $c->stash->{$our_stash_key};
            $current_user_p->($c);
        })->then(sub {
            defined $_[0] ? 1 : undef;
        });
    };
}

1;

__END__

=encoding UTF-8

=head1 NAME

Mojolicious::Plugin::Authentication - A plugin to make authentication a bit easier

=head1 SYNOPSIS

    use Mojolicious::Plugin::Authentication;

    $self->plugin('Authentication' => {
        autoload_user   => 1,
        session_key     => 'wickedapp',
        load_user_p     => sub { ... },
        validate_user_p => sub { ... },
    });
    # ...
    $self->authenticate_p(
        'username', 'password',
        { optional => 'extra data stuff' },
    )->then(sub {
        my ($authenticated) = @_;
        if ($authenticated) {
            # ...
        }
    });

    # or, synchronous style
    $self->plugin('Authentication' => {
        autoload_user   => 1,
        session_key     => 'wickedapp',
        load_user       => sub { ... },
        validate_user   => sub { ... },
        current_user_fn => 'user', # compatibility with old code
    });
    my $authenticated = $self->authenticate(
        'username', 'password',
        { optional => 'extra data stuff' },
    );
    if ($authenticated) {
        ...
    }

=head1 METHODS

Like other Mojolicious plugins, loading this plugin will import some function
helpers into the namespace of your application. This will not normally cause
any trouble, but be aware that if you define methods with the same names as
those below, you'll likely run into unexpected results.

=head2 authenticate($username, $password, $extra_data_hashref)

Authenticate will use the supplied C<load_user> and C<validate_user>
subroutine refs to see whether a user exists with the given username and
password, and will set up the session accordingly. Returns true when the user
has been successfully authenticated, false otherwise. You can pass additional
data along in the C<extra_data> hashref, it will be passed to your
C<validate_user> subroutine as-is. If the extra data hash contains a key
C<auto_validate>, the value of that key will be used as the UID, and
authenticate will not call your C<validate_user> callback; this can be used
when working with OAuth tokens or other authentication mechanisms that do not
use a local username and password form.

=head2 authenticate_p($username, $password, $extra_data_hashref)

As above, but instead of returning a value, returns a promise of
same. Available even if only synchronous callbacks are provided as these
will be "promisified".

=head2 is_user_authenticated

Returns true if current_user() returns some valid object, false otherwise.

=head2 is_user_authenticated_p

As above, but instead of returning a value, returns a promise of same.

=head2 current_user

Returns the user object as it was returned from the supplied C<load_user>
subroutine ref.

You can change the current user by passing it in, but be careful: This
bypasses the authentication. This is useful if you have multiple ways to
authenticate users and want to re-use authorization checks that use
C<current_user>.

Note that the name of this helper can be changed with
the C<current_user_fn> field during initialisation (see
L<below|/CONFIGURATION>).

=head2 current_user_p

As above, but instead of returning a value, returns a promise of
same.

=head2 reload_user

Flushes the current user object and then returns current_user().

=head2 reload_user_p

As above, but instead of returning a value, returns a promise of
same.

=head2 signature_exists

Returns true if uid signature exist on the client side (in cookies), false
otherwise.

Warning: non-secure check! Use this method only for a "fast & dirty" lookup
to see if the client has the proper cookies. May be helpful in some cases
(for example - in counting C<guest>/C<logged users> or for additional
non-confidential information for C<logged users> but not for C<guest>).

=head2 logout

Removes the session data for authentication, and effectively logs a user out.
Returns a true value, to allow for chaining.

=head1 CONFIGURATION

The following options can be set for the plugin, (but the "REQUIRED"
ones can be replaced with a promise-returning equivalent with C<_p>
appended to the key):

=over 4

=item load_user (REQUIRED)

A coderef for user loading (see L</"USER LOADING">)

=item validate_user (REQUIRED)

A coderef for user validation (see L</"USER VALIDATION">)

=item session_key (optional)

The name of the session key

=item autoload_user (optional)

Turn on/off automatic loading of user data - user data can be loaded only if
it be used. May reduce site latency in some cases.

=item current_user_fn (optional)

Set the name for the C<current_user()> helper function. C<_p> will be
appended for the asynchronous version.

=item fail_render (optional)

Specify what is to be rendered when the authenticated condition is not met.

Set to a coderef which will be called with the following signature:

    sub {
        my ($routes, $controller, $captures, $required) = @_;
        ...
        return $hashref;
    }

The return value of the subroutine will be ignored if it evaluates to false.
If it returns a hash reference, it will be dereferenced and passed as-is
to the controller's C<render> function. If you return anything else, you are
going to have a bad time.

If set directly to a hash reference, that will be passed to C<render> instead.

=back

In order to set the session expiry time, use the following in your startup
routine:

    $app->plugin('authentication', { ... });
    $app->sessions->default_expiration(86400); # set expiry to 1 day
    $app->sessions->default_expiration(3600); # set expiry to 1 hour

=head1 USER LOADING

The coderef you pass to the load_user configuration key has the following
signature:

    sub {
        my ($app, $uid) = @_;
        ...
        return $user;
    }

The uid is the value that was originally returned from the C<validate_user>
coderef. You must return either a user object (it can be a hashref, arrayref,
or a blessed object) or undef.

=head1 USER VALIDATION

User validation is what happens when we need to authenticate someone. The
coderef you pass to the C<validate_user> configuration key has the following
signature:

    sub {
        my ($c, $username, $password, $extradata) = @_;
        ...
        return $uid;
    }

You must return either a user id or undef. The user id can be numerical or a
string. Do not return hashrefs, arrayrefs or objects, since the behaviour of
this plugin could get a little bit on the odd side of weird if you do that.

=head1 EXAMPLES

For a code example using this, see the F<t/01-functional.t> and
F<t/02-functional_lazy.t> tests, it uses L<Mojolicious::Lite> and this plugin.

=head1 ROUTING VIA CONDITION

This plugin also exports a routing condition you can use in order to limit
access to certain documents to only authenticated users.

    $r->route('/foo')->over(authenticated => 1)->to('mycontroller#foo');

    my $authenticated_only = $r->route('/members')
        ->over(authenticated => 1)
        ->to('members#index');

    $authenticated_only->route('online')->to('members#online');

If someone is not authenticated, these routes will not be considered by the
dispatcher and unless you have set up a catch-all route, a 404 Not Found will
be generated instead.

And another condition for fast and unsecured checking for users, having a
signature (without validating it). This method just checks client cookies for
uid data existing.

    $r->route('/foo')->over(signed => 1)->to('mycontroller#foo');

This behavior is similar to the "authenticated" condition.

=head1 ROUTING VIA CALLBACK

If you want to be able to send people to a login page, you will have to use
the following:

    my $members_only = $r->route('/members')->to(cb => sub {
        my $self = shift;

        $self->redirect_to('/login') and return 0
            unless($self->is_user_authenticated);

        return 1;
    });

    $members_only->route('online')->to('members#online');

Lazy and unsecured methods:

    my $members_only = $r->route('/unimportant')->to(cb => sub {
        my $self = shift;

        $self->redirect_to('/login') and return 0
            unless($self->signature_exists);

        return 1;
    });

    $members_only->route('pages')->to('unimportant#pages');

=head1 ROUTING VIA BRIDGE

If you want to be able to send people to a login page, you will have to use
the following:

    my $auth_bridge = $r->under('/members')->to('auth#check');
    # only visible to logged in users
    $auth_bridge->route('/list')->to('members#list');

And in your Auth controller you would put:

    sub check {
        my $self = shift;

        $self->redirect_to('/login') and return 0
            unless($self->is_user_authenticated);

        return 1;
    };

Lazy and unsecured methods:

    sub check {
        my $self = shift;

        $self->redirect_to('/login') and return 0
            unless($self->signature_exists);

        return 1;
    };

=head1 SEE ALSO

=over 4

=item L<Mojolicious::Sessions>

=item L<Mojocast 3: Authentication|http://mojocasts.com/e3#>

=back

=head1 AUTHOR

=over 4

=item Ben van Staveren, C<< <madcat at cpan.org> >>

=item José Joaquín Atria, C<< <jjatria@cpan.org> >>

=back

=head1 BUGS / CONTRIBUTING

Please report any bugs or feature requests through the web interface at
L<https://github.com/benvanstaveren/mojolicious-plugin-authentication/issues>.

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

Andrew Parker
    -   For pointing out some bugs that crept in; a silent reminder not to
        code while sleepy

Mirko Westermeier (memowe)
    -   For doing some (much needed) code cleanup

Terrence Brannon (metaperl)
    -   Documentation patches

Karpich Dmitry (meettya)
    -   C<lazy_mode> and C<signature_exists> functionality, including a test
        and documentation

Ivo Welch
    -   For donating his first ever Mojolicious application that shows an
        example of how to use this module

Ed Wildgoose (ewildgoose)
    -   Adding the C<current_user()> functionality, as well as some method
        renaming to make things a bit more sane.

Colin Cyr (SailingYYC)
    -   For reporting an issue with routing conditions; I really should not
        code while sleepy, brainfarts imminent!

Carlos Ramos (carragom)
    -   For fixing the bug that'd consider an uid of 0 or "0" to be a problem

Doug Bell (preaction)
    -   For improving the Travis CI integration and enabling arguments for
        current_user

Roman F (moltar)
    -   For fixing some pesky typos in sample code

Hernan Lopes (hernan604)
    -   For updating some deprecated method names in the documentation

=head1 LICENSE AND COPYRIGHT

Copyright 2011-2021 Ben van Staveren.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut
