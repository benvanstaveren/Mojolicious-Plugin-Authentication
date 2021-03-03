# NAME

Mojolicious::Plugin::Authentication - A plugin to make authentication a bit easier

# SYNOPSIS

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

# METHODS

Like other Mojolicious plugins, loading this plugin will import some function
helpers into the namespace of your application. This will not normally cause
any trouble, but be aware that if you define methods with the same names as
those below, you'll likely run into unexpected results.

## authenticate($username, $password, $extra\_data\_hashref)

Authenticate will use the supplied `load_user` and `validate_user`
subroutine refs to see whether a user exists with the given username and
password, and will set up the session accordingly. Returns true when the user
has been successfully authenticated, false otherwise. You can pass additional
data along in the `extra_data` hashref, it will be passed to your
`validate_user` subroutine as-is. If the extra data hash contains a key
`auto_validate`, the value of that key will be used as the UID, and
authenticate will not call your `validate_user` callback; this can be used
when working with OAuth tokens or other authentication mechanisms that do not
use a local username and password form.

## authenticate\_p($username, $password, $extra\_data\_hashref)

As above, but instead of returning a value, returns a promise of
same. Available even if only synchronous callbacks are provided as these
will be "promisified".

## is\_user\_authenticated

Returns true if current\_user() returns some valid object, false otherwise.

## is\_user\_authenticated\_p

As above, but instead of returning a value, returns a promise of same.

## current\_user

Returns the user object as it was returned from the supplied `load_user`
subroutine ref.

You can change the current user by passing it in, but be careful: This
bypasses the authentication. This is useful if you have multiple ways to
authenticate users and want to re-use authorization checks that use
`current_user`.

Note that the name of this helper can be changed with
the `current_user_fn` field during initialisation (see
[below](#configuration)).

## current\_user\_p

As above, but instead of returning a value, returns a promise of
same.

## reload\_user

Flushes the current user object and then returns current\_user().

## reload\_user\_p

As above, but instead of returning a value, returns a promise of
same.

## signature\_exists

Returns true if uid signature exist on the client side (in cookies), false
otherwise.

Warning: non-secure check! Use this method only for a "fast & dirty" lookup
to see if the client has the proper cookies. May be helpful in some cases
(for example - in counting `guest`/`logged users` or for additional
non-confidential information for `logged users` but not for `guest`).

## logout

Removes the session data for authentication, and effectively logs a user out.
Returns a true value, to allow for chaining.

# CONFIGURATION

The following options can be set for the plugin, (but the "REQUIRED"
ones can be replaced with a promise-returning equivalent with `_p`
appended to the key):

- load\_user (REQUIRED)

    A coderef for user loading (see ["USER LOADING"](#user-loading))

- validate\_user (REQUIRED)

    A coderef for user validation (see ["USER VALIDATION"](#user-validation))

- session\_key (optional)

    The name of the session key

- autoload\_user (optional)

    Turn on/off automatic loading of user data - user data can be loaded only if
    it be used. May reduce site latency in some cases.

- current\_user\_fn (optional)

    Set the name for the `current_user()` helper function. `_p` will be
    appended for the asynchronous version.

- fail\_render (optional)

    Specify what is to be rendered when the authenticated condition is not met.

    Set to a coderef which will be called with the following signature:

        sub {
            my ($routes, $controller, $captures, $required) = @_;
            ...
            return $hashref;
        }

    The return value of the subroutine will be ignored if it evaluates to false.
    If it returns a hash reference, it will be dereferenced and passed as-is
    to the controller's `render` function. If you return anything else, you are
    going to have a bad time.

    If set directly to a hash reference, that will be passed to `render` instead.

In order to set the session expiry time, use the following in your startup
routine:

    $app->plugin('authentication', { ... });
    $app->sessions->default_expiration(86400); # set expiry to 1 day
    $app->sessions->default_expiration(3600); # set expiry to 1 hour

# USER LOADING

The coderef you pass to the load\_user configuration key has the following
signature:

    sub {
        my ($app, $uid) = @_;
        ...
        return $user;
    }

The uid is the value that was originally returned from the `validate_user`
coderef. You must return either a user object (it can be a hashref, arrayref,
or a blessed object) or undef.

# USER VALIDATION

User validation is what happens when we need to authenticate someone. The
coderef you pass to the `validate_user` configuration key has the following
signature:

    sub {
        my ($c, $username, $password, $extradata) = @_;
        ...
        return $uid;
    }

You must return either a user id or undef. The user id can be numerical or a
string. Do not return hashrefs, arrayrefs or objects, since the behaviour of
this plugin could get a little bit on the odd side of weird if you do that.

# EXAMPLES

For a code example using this, see the `t/01-functional.t` and
`t/02-functional_lazy.t` tests, it uses [Mojolicious::Lite](https://metacpan.org/pod/Mojolicious::Lite) and this plugin.

# ROUTING VIA CONDITION

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

# ROUTING VIA CALLBACK

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

# ROUTING VIA BRIDGE

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

# SEE ALSO

- [Mojolicious::Sessions](https://metacpan.org/pod/Mojolicious::Sessions)
- [Mojocast 3: Authentication](http://mojocasts.com/e3#)

# AUTHOR

- Ben van Staveren, `<madcat at cpan.org>`
- José Joaquín Atria, `<jjatria@cpan.org>`

# BUGS / CONTRIBUTING

Please report any bugs or feature requests through the web interface at
[https://github.com/benvanstaveren/mojolicious-plugin-authentication/issues](https://github.com/benvanstaveren/mojolicious-plugin-authentication/issues).

# SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Mojolicious::Plugin::Authentication

You can also look for information at:

- AnnoCPAN: Annotated CPAN documentation

    [http://annocpan.org/dist/Mojolicious-Plugin-Authentication](http://annocpan.org/dist/Mojolicious-Plugin-Authentication)

- CPAN Ratings

    [http://cpanratings.perl.org/d/Mojolicious-Plugin-Authentication](http://cpanratings.perl.org/d/Mojolicious-Plugin-Authentication)

- Search CPAN

    [http://search.cpan.org/dist/Mojolicious-Plugin-Authentication/](http://search.cpan.org/dist/Mojolicious-Plugin-Authentication/)

# ACKNOWLEDGEMENTS

Andrew Parker
    -   For pointing out some bugs that crept in; a silent reminder not to
        code while sleepy

Mirko Westermeier (memowe)
    -   For doing some (much needed) code cleanup

Terrence Brannon (metaperl)
    -   Documentation patches

Karpich Dmitry (meettya)
    -   `lazy_mode` and `signature_exists` functionality, including a test
        and documentation

Ivo Welch
    -   For donating his first ever Mojolicious application that shows an
        example of how to use this module

Ed Wildgoose (ewildgoose)
    -   Adding the `current_user()` functionality, as well as some method
        renaming to make things a bit more sane.

Colin Cyr (SailingYYC)
    -   For reporting an issue with routing conditions; I really should not
        code while sleepy, brainfarts imminent!

Carlos Ramos (carragom)
    -   For fixing the bug that'd consider an uid of 0 or "0" to be a problem

Doug Bell (preaction)
    -   For improving the Travis CI integration and enabling arguments for
        current\_user

Roman F (moltar)
    -   For fixing some pesky typos in sample code

Hernan Lopes (hernan604)
    -   For updating some deprecated method names in the documentation

# LICENSE AND COPYRIGHT

Copyright 2011-2021 Ben van Staveren.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.
