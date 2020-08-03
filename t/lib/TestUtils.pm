use strict;
use warnings;
use Exporter 'import';
use Mojo::Promise;

our @EXPORT_OK = qw(
    load_user_t validate_user_t
    load_user_t_p validate_user_t_p
);

sub load_user_t {
    my $self = shift;
    my $uid  = shift;
    return {
        'username' => 'foo',
        'password' => 'bar',
        'name'     => 'Foo'
      }
      if ( $uid eq 'userid' ) || $uid eq 'useridwithextradata';
    return undef;
}

sub validate_user_t {
    my $self = shift;
    my $username = shift || '';
    my $password = shift || '';
    my $extradata = shift || {};

    return 'useridwithextradata' if($username eq 'foo' && $password eq 'bar' && ( $extradata->{'ohnoes'} || '' ) eq 'itsameme');
    return 'userid' if($username eq 'foo' && $password eq 'bar');
    return undef;
}

sub load_user_t_p { Mojo::Promise->resolve(load_user_t(@_)) }

sub validate_user_t_p { Mojo::Promise->resolve(validate_user_t(@_)) }
