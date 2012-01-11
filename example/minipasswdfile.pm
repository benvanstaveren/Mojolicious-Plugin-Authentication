package minipasswdfile;
use strict;
use warnings;
use warnings FATAL => qw{ uninitialized };
use autodie;

use 5.10.0;

################################################################
=pod

=head1 Title

  minipasswdfile.pm --- mini data base for a plain-text password file.

=head1 Invocation

  $ perl minipasswdfile.pm

shows off how this module works.  The .pm invokation will also create
a suitable sample file in /tmp/tmpusers.txt.

=head1 Versions

  0.0: Tue Jan 10 14:22:52 2012

=cut

################################################################
# file format: username:password:privilegelevel:full name
################################################################
sub new {
  my ($class_name, $passwdfile)= @_;

  (-e $passwdfile) or die "You must create a user-readable and user-writable password file first.\n";

  ## load persistent user information from an existing passwd file
  my %users;
  open(my $FIN, "<", $passwdfile);
  while (<$FIN>) {
    (/^\#/) and next; ## skip comments
    (/\w/) or next;  ## skip empty lines
    (!/([\w :\\])/) and die "Your password file has a non-word character ($1), other than : and \\ on line $.: $_\n";

    my @values= split(/:/);
    ($#values>=3) or die "invalid entry on line $. '$_'\n";
    $users{$values[0]}= { 'uid'=>$values[0], 'password' => $values[1], 'privileges' => $values[2], 'username' => $values[3] };
  }
  close($FIN);
  return bless({ passwdfile => $passwdfile, %users }, $class_name);
}

################################################################
sub userexists {
  my $self=shift;
  ($_[0]) or return undef;
  return ((exists($self->{$_[0]}))?($_[0]):undef);
}

################################################################
sub userinfo {
  my $self=shift;
  ($_[0]) or return undef;
  return $self->{$_[0]};
}

################################################################
sub checkuserpw {
  my $self=shift;
  ($_[0]) or return undef;
  ($_[1]) or return undef;
  my $pwinfile= $self->{$_[0]}->{'password'};
  say "\t[minipw---Trying to authenticate $_[0] ($pwinfile) with $_[1]\n]";
  return undef unless exists($self->{$_[0]});
  return undef unless ($pwinfile eq $_[1]);
  return $_[0];
}

################################################################
sub adduser {
  my $self=shift;

  foreach (@_) { (/^[\w ]+$/) or return "we allow only word characters, not '$_'"; }
  ($_[0] =~ /passwdfile/) and return "passwdfile is a reserved word";

  $self->{$_[0]}= { 'uid'=>$_[0], 'password' => $_[1], 'privileges' => $_[2], 'username' => $_[3] };
  return$self->rewritefile();
}


################################################################
sub rmuser {
  my $self=shift;

  ($_[0] =~ /^[\w ]+$/) or return "we allow only word characters, not '$_'";
  ($_[0] =~ /passwdfile/) and return "passwdfile is a reserved word";

  delete $self->{$_[0]};
  return$self->rewritefile();
}

################################################################
sub rewritefile {
  my $self=shift;
  open(my $FOUT, ">", $self->{passwdfile});
  say $FOUT "## format: username:password:privilegelevel:full name";
  say $FOUT "## last updated on ".scalar(localtime).", ".time();
  foreach my $uid (keys %{$self}) {
    ($uid =~ /passwdfile/) and next;  # a pseudo-key
    foreach my $field (qw/uid password privileges username/) {
      print $FOUT $self->{$uid}->{$field}.":";
    }
    print $FOUT "\n";
  }
  close($FOUT);
  return "ok";
}


################################################################
sub numusers {
  my $self=shift;
  return scalar keys %{$self};
}

################################################################

if ($0 eq "minipasswdfile.pm") {
  say "$0 invoked directly (TEST Mode)";

  sub mkminipasswdfile {
    my $filename="minipasswdfile.txt";
    open(my $FOUT, ">", $filename);
    say $FOUT "## format: username:password:privilegelevel:full name";
    close($FOUT);
    return $filename;
  }
  my $fname=mkminipasswdfile();


  sub _displaysecretfile {
    my $self=shift;
    use Data::Dumper;
    print Dumper($self);
    ## sample access: ($self->{'albert'}->{'password'});
  };

  ## true testing code
  package main;
  my $pw= minipasswdfile->new($fname);
  say "Before Insertion";
  $pw->_displaysecretfile();
  ($pw->adduser('sigmund', 'psycho', 'instructor', 'Sigmund Freud') eq 'ok') or die 'Cannot add sigmund\n';
  ($pw->adduser('albert','relativity','instructor','Albert Einstein') eq 'ok') or die 'cannot add albert\n';
  ($pw->adduser('richard','qed','instructor','Richard Feynman') eq 'ok') or die 'cannot add richard\n';
  ($pw->adduser('dummy','knownothing','student','Not So Anonymous Student') eq 'ok') or die 'cannot add dummy\n';
  ($pw->adduser('sigmund','psycho','instructor','Sigmund Freud') eq 'ok') or die 'cannot add sigmund\n';
  say "After Insertion";
  $pw->_displaysecretfile();
  foreach (qw/albert angstrom/) {
    print "Does '$_' exist? ".($pw->userexists($_) || "no")."\n";
    print "Does '$_' have password 'relativity'? ".($pw->checkuserpw($_, 'relativity') || "no")."\n";
  }
}

1;

