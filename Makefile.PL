use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Mojolicious::Plugin::Authentication',
    AUTHOR              => q{Ben van Staveren <madcat@cpan.org>},
    VERSION_FROM        => 'lib/Mojolicious/Plugin/Authentication.pm',
    ABSTRACT_FROM       => 'lib/Mojolicious/Plugin/Authentication.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'MojoX::Session' => 0,
        'Mojolicious::Plugin::Session' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Mojolicious-Plugin-Authentication-*' },
);
