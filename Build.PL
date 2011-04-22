use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Mojolicious::Plugin::Authentication',
    license             => 'perl',
    dist_author         => q{Ben van Staveren <madcat@cpan.org>},
    dist_version_from   => 'lib/Mojolicious/Plugin/Authentication.pm',
    dist_abstract       => 'Mojolicious plugin to make authentication of users a bit eaier',
    configure_requires  => {
        'Module::Build' => '0.38',
    },
    build_requires => {
        'Test::More'    =>  0,
        'Test::Mojo'    =>  0,
    },
    requires => {
        'Mojolicious'   =>  0,
    },
    add_to_cleanup      => [ 'Mojolicious-Plugin-Authentication-*' ],
);

$builder->create_build_script();
