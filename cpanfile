requires 'Mojolicious' => '8.0';
requires 'Exporter'    => 0;

on develop => sub {
    recommends 'Test::CheckManifest' => '1.31';
    requires   'Test::CPAN::Changes' => '0.400002';
    requires   'Test::Pod'           => '1.41';
};

on test => sub {
    requires 'Test::More' => '0.96';
};
