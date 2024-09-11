# Net-LDAP-KeyCache

A simple key cache server aimed at caching LDAP searches.

## Install

For Debian...

```bash
apt-get install libnet-ldap-perl libpoe-perl libtoml-perl libjson-perl libnet-server-perl libfile-slurp-perl libmojolicious-perl libyaml-libyaml-perl 
perl Makefile.PL
make
make test
make install
```

For FreeBSD...

```bash
pkg install p5-Net-LDAP p5-POE p5-TOML p5-JSON p5-Net-Server p5-File-Slurp  p5-Mojolicious p5-YAML-LibYAML
perl Makefile.PL
make
make test
make install
```

The following systemd service files for SystemD are available for it.

```
init/mojo_nlkcc.service
init/nlkcd.service
```

## Other Docs

- Configuration :: perldoc nlkcd
- CLI usage :: perldoc nlkcc
- HTTP(S) API usage :: perldoc mojo_nlkcc 
