package Net::LDAP::KeyCache;

use 5.006;
use strict;
use warnings;
use JSON;
use POE;
use POE::Wheel::SocketFactory;
use POE::Wheel::Run;
use POE::Wheel::ReadWrite;
use Socket;
use File::Temp qw/ tempfile tempdir /;
use Net::LDAP::LDIF;
use Sys::Syslog;
use Clone;
use Time::HiRes qw( usleep ualarm gettimeofday tv_interval nanosleep
	clock_gettime clock_getres clock_nanosleep clock
	stat lstat utime);
use Net::LDAP::Util qw(canonical_dn);

=head1 NAME

Net::LDAP::KeyCache - LDAP caching daemon with a JSON socket interface.

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

    use Net::LDAP::KeyCache;

    my $nlkcd = Net::LDAP::KeyCache->new();
    $nlkcd->start_server;

=head1 METHODS

=head2 new

Innitializes it.

    - pid :: Location of the PID file.
        Default :: /var/run/nlkcd/pid

    - socket :: Socket locations.
        Default :: /var/run/nlkcd/socket

    - base_search :: The base to use for the search.
        Default :: (|(objectClass=person)(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=account)(objectClass=posixGroup))

    - connect :: An array to of options to pass to ldapsearch. Should include the relevant
                 bind, base DN, and host options.
        Default :: undef

    - connect_admin :: Connect options to use for ad_disable and ad_lockout.
        Default :: undef

    - cache_time :: Timeout for cached items in seconds.
        Default :: 120

    - enable_ad_disable :: Enable AD lockout via ORing useraccountcontrol attributes via 0x0002
            Requires connect_admin to be set.
        Default :: 0

    - enable_ad_lockout :: Enable AD lockout via ORing useraccountcontrol attributes via 0x0010
            Requires connect_admin to be set.
        Default :: 0

Example of starting passing a config hash to new.

    my $nlkcd;
    eval{ $nlkcd = Net::LDAP::KeyCache->new( %config ); };
    if ($@) {
        die('Error calling Net::LDAP::KeyCache->new( %config ) ... '.$@);
    }

=cut

sub new {
	my ( $blank, %opts ) = @_;

	#
	if ( !defined( $opts{connect} ) ) {
		die('$opts{connect} is undef');
	} elsif ( ref( $opts{connect} ) ne 'ARRAY' ) {
		die( '$opts{connect} is a ' . ref( $opts{connect} . ' and not a ARRAY' ) );
	}

	my $self = {
		pid         => '/var/run/nlkcd/pid',
		socket      => '/var/run/nlkcd/socket',
		base_search => '(|(objectClass=person)'
			. '(objectClass=posixAccount)'
			. '(objectClass=inetOrgPerson)'
			. '(objectClass=account)'
			. '(objectClass=posixGroup))',
		connect               => $opts{connect},
		connect_admin         => undef,
		cache_by_dn           => {},
		time_cached_by_dn     => {},
		cache_by_search       => {},
		time_cached_by_search => {},
		start_time            => [gettimeofday],
		enable_ad_lockout     => 0,
		enable_ad_disable     => 0,
		stats                 => {
			hits        => 0,
			misses      => 0,
			connected   => 0,
			disconnects => 0,
			commands    => {
				fetch         => 0,
				search        => 0,
				list_searches => 0,
				stats         => 0,
				unknown       => 0,
				ad_lockout    => 0,
				ad_disable    => 0,
			},
			command_time => {
				fetch         => 0,
				search        => 0,
				list_searches => 0,
				stats         => 0,
				unknown       => 0,
				ad_lockout    => 0,
				ad_disable    => 0,
			},
			error_time         => 0,
			decode_fail        => 0,
			already_processing => 0,
			processing         => 0,
		},
		cache_time => 300,
		daemonized => undef,
	};
	bless $self;

	my @to_merge
		= ( 'pid', 'socket', 'base_search', 'cache_time', 'enable_ad_lockout', 'enable_ad_disable', 'connect_admin' );
	foreach my $item (@to_merge) {
		if ( defined( $opts{$item} ) ) {
			$self->{$item} = $opts{$item};
		}
	}

	if ( $self->{enable_ad_disable} || $self->{enable_ad_lockout} ) {
		if ( !defined( $self->{connect_admin} ) ) {
			die('"connect_admin is undef"');
		}
		if ( ref( $self->{connect_admin} ) ne 'ARRAY' ) {
			die( '"connect_admin" is ref type ' . reF( $self->{connect_admin} ) . ' and not ARRAY' );
		}
	}

	return $self;
} ## end sub new

=head2 start_server

Starts up server, calling $poe_kernel->run.

This should not be expected to return.

    $nlkcd->start_server;

=cut

sub start_server {
	my ($self) = @_;

	POE::Session->create(
		inline_states => {
			_start     => \&server_started,
			got_client => \&server_accepted,
			got_error  => \&server_error,
		},
		heap => { socket => $self->{socket}, self => $self },
	);

	$poe_kernel->run();
} ## end sub start_server

sub server_started {
	my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
	unlink $heap->{socket} if -e $heap->{socket};
	$heap->{server} = POE::Wheel::SocketFactory->new(
		SocketDomain => PF_UNIX,
		BindAddress  => $heap->{socket},
		SuccessEvent => 'got_client',
		FailureEvent => 'got_error',
	);
} ## end sub server_started

sub server_error {
	my ( $heap, $syscall, $errno, $error ) = @_[ HEAP, ARG0 .. ARG2 ];
	$error = "Normal disconnection." unless $errno;
	warn "Server socket encountered $syscall error $errno: $error\n";
	delete $heap->{server};
}

sub server_accepted {
	my ( $heap, $client_socket ) = @_[ HEAP, ARG0 ];
	session_spawn( $client_socket, $heap->{self} );
}

##
##
## for when we get a connection
##
##

# spawns the session
sub session_spawn {
	my $socket = shift;
	my $self   = shift;
	POE::Session->create(
		inline_states => {
			_start           => \&server_session_start,
			got_client_input => \&server_session_input,
			got_client_error => \&server_session_error,
		},
		args => [$socket],
		heap => { self => $self, processing => 0 },
	);
} ## end sub session_spawn

# starts the session and setup handlers referenced in session_spawn
sub server_session_start {
	my ( $heap, $socket ) = @_[ HEAP, ARG0 ];
	$heap->{client} = POE::Wheel::ReadWrite->new(
		Handle     => $socket,
		InputEvent => 'got_client_input',
		ErrorEvent => 'got_client_error',
	);
	$heap->{client}->put( '{"connected_to": "Net::LDAP::KeyCache v. ' . $Net::LDAP::KeyCache::VERSION . '"}' );
	$heap->{self}{stats}{connected}++;
} ## end sub server_session_start

# handle line inputs
sub server_session_input {
	my ( $heap, $input ) = @_[ HEAP, ARG0 ];

	if ( $input eq 'exit' ) {
		delete $heap->{client};
		return;
	}

	my $t0 = [gettimeofday];

	if ( $heap->{processing} ) {
		$heap->{self}{stats}{already_processing}++;
		my $error = { status => 'error', error => 'already processing a request' };
		$heap->{client}->put( encode_json($error) );
		$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
		return;
	}

	my $json;
	eval { $json = decode_json($input); };
	if ($@) {
		$heap->{self}{stats}{decode_fail}++;
		my $error = { status => 'error', error => $@ };
		$heap->{client}->put( encode_json($error) );
		$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
		return;
	} elsif ( !defined($json) ) {
		$heap->{self}{stats}{decode_fail}++;
		my $error = { status => 'error', error => 'parsing JSON returned undef' };
		$heap->{client}->put( encode_json($error) );
		$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
		return;
	}

	if ( !defined( $json->{command} ) ) {
		my $error = { status => 'error', error => '$json->{command} is undef' };
		$heap->{client}->put( encode_json($error) );
		$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
		return;
	}

	# set the default value for nc if needed
	if ( defined( $json->{nc} ) && ref( $json->{nc} ) != '' ) {
		$json->{nc} = 0;
	} elsif ( $json->{nc} ne '0' && $json->{nc} ne '1' ) {
		$json->{nc} = 0;
	}

	# set drop to a empty array if not set or if not a array
	if ( defined( $json->{drop} ) && ref( $json->{drop} ) != 'ARRAY' ) {
		$json->{drop} = [];
	} else {
		$json->{drop} = [];
	}

	# bad idea, don't use this in production
	my $make_it_pretty = 0;
	if ( !defined( $json->{make_it_pretty} ) ) {
		$json->{make_it_pretty} = 0;
	}

	if ( $json->{command} eq 'fetch' ) {
		$heap->{self}{stats}{commands}{fetch}++;

		if ( !defined( $json->{var} ) ) {
			my $error = { status => 'error', error => '$json->{var} is undef' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{command_time}{fetch}
				= $heap->{self}{stats}{command_time}{fetch} + tv_interval( $t0, [gettimeofday] );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		} elsif ( !defined( $json->{val} ) ) {
			my $error = { status => 'error', error => '$json->{val} is undef' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{command_time}{fetch}
				= $heap->{self}{stats}{command_time}{fetch} + tv_interval( $t0, [gettimeofday] );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		}

		$json->{val} =~ s/\\/\\\\/g;
		$json->{val} =~ s/\,/\\\,/g;
		$json->{val} =~ s/\(/\\\(/g;
		$json->{val} =~ s/\)/\\\)/g;
		$json->{val} =~ s/\+/\\\+/g;
		$json->{val} =~ s/\</\\\</g;
		$json->{val} =~ s/\>/\\\>/g;
		$json->{val} =~ s/\;/\\\;/g;
		$json->{val} =~ s/\"/\\\"/g;
		$json->{val} =~ s/^\ /\\ /g;
		$json->{val} =~ s/\ $/\\ /g;

		# use the cached search if possible
		my $search = '(' . $json->{var} . '=' . $json->{val} . ')';
		if ( $json->{nc} eq '0' ) {
			if (   defined( $heap->{self}{cache_by_search}{$search} )
				&& defined( $heap->{self}{time_cached_by_search}{$search} ) )
			{
				my $time_diff = time - $heap->{self}{time_cached_by_search}{$search};
				if ( $time_diff <= $heap->{self}{cache_time} ) {
					$heap->{self}{stats}{hits}++;
					my $results = {
						status              => 'ok',
						results             => $heap->{self}{cache_by_search}{$search},
						from_cache          => 1,
						cached_at           => $heap->{self}{time_cached_by_search}{$search},
						cached_to_now_delta => $time_diff
					};

					# check the results for things to drop
					my $return_results = $results;
					if ( $json->{drop}[0] ) {
						my $return_results = clone($results);
						my @drop_check     = keys( %{ $return_results->{results} } );
						foreach my $dn_to_check (@drop_check) {
							foreach my $to_drop ( @{ $json->{drop} } ) {
								if ( ref($to_drop) eq '' ) {
									if ( defined( $return_results->{results}{$dn_to_check}{$to_drop} ) ) {
										delete( $return_results->{results}{$dn_to_check}{$to_drop} );
									}
								}
							}
						}
					} ## end if ( $json->{drop}[0] )

					$heap->{client}->put( encode_json($return_results) );
					$heap->{self}{stats}{command_time}{fetch}
						= $heap->{self}{stats}{command_time}{fetch} + tv_interval( $t0, [gettimeofday] );
					return;
				} ## end if ( $time_diff <= $heap->{self}{cache_time...})
				$heap->{self}{stats}{misses}++;
			} else {
				$heap->{self}{stats}{misses}++;
			}
		} else {
			$heap->{self}{stats}{no_cache}++;
		}

		$heap->{processing} = 1;
		$heap->{self}{stats}{processing}++;

		POE::Session->create(
			inline_states => {
				_start           => \&fetch_start,
				got_child_stdout => \&fetch_child_stdout,
				got_child_stderr => \&fetch_child_stderr,
				got_child_close  => \&fetch_child_close,
				got_child_signal => \&fetch_child_signal,
			},
			heap => {
				self           => $heap->{self},
				client         => $heap->{client},
				session_heap   => $heap,
				stdout         => '',
				stderr         => '',
				make_it_pretty => $json->{make_it_pretty},
				search         => $search,
				drop           => $json->{drop},
				type           => 'fetch',
				t0             => $t0,
			},
		);
	} elsif ( $json->{command} eq 'search' ) {
		$heap->{self}{stats}{commands}{search}++;
		if ( !defined( $json->{search} ) ) {
			my $error = { status => 'error', error => '$json->{search} is undef' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{command_time}{search}
				= $heap->{self}{stats}{command_time}{search} + tv_interval( $t0, [gettimeofday] );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		}

		my $search = $json->{search};
		if ( $search !~ /^\(/ ) {
			$search = '(' . $search;
		}
		if ( $search !~ /\)$/ ) {
			$search = $search . ')';
		}

		# use the cached search if possible
		if ( $json->{nc} eq '0' ) {
			if (   defined( $heap->{self}{cache_by_search}{$search} )
				&& defined( $heap->{self}{time_cached_by_search}{$search} ) )
			{
				my $time_diff = time - $heap->{self}{time_cached_by_search}{$search};
				if ( $time_diff <= $heap->{self}{cache_time} ) {
					$heap->{self}{stats}{hits}++;
					my $results = {
						status              => 'ok',
						results             => $heap->{self}{cache_by_search}{$search},
						from_cache          => 1,
						cached_at           => $heap->{self}{time_cached_by_search}{$search},
						cached_to_now_delta => $time_diff
					};

					# check the results for things to drop
					my $return_results = $results;
					if ( $json->{drop}[0] ) {
						my $return_results = clone($results);
						my @drop_check     = keys( %{ $return_results->{results} } );
						foreach my $dn_to_check (@drop_check) {
							foreach my $to_drop ( @{ $json->{drop} } ) {
								if ( ref($to_drop) eq '' ) {
									if ( defined( $return_results->{results}{$dn_to_check}{$to_drop} ) ) {
										delete( $return_results->{results}{$dn_to_check}{$to_drop} );
									}
								}
							}
						}
					} ## end if ( $json->{drop}[0] )

					$heap->{client}->put( encode_json($return_results) );
					$heap->{self}{stats}{command_time}{search}
						= $heap->{self}{stats}{command_time}{search} + tv_interval( $t0, [gettimeofday] );
					return;
				} ## end if ( $time_diff <= $heap->{self}{cache_time...})
				$heap->{self}{stats}{misses}++;
			} else {
				$heap->{self}{stats}{misses}++;
			}
		} else {
			$heap->{self}{stats}{no_cache}++;
		}

		$heap->{processing} = 1;
		$heap->{self}{stats}{processing}++;

		POE::Session->create(
			inline_states => {
				_start           => \&fetch_start,
				got_child_stdout => \&fetch_child_stdout,
				got_child_stderr => \&fetch_child_stderr,
				got_child_close  => \&fetch_child_close,
				got_child_signal => \&fetch_child_signal,
			},
			heap => {
				self           => $heap->{self},
				client         => $heap->{client},
				session_heap   => $heap,
				stdout         => '',
				stderr         => '',
				make_it_pretty => $json->{make_it_pretty},
				search         => $search,
				drop           => $json->{drop},
				type           => 'search',
				t0             => $t0,
			},
		);
	} elsif ( $json->{command} eq 'list_searches' ) {
		$heap->{self}{stats}{commands}{list_searches}++;
		my @searches = keys( %{ $heap->{self}{cache_by_search} } );
		my $results  = {
			status     => 'ok',
			searches   => \@searches,
			when       => $heap->{self}{time_cached_by_search},
			time       => time,
			from_cache => 1,
			cache_time => $heap->{self}{cache_time}
		};
		$heap->{client}->put( encode_json($results) );
		$heap->{self}{stats}{command_time}{list_searches}
			= $heap->{self}{stats}{command_time}{list_searches} + tv_interval( $t0, [gettimeofday] );
		return;
	} elsif ( $json->{command} eq 'stats' ) {
		$heap->{self}{stats}{commands}{stats}++;
		$heap->{self}{stats}{uptime} = tv_interval( $heap->{self}{start_time}, [gettimeofday] );
		my @searches = keys( %{ $heap->{self}{cache_by_search} } );
		$heap->{self}{stats}{cached_searches} = $#searches + 1;
		my @DNs = keys( %{ $heap->{self}{cache_by_dn} } );
		$heap->{self}{stats}{cached_DNs} = $#DNs + 1;
		my $results = {
			status => 'ok',
			stats  => $heap->{self}{stats},
		};
		$heap->{client}->put( encode_json($results) );
		$heap->{self}{stats}{command_time}{stats}
			= $heap->{self}{stats}{command_time}{stats} + tv_interval( $t0, [gettimeofday] );
		return;
	} elsif ( $json->{command} eq 'ad_disable' ) {
		if ( !$heap->{self}{enable_ad_disable} ) {
			$heap->{self}{stats}{already_processing}++;
			my $error = { status => 'error', error => 'enable_ad_disable is false' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		}

		if ( !defined( $json->{dn} ) ) {
			$heap->{self}{stats}{already_processing}++;
			my $error = { status => 'error', error => 'dn is undef, should be the full DN for the account to disable' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		} elsif ( ref( $json->{dn} ) ne '' ) {
			$heap->{self}{stats}{already_processing}++;
			my $error = { status => 'error', error => 'dn is is ref type ' . ref( $json->{dn} ) . ' and not ""' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		}

		$heap->{processing} = 1;
		$heap->{self}{stats}{processing}++;
		$heap->{self}{stats}{commands}{ad_disable}++;

		my $search = '(useraccountcontrol=*)';

		POE::Session->create(
			inline_states => {
				_start           => \&fetch_start,
				got_child_stdout => \&fetch_child_stdout,
				got_child_stderr => \&fetch_child_stderr,
				got_child_close  => \&fetch_child_close,
				got_child_signal => \&fetch_child_signal,
			},
			heap => {
				self         => $heap->{self},
				client       => $heap->{client},
				session_heap => $heap,
				stdout       => '',
				stderr       => '',
				search       => $search,
				dn           => $json->{dn},
				type         => 'ad_disable',
				t0           => $t0,
			},
		);
	} elsif ( $json->{command} eq 'ad_lockout' ) {
		if ( !$heap->{self}{enable_ad_lockout} ) {
			$heap->{self}{stats}{already_processing}++;
			my $error = { status => 'error', error => 'enable_ad_lockout is false' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		}

		if ( !defined( $json->{dn} ) ) {
			$heap->{self}{stats}{already_processing}++;
			my $error = { status => 'error', error => 'dn is undef, should be the full DN for the account to lockout' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		} elsif ( ref( $json->{dn} ) ne '' ) {
			$heap->{self}{stats}{already_processing}++;
			my $error = { status => 'error', error => 'dn is is ref type ' . ref( $json->{dn} ) . ' and not ""' };
			$heap->{client}->put( encode_json($error) );
			$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
			return;
		}

		$heap->{processing} = 1;
		$heap->{self}{stats}{processing}++;
		$heap->{self}{stats}{commands}{ad_lockout}++;

		my $search = '(useraccountcontrol=*)';

		POE::Session->create(
			inline_states => {
				_start           => \&fetch_start,
				got_child_stdout => \&fetch_child_stdout,
				got_child_stderr => \&fetch_child_stderr,
				got_child_close  => \&fetch_child_close,
				got_child_signal => \&fetch_child_signal,
			},
			heap => {
				self         => $heap->{self},
				client       => $heap->{client},
				session_heap => $heap,
				stdout       => '',
				stderr       => '',
				search       => $search,
				dn           => $json->{dn},
				type         => 'ad_lockout',
				t0           => $t0,
			},
		);
	} else {
		$heap->{self}{stats}{commands}{unknown}++;
		my $results = { status => 'unknown command', };
		$heap->{client}->put( encode_json($results) );
		$heap->{self}{stats}{command_time}{unknown}
			= $heap->{self}{stats}{command_time}{unknown} + tv_interval( $t0, [gettimeofday] );
		$heap->{self}{stats}{error_time} = $heap->{self}{stats}{error_time} + tv_interval( $t0, [gettimeofday] );
		return;
	}
} ## end sub server_session_input

sub server_session_error {
	my ( $heap, $syscall, $errno, $error ) = @_[ HEAP, ARG0 .. ARG2 ];
	$error = "Normal disconnection." unless $errno;
	warn "Server session encountered $syscall error $errno: $error\n";
	$heap->{self}{stats}{connected}--;
	$heap->{self}{stats}{disconnects}++;
	delete $heap->{client};
}

#
#
# handles fetching items
#
#

sub fetch_start {
	my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];

	my @args         = ( "ldapsearch", '-LL' );
	my $connect_type = 'connect';
	if ( $heap->{type} eq 'ad_disable' || $heap->{type} eq 'ad_disable' ) {
		$connect_type = 'connect_admin';
	}
	foreach my $item ( @{ $heap->{session_heap}{self}{$connect_type} } ) {
		push( @args, $item );
	}

	if ( $heap->{type} eq 'ad_disable' || $heap->{type} eq 'ad_disable' ) {
		push( @args, '-b', $heap->{dn}, '-s', 'one' );
	}

	push( @args, '(&' . $heap->{session_heap}{self}{base_search} . $heap->{search} . ')' );

	my $child = POE::Wheel::Run->new(
		Program     => \@args,
		StdoutEvent => "got_child_stdout",
		StderrEvent => "got_child_stderr",
		CloseEvent  => "got_child_close",
	);

	$_[KERNEL]->sig_child( $child->PID, "got_child_signal" );

	# Wheel events include the wheel's ID.
	$_[HEAP]{children_by_wid}{ $child->ID } = $child;

	# Signal events include the process ID.
	$_[HEAP]{children_by_pid}{ $child->PID } = $child;

	#print( "Child pid ", $child->PID, " started as wheel ", $child->ID, ".\n" );
} ## end sub fetch_start

sub fetch_child_stdout {
	my ( $stdout_line, $wheel_id ) = @_[ ARG0, ARG1 ];
	my $child = $_[HEAP]{children_by_wid}{$wheel_id};

	#print "pid ", $child->PID, " STDOUT: $stdout_line\n";
	$_[HEAP]{stdout} = $_[HEAP]{stdout} . "\n" . $stdout_line;
}

sub fetch_child_stderr {
	my ( $stderr_line, $wheel_id ) = @_[ ARG0, ARG1 ];
	my $child = $_[HEAP]{children_by_wid}{$wheel_id};

	#print "pid ", $child->PID, " STDERR: $stderr_line\n";
	$_[HEAP]{stderr} = $_[HEAP]{stderr} . "\n" . $stderr_line;
}

sub fetch_child_close {
	my $wheel_id = $_[ARG0];
	my $child    = delete $_[HEAP]{children_by_wid}{$wheel_id};

	my $time   = time;
	my $search = $_[HEAP]{search};
	$_[HEAP]{self}{time_cached_by_search}{$search} = $time;
	my $found = 0;
	my $last_entry;
	eval {
		my ( $fh, $filename ) = tempfile();
		print $fh $_[HEAP]{stdout};
		close $fh;

		my $ldif = Net::LDAP::LDIF->new( $filename, "r", onerror => 'die' );
		delete( $_[HEAP]{self}{cache_by_search}{$search} );
		$_[HEAP]{self}{cache_by_search}{$search} = {};
		while ( not $ldif->eof() ) {
			my $entry      = $ldif->read_entry;
			my $entry_hash = {};

			if ( defined($entry) ) {
				$last_entry = $entry;

				foreach my $attribute ( $entry->attributes ) {
					$entry_hash->{$attribute} = $entry->get_value( $attribute, nooptions => 1, asref => 1 );
				}

				$_[HEAP]{self}{cache_by_dn}{ $entry->dn }       = $entry_hash;
				$_[HEAP]{self}{time_cached_by_dn}{ $entry->dn } = $time;

				$_[HEAP]{self}{cache_by_search}{$search}{ $entry->dn } = $entry_hash;

				$found++;
			} ## end if ( defined($entry) )
		} ## end while ( not $ldif->eof() )
	};
	if ($@) {
		warn($@);
		my $error = { status => 'error', error => 'Search failed... ' . $@ };
		$_[HEAP]{session_heap}{client}->put( encode_json($error) );
	}

	if ( $_[HEAP]{type} eq 'ad_disable' || $_[HEAP]{type} eq 'ad_lockout' ) {
		if ( $found == 1 ) {
			my $UserAccountControl_value;
			foreach my $attribute ( $last_entry->attributes ) {
				my $lc_attribute = lc($attribute);
				if ( $lc_attribute eq 'useraccountcontrol' ) {
					$UserAccountControl_value = $last_entry->get_value( $attribute, nooptions => 1, asref => 1 );
				}
			}
			if ( defined($UserAccountControl_value) ) {
				if ( defined( $UserAccountControl_value->[1] ) ) {
					my $error = { status => 'error', error => 'Multiple UserAccountControl values found' };
					$_[HEAP]{session_heap}{client}->put( encode_json($error) );
				} elsif ( defined( $UserAccountControl_value->[0] ) ) {
					my $new_value = $UserAccountControl_value->[0];
					if ( $_[HEAP]{type} eq 'ad_disable' ) {
						$new_value = $new_value ^ 0x0002;
					} elsif ( $_[HEAP]{type} eq 'ad_lockout' ) {
						$new_value = $new_value ^ 0x0010;
					}
					my $update_entry_string
						= 'DN: '
						. canonical_dn( $last_entry->dn )
						. "\nchangetype: modify\nreplace: UserAccountControl\nUserAccountControl: "
						. $new_value . "\n";
					print $update_entry_string."\n";
				} ## end elsif ( defined( $UserAccountControl_value->[...]))
			} else {
				my $error = { status => 'error', error => 'No UserAccountControl found.' };
				$_[HEAP]{session_heap}{client}->put( encode_json($error) );
			}
		} elsif ( $found > 1 ) {
			my $error = { status => 'error', error => 'More than one entry returned.' };
			$_[HEAP]{session_heap}{client}->put( encode_json($error) );
		} else {
			my $error = { status => 'error', error => 'No entry found.' };
			$_[HEAP]{session_heap}{client}->put( encode_json($error) );
		}
	} else {
		eval {
			my $json = JSON->new->utf8(1);
			if ( $found > 0 ) {
				my $results = {
					status              => 'ok',
					results             => $_[HEAP]{self}{cache_by_search}{$search},
					from_cache          => 0,
					cached_at           => $time,
					cached_to_now_delta => 0
				};

				my $return_results = $results;
				if ( defined( $_[HEAP]{session_heap}{drop}[0] ) ) {
					$return_results = clone($results);
					my @drop_check = keys( %{ $return_results->{results} } );
					foreach my $dn (@drop_check) {
						foreach my $to_drop ( @{ $_[HEAP]{session_heap}{drop} } ) {
							if ( ref($to_drop) eq '' ) {
								if ( defined( $return_results->{results}{$dn}{$to_drop} ) ) {
									delete( $return_results->{results}{$dn}{$to_drop} );
								}
							}
						}
					}
				} ## end if ( defined( $_[HEAP]{session_heap}{drop}...))

				$_[HEAP]{session_heap}{client}->put( $json->encode($return_results) );
			} else {
				my $results = { status => 'ok', results => {} };
				if ( $_[HEAP]{session_heap}{make_it_pretty} ) {
					$_[HEAP]{session_heap}{client}->put( $json->encode($results) );
				} else {
					$_[HEAP]{session_heap}{client}->put( $json->encode($results) );
				}
			}
		};
		if ($@) {
			warn($@);
		}
	} ## end else [ if ( $_[HEAP]{type} eq 'ad_disable' || $_[...])]

	# we are done processing the request at this point
	$_[HEAP]{session_heap}{processing} = 0;
	$_[HEAP]{session_heap}{self}{stats}{processing}--;

	# May have been reaped by on_child_signal().
	unless ( defined $child ) {

		#print "wid $wheel_id closed all pipes.\n";
		return;
	}

	$$_[HEAP]{session_heap}{self}{stats}{command_time}{ $_[HEAP]{session_heap}{type} }
		= $$_[HEAP]{session_heap}{self}{stats}{command_time}{ $_[HEAP]{session_heap}{type} }
		+ tv_interval( $_[HEAP]{session_heap}{t0}, [gettimeofday] );

	#print "pid ", $child->PID, " closed all pipes.\n";
	delete $_[HEAP]{children_by_pid}{ $child->PID };
} ## end sub fetch_child_close

sub fetch_child_signal {

	#print "pid $_[ARG1] exited with status $_[ARG2].\n";
	my $child = delete $_[HEAP]{children_by_pid}{ $_[ARG1] };

	# May have been reaped by on_child_close().
	return unless defined $child;

	if ( $_[HEAP]{session_heap}{processing} >= 1 ) {
		$_[HEAP]{session_heap}{processing} = 0;
		$_[HEAP]{session_heap}{self}{stats}{processing}--;
	}

	delete $_[HEAP]{children_by_wid}{ $child->ID };
} ## end sub fetch_child_signal

sub verbose {
	my ( $self, $level, $string ) = @_;

	if ( !defined($string) || $string eq '' ) {
		return;
	}

	if ( !defined($level) ) {
		$level = 'info';
	}

	openlog( 'nlkcd', undef, 'daemon' );
	syslog( $level, $string );
	closelog();
	if ( !$self->{daemonized} ) {
		print $string. "\n";
	}

	return;
} ## end sub verbose

=head1 SOCKET INTERFACE

The socket interface is JSON based. Upon connecting it returns...

    {"connected_to": "Net::LDAP::KeyCache v. 0.0.1"}

It will then wait for a command.

=head2 COMMANDS

=head3 fetch

The fetch command does a basic equality search.

Both are required.

    - var :: LDAP attribute to search for.
        - Default :: undef.

    - val :: Value to search for.
        - Default :: undef.

Example...

    {"command":"fetch","var":"uid","val":"foo"}

=head3 search

Runs the specified LDAP search. This is will be joined
with the base search as to form a and statement.

If the search does not start or end with () it is added.

    - search :: LDAP search string.
        - Default :: undef.

Example...

    {"command":"search","search":"uid=kitsune",}

=head3 list_searches

Returns a data on the current cache.

Example...

    {"command":"search","search":"uid=kitsune",}

The results returnt the following keys.

    - time :: Current unix time of the system it is running on.

    - searches :: A array of cached searches cached searches.

    - cache_time :: Length for how long a cached search is considered valid.

    - when :: A hash whose keys are the values from the array searches
            the values are the keys are the time at which that search was
            ran in unix time.

=head1 JSON RETURN

After issueing a command a line containing JSON will be returned.

    .status :: 'ok' or 'error' depending on if the command ran
            successfully or not. This key will always be present.

For 'fetch' and 'results' the following are present.

    .results :: An hash with the DN of found LDAP entries as keys.

    .results.$dn :: A found LDAP entry where the attributes are used as keys.

    .results.$dn.$attribute :: An array containing keys for that attribute.

Example...

    {
      "results": {
        "uid=foo,ou=users,dc=example": {
          "cn": [
            "foo"
          ],
          "description": [
            "some user"
          ],
          "gecos": [
            "Foo"
          ],
          "gidNumber": [
            "1001"
          ],
          "homeDirectory": [
            "/home/foo/"
          ],
          "loginShell": [
            "/sbin/nologin"
          ],
          "objectClass": [
            "top",
            "account",
            "posixAccount"
          ],
          "uid": [
            "foo"
          ],
          "uidNumber": [
            "1001"
          ]
        }
      },
      "status": "ok"
    }

For the 'stats' command the keys are as below...

    .stats.already_processing :: Count of times connected clients issued another
            command before waiting for a return.

    .stats.cached_DNs :: Count of number of cached DNs.

    .stats.cached_searches :: Count of number of cached searches.

    .stats.commands.fetch :: Count of fetch commands issues.

    .stats.commands.list_searches :: Count of list_searches commands issues.

    .stats.commands.search :: Count of search commands issues.

    .stats.commands :: Count of stats commands issues.

    .stats.commands.unknown :: Count of times client asked for a command
            that the server did not understand.

    .stats.command_time :: High resolution time used by commands

    .stats.command_time.unknown :: High resolution time used by used by handling
            commands the the server does not udnerstand

    .stats.connected :: List of currently connected client. Will always be
            one or higher as the client asking for stats counts as a client.

    .stats.decode_fail :: The number of times a connected client passed a line
            to the client could not be parsed as JSON.

    .stats.disconnects :: Cound of times a client has disconnected from the server.

    .stats.error_time :: Total time used for by things that errored.

    .stats.hits :: Cache hit count.

    .stats.misses :: Cache miss count.

    .stats.processing :: Current connections count that have a command being
            processed(as in the connection is not idle).

    .stats.uptime :: Number of seconds the server has been connected for.

Example...

    {
      "stats": {
        "already_processing": 0,
        "cached_DNs": 2,
        "cached_searches": 2,
        "commands": {
          "fetch": 8,
          "list_searches": 2,
          "search": 0,
          "stats": 4,
          "unknown": 0
        },
        "connected": 1,
        "decode_fail": 0,
        "disconnects": 13,
        "hits": 4,
        "misses": 4,
        "processing": 0,
        "uptime": 978
      },
      "status": "ok"
    }

=head1 AUTHOR

Zane C. Bowers-Hadley, C<< <vvelox at vvelox.net> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-net-ldap-keycache at rt.cpan.org>, or through
the web interface at L<https://rt.cpan.org/NoAuth/ReportBug.html?Queue=Net-LDAP-KeyCache>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Net::LDAP::KeyCache


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<https://rt.cpan.org/NoAuth/Bugs.html?Dist=Net-LDAP-KeyCache>

=item * Search CPAN

L<https://metacpan.org/release/Net-LDAP-KeyCache>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2024 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991


=cut

1;    # End of Net::LDAP::KeyCache
