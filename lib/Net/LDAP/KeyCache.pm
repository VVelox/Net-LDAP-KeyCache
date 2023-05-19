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

=head1 NAME

Net::LDAP::KeyCache - 

=head1 VERSION

Version 0.0.1

=cut

our $VERSION = '0.0.1';

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use Net::LDAP::KeyCache;

    my $foo = Net::LDAP::KeyCache->new();
    ...

=head1 METHODS

=head2 ne
w
    - pid :: Location of the PID file.
        Default :: /var/run/nlkcd/pid

    - socket :: Socket locations.
        Default :: /var/run/nlkcd/socket

    - base_search :: The base to use for the search.
        Default :: (|(objectClass=person)(objectClass=posixAccount)(objectClass=inetOrgPerson)(objectClass=account)(objectClass=posixGroup))

    - connect :: An array to of options to pass to ldapsearch. Should include the relevant
                 bind, base DN, and host options.
        Default :: undef

    - cache_time :: Timeout for cached items in seconds.
        Default :: 120

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
		cache_by_dn           => {},
		time_cached_by_dn     => {},
		cache_by_search       => {},
		time_cached_by_search => {},
		cache_time            => 300,
	};
	bless $self;

	my @to_merge = ( 'pid', 'socket', 'base_search', 'cache_time' );
	foreach my $item (@to_merge) {
		if ( defined( $opts{$item} ) ) {
			$self->{$item} = $opts{item};
		}
	}

	return $self;
} ## end sub new

=head2 start_server

Starts up server, calling $poe_kernel->run.

This should not be expected to return.

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
	$heap->{client}->put( "Connected to Net::LDAP::KeyCache v. " . $Net::LDAP::KeyCache::VERSION );
}

# handle line inputs
sub server_session_input {
	my ( $heap, $input ) = @_[ HEAP, ARG0 ];

	if ( $input eq 'exit' ) {
		delete $heap->{client};
		return;
	}

	if ( $heap->{processing} ) {
		my $error = { status => 'error', error => 'already processing a request' };
		$heap->{client}->put( encode_json($error) );
		return;
	}

	my $json;
	eval { $json = decode_json($input); };
	if ($@) {
		my $error = { status => 'error', error => $@ };
		$heap->{client}->put( encode_json($error) );
		return;
	} elsif ( !defined($json) ) {
		my $error = { status => 'error', error => 'parsing JSON returned undef' };
		$heap->{client}->put( encode_json($error) );
		return;
	}

	if ( !defined( $json->{command} ) ) {
		my $error = { status => 'error', error => '$json->{command} is undef' };
		$heap->{client}->put( encode_json($error) );
		return;
	}

	# bad idea, don't use this in production
	my $make_it_pretty = 0;
	if ( !defined( $json->{make_it_pretty} ) ) {
		$json->{make_it_pretty} = 0;
	}

	if ( $json->{command} eq 'fetch' ) {
		if ( !defined( $json->{var} ) ) {
			my $error = { status => 'error', error => '$json->{var} is undef' };
			$heap->{client}->put( encode_json($error) );
			return;
		} elsif ( !defined( $json->{val} ) ) {
			my $error = { status => 'error', error => '$json->{val} is undef' };
			$heap->{client}->put( encode_json($error) );
			return;
		}

		$heap->{processing} = 1;

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
				var            => $json->{var},
				val            => $json->{val},
				map_to         => $json->{map_to},
				make_it_pretty => $json->{make_it_pretty},
				search         => $json->{var} . '=' . $json->{val},
			},
		);
	} ## end if ( $json->{command} eq 'fetch' )
} ## end sub server_session_input

sub server_session_error {
	my ( $heap, $syscall, $errno, $error ) = @_[ HEAP, ARG0 .. ARG2 ];
	$error = "Normal disconnection." unless $errno;
	warn "Server session encountered $syscall error $errno: $error\n";
	delete $heap->{client};
}

#
#
# handles fetching items
#
#

sub fetch_start {
	my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];

	my @args = ( "ldapsearch", '-LL' );
	foreach my $item ( @{ $heap->{session_heap}{self}{connect} } ) {
		push( @args, $item );
	}

	push( @args, '(&' . $heap->{session_heap}{self}{base_search} . '(' . $heap->{var} . '=' . $heap->{val} . '))' );

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

	my $time   = localtime;
	my $search = $_[HEAP]{search};
	$_[HEAP]{self}{time_cached_by_search}{$search} = $time;
	my $found = 0;
	eval {
		my ( $fh, $filename ) = tempfile();
		print $fh $_[HEAP]{stdout};
		close $fh;

		my $ldif = Net::LDAP::LDIF->new( $filename, "r", onerror => 'die' );
		while ( not $ldif->eof() ) {
			my $entry      = $ldif->read_entry;
			my $entry_hash = {};

			foreach my $attribute ( $entry->attributes ) {
				$entry_hash->{$attribute} = $entry->get_value( $attribute, nooptions => 1, asref => 1 );
			}

			$_[HEAP]{self}{cache_by_dn}{ $entry->dn }       = $entry_hash;
			$_[HEAP]{self}{time_cached_by_dn}{ $entry->dn } = $time;

			if ( !defined( $_[HEAP]{self}{cache_by_search}{$search} ) ) {
				$_[HEAP]{self}{cache_by_search}{$search} = { $entry->dn => $entry_hash, };
			} else {
				$_[HEAP]{self}{cache_by_search}{$search}{ $entry->dn } = $entry_hash;
			}

			$found++;
		} ## end while ( not $ldif->eof() )
	};
	if ($@) {
		warn($@);
		my $error = { status => 'error', error => 'Search failed... $@' };
		$_[HEAP]{session_heap}{client}->put( encode_json($error) );
	}

	eval {
		if ( $found > 0 ) {
			my $results = { status => 'found', results => $_[HEAP]{self}{cache_by_search}{$search} };
			$_[HEAP]{session_heap}{client}->put( encode_json($results) );
		} else {
			my $results = { status => 'notfound', results => {} };
			if ($_[HEAP]{session_heap}{make_it_pretty}) {
				$_[HEAP]{session_heap}{client}->put( encode_json($results) );
			}else {
				$_[HEAP]{session_heap}{client}->put( encode_json($results) );
			}
		}
	};
	if ($@) {
		warn($@);
	}

	# we are done processing the request at this point
	$_[HEAP]{session_heap}{processing} = 0;

	# May have been reaped by on_child_signal().
	unless ( defined $child ) {

		#print "wid $wheel_id closed all pipes.\n";
		return;
	}

	#print "pid ", $child->PID, " closed all pipes.\n";
	delete $_[HEAP]{children_by_pid}{ $child->PID };
} ## end sub fetch_child_close

sub fetch_child_signal {

	#print "pid $_[ARG1] exited with status $_[ARG2].\n";
	my $child = delete $_[HEAP]{children_by_pid}{ $_[ARG1] };

	# May have been reaped by on_child_close().
	return unless defined $child;

	$_[HEAP]{session_heap}{processing} = 0;

	delete $_[HEAP]{children_by_wid}{ $child->ID };
} ## end sub fetch_child_signal

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

=item * CPAN Ratings

L<https://cpanratings.perl.org/d/Net-LDAP-KeyCache>

=item * Search CPAN

L<https://metacpan.org/release/Net-LDAP-KeyCache>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2023 by Zane C. Bowers-Hadley.

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991


=cut

1;    # End of Net::LDAP::KeyCache
