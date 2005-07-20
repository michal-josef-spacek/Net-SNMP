# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::Transport;

# $Id: Transport.pm,v 1.2 2005/07/20 13:53:07 dtown Exp $

# Base object for the Net::SNMP Transport Domain objects.

# Copyright (c) 2004-2005 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

## Version of the Net::SNMP::Transport module

our $VERSION = v1.0.2;

## Handle importing/exporting of symbols

use Exporter();

our @ISA = qw( Exporter );

our @EXPORT_OK = qw( TRUE FALSE );

our %EXPORT_TAGS = (
   domains => [ 
      qw( DOMAIN_UDP DOMAIN_UDPIPV6 DOMAIN_TCPIPV4 DOMAIN_TCPIPV6 ) 
   ], 
   msgsize => [ qw( MSG_SIZE_DEFAULT MSG_SIZE_MINIMUM MSG_SIZE_MAXIMUM ) ], 
   ports   => [ qw( SNMP_PORT SNMP_TRAP_PORT )                           ],
   retries => [ qw( RETRIES_DEFAULT RETRIES_MINIMUM RETRIES_MAXIMUM )    ],
   timeout => [ qw( TIMEOUT_DEFAULT TIMEOUT_MINIMUM TIMEOUT_MAXIMUM )    ],
   _array  => [ 
      qw( _DSTNAME _MAXSIZE _RETRIES _TIMEOUT _SOCKET _SRCADDR _DSTADDR
          _ERROR _REASM_BUFFER _REASM_LENGTH )
   ],
   _shared => [ qw( _SHARED_SOCKET _SHARED_REFC _SHARED_MAXSIZE )        ]
);

Exporter::export_ok_tags(
   qw( domains msgsize ports retries timeout _array _shared ) 
);

$EXPORT_TAGS{ALL} = [ @EXPORT_OK ];

## Transport Layer Domain definitions

# RFC 3417 Transport Mappings for SNMP
# Presuhn, Case, McCloghrie, Rose, and Waldbusser; December 2002

sub DOMAIN_UDP()           { '1.3.6.1.6.1.1' } # snmpUDPDomain

# RFC 3419 Textual Conventions for Transport Addresses
# Consultant, Schoenwaelder, and Braunschweig; December 2002

sub DOMAIN_UDPIPV6() { '1.3.6.1.2.1.100.1.2' } # transportDomainUdpIpv6
sub DOMAIN_TCPIPV4() { '1.3.6.1.2.1.100.1.5' } # transportDomainTcpIpv4
sub DOMAIN_TCPIPV6() { '1.3.6.1.2.1.100.1.6' } # transportDomainTcpIpv6

## SNMP well-known ports

sub SNMP_PORT()              { 161 }
sub SNMP_TRAP_PORT()         { 162 }

## RFC 3411 - snmpEngineMaxMessageSize::=INTEGER (484..2147483647)

sub MSG_SIZE_DEFAULT()      {  484 }  
sub MSG_SIZE_MINIMUM()      {  484 }
sub MSG_SIZE_MAXIMUM()     { 65535 }  # 2147483647 is not reasonable

sub RETRIES_DEFAULT()         {  1 }
sub RETRIES_MINIMUM()         {  0 }
sub RETRIES_MAXIMUM()         { 20 }

sub TIMEOUT_DEFAULT()       {  5.0 }
sub TIMEOUT_MINIMUM()       {  1.0 }
sub TIMEOUT_MAXIMUM()       { 60.0 }

## Truth values

sub TRUE()                  { 0x01 }
sub FALSE()                 { 0x00 }

## Object array indexes

sub _DSTNAME()                 { 0 }   # Destination hostname
sub _MAXSIZE()                 { 1 }   # maxMsgSize
sub _RETRIES()                 { 2 }   # Number of retransmissions
sub _TIMEOUT()                 { 3 }   # Timeout period in seconds
sub _SOCKET()                  { 4 }   # Socket object
sub _SRCADDR()                 { 5 }   # Source sockaddr
sub _DSTADDR()                 { 6 }   # Destination sockaddr
sub _ERROR()                   { 7 }   # Error message
sub _REASM_BUFFER()            { 8 }   # Reassembly buffer for data
sub _REASM_LENGTH()            { 9 }   # Expected length of reassembled data

## Shared socket array indexes

sub _SHARED_SOCKET()           { 0 }   # Shared Socket object
sub _SHARED_REFC()             { 1 }   # Reference count
sub _SHARED_MAXSIZE()          { 2 }   # Shared maxMsgSize

## Package variables

our $DEBUG = FALSE;                    # Debug flag

our $AUTOLOAD;                         # Used by the AUTOLOAD method

our $SOCKETS = {};                     # List of shared sockets

## Load the module for the default Transport Domain.

require Net::SNMP::Transport::UDP;

# [public methods] -----------------------------------------------------------

sub new
{
   my ($class, %argv) = @_;

   my $domain = DOMAIN_UDP;
   my $error  = '';

   # See if a Transport Layer Domain argument has been passed.

   foreach (keys %argv) {

      if (/^-?domain$/i) {

         # Allow the user some flexability
         my $supported = {
            'udp4',          DOMAIN_UDP,
            'udpip4',        DOMAIN_UDP,
            'udpipv4',       DOMAIN_UDP,
            'udp/ipv4',      DOMAIN_UDP,
            DOMAIN_UDP,      DOMAIN_UDP,
            'udp6',          DOMAIN_UDPIPV6,
            'udpip6',        DOMAIN_UDPIPV6,
            'udpipv6',       DOMAIN_UDPIPV6,
            'udp/ipv6',      DOMAIN_UDPIPV6,
            DOMAIN_UDPIPV6,  DOMAIN_UDPIPV6,
            'tcp4',          DOMAIN_TCPIPV4,
            'tcpip4',        DOMAIN_TCPIPV4,
            'tcpipv4',       DOMAIN_TCPIPV4,
            'tcp/ipv4',      DOMAIN_TCPIPV4,
            DOMAIN_TCPIPV4,  DOMAIN_TCPIPV4,
            'tcp6',          DOMAIN_TCPIPV6,
            'tcpip6',        DOMAIN_TCPIPV6,
            'tcpipv6',       DOMAIN_TCPIPV6,
            'tcp/ipv6',      DOMAIN_TCPIPV6,
            DOMAIN_TCPIPV6,  DOMAIN_TCPIPV6,
         };

         my $key   = $_;
         my @match = grep(/^\Q$argv{$key}/i, keys(%{$supported}));

         if (@match > 1) {
            if (lc($argv{$key}) eq 'udp') {
               $match[0] = 'udp4';
            } elsif (lc($argv{$key}) eq 'tcp') {
               $match[0] = 'tcp4';
            } else { 
               $error = err_msg('Ambiguous Transport Domain [%s]', $argv{$_});
               return wantarray ? (undef, $error) : undef;
            }
         } elsif (@match != 1) {
            $error = err_msg(
               'Unknown or invalid Transport Domain [%s]', $argv{$_}
            );
            return wantarray ? (undef, $error) : undef;
         }

         $argv{$key} = $domain = $supported->{$match[0]}
      }

   }

   # Return the appropriate object based on the Transport Domain.  To
   # avoid consuming unnecessary resources, load the non-default modules 
   # only when requested.  Some modules require non-core modules and if
   # these modules are not present, we gracefully return an error.

   if ($domain eq DOMAIN_UDPIPV6) {
      if (defined($error = load_module('Net::SNMP::Transport::UDP6'))) {
         wantarray ? (undef, 'UDP/IPv6 support unavailable ' . $error) : undef;
      } else {
         Net::SNMP::Transport::UDP6->new(%argv);
      }
   } elsif ($domain eq DOMAIN_TCPIPV6) {
      if (defined($error = load_module('Net::SNMP::Transport::TCP6'))) {
         wantarray ? (undef, 'TCP/IPv6 support unavailable ' . $error) : undef;
      } else {
         Net::SNMP::Transport::TCP6->new(%argv);
      }
   } elsif ($domain eq DOMAIN_TCPIPV4) {
      if (defined($error = load_module('Net::SNMP::Transport::TCP'))) {
         wantarray ? (undef, 'TCP/IPv4 support unavailable ' . $error) : undef;
      } else {
         Net::SNMP::Transport::TCP->new(%argv);
      }
   } else {
      Net::SNMP::Transport::UDP->new(%argv);
   }

}

sub max_msg_size
{
   my ($this, $size) = @_;

   if (@_ == 2) {

      $this->_error_clear;

      if ($size =~ /^\d+$/) {
         if (($size >= MSG_SIZE_MINIMUM) && ($size <= MSG_SIZE_MAXIMUM)) { 
            $this->_shared_maxsize($this->[_MAXSIZE] = $size);
         } else {
            return $this->_error(
               'Invalid maxMsgSize value [%s], range %d - %d octets',
               $size, MSG_SIZE_MINIMUM, MSG_SIZE_MAXIMUM
            );
         }
      } else {
         return $this->_error('Expected positive numeric maxMsgSize value');
      }

   }

   $this->[_MAXSIZE];
}

sub timeout
{
   my ($this, $timeout) = @_;

   if (@_ == 2) {

      $this->_error_clear;

      if ($timeout =~ /^\d+(\.\d+)?$/) {
         if (($timeout >= TIMEOUT_MINIMUM) && ($timeout <= TIMEOUT_MAXIMUM)) {
            $this->[_TIMEOUT] = $timeout;
         } else {
            return $this->_error(
               'Invalid timeout value [%s], range %03.01f - %03.01f seconds',
               $timeout, TIMEOUT_MINIMUM, TIMEOUT_MAXIMUM
            );
         }
      } else {
         return $this->_error('Expected positive numeric timeout value');
      }

   }

   $this->[_TIMEOUT];
}

sub retries
{
   my ($this, $retries) = @_;

   if (@_ == 2) {

      $this->_error_clear;

      if ($retries =~ /^\d+$/) {
         if (($retries >= RETRIES_MINIMUM) && ($retries <= RETRIES_MAXIMUM)) {
            $this->[_RETRIES] = $retries;
         } else {
            return $this->_error(
               'Invalid retries value [%s], range %d - %d',
               $retries, RETRIES_MINIMUM, RETRIES_MAXIMUM
            );
         }
      } else {
         return $this->_error('Expected positive numeric retries value');
      }

   }

   $this->[_RETRIES];
}

sub connectionless
{
   TRUE;  
}

sub domain
{
   '0.0';
}

sub name
{
   '<unknown>';
}

sub srcaddr
{
   $_[0]->[_SOCKET]->sockaddr || $_[0]->_addr_any;
}

sub srcport
{
   $_[0]->[_SOCKET]->sockport || 0;
}

sub srchost
{
   $_[0]->[_SOCKET]->sockhost || $_[0]->_addr_ntoa($_[0]->srcaddr);
}

sub srcname
{
   my ($this) = @_;

   my $srcaddr = $this->srcaddr;

   if ($srcaddr eq $this->_addr_any) {
      eval {
         require Sys::Hostname;
         $srcaddr = $this->_addr_aton(Sys::Hostname::hostname());
      };
      $srcaddr = $this->_addr_any if (!defined($srcaddr) || $@);
   }

   $this->_addr_ntoa($srcaddr);
}

sub dstaddr
{
   ($_[0]->_addr_pack($_[0]->[_DSTADDR]))[1];
}

sub dstport
{
   ($_[0]->_addr_pack($_[0]->[_DSTADDR]))[0];
}

sub dsthost
{
   $_[0]->_addr_ntoa($_[0]->dstaddr);
}

sub dstname
{
   $_[0]->[_DSTNAME];
}

sub recvaddr
{
   $_[0]->[_SOCKET]->peeraddr || $_[0]->_addr_any;
}

sub recvport
{
   $_[0]->[_SOCKET]->peerport || 0;
}

sub recvhost
{
   $_[0]->[_SOCKET]->peerhost || $_[0]->_addr_ntoa($_[0]->recvaddr);
}

sub socket
{
   $_[0]->[_SOCKET];
}

sub fileno
{
   $_[0]->[_SOCKET]->fileno;
}

sub error
{
   $_[0]->[_ERROR] || '';
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

sub AUTOLOAD
{
   my ($this) = @_;

   return if $AUTOLOAD =~ /::DESTROY$/;

   $AUTOLOAD =~ s/.*://;

   if (ref($this)) {
      $this->_error(
         'Feature not supported by this Transport Domain [%s]', $AUTOLOAD
      );
   } else {
      die sprintf('Unsupported function call [%s]', $AUTOLOAD);
   }
}

sub DESTROY
{
   my ($this) = @_;

   # Connection-oriented transports do not share sockets.
   return unless ($this->connectionless);

   # Decrement the reference count and clear the shared
   # socket structure if no one is using it.

   return unless (defined($this->[_SRCADDR]) &&
                    exists($SOCKETS->{$this->[_SRCADDR]}));

   if (--$SOCKETS->{$this->[_SRCADDR]}->[_SHARED_REFC] < 1) {
      delete($SOCKETS->{$this->[_SRCADDR]});
   }
}

# [private methods] ----------------------------------------------------------

sub _new
{
   my ($class, %argv) = @_;

   my $this = bless [
      'localhost',                # Destination hostname
      $class->_msg_size_default,  # maxMsgSize
      RETRIES_DEFAULT,            # Number of retransmissions
      TIMEOUT_DEFAULT,            # Timeout period in seconds
      undef,                      # Socket object
      undef,                      # Source sockaddr
      undef,                      # Destination sockaddr
      undef,                      # Error message
      '',                         # Reassembly buffer
      0                           # Reassembly length
   ], $class;

   my $src_addr = $this->_addr_any;
   my $src_port = 0;
   my $dst_addr = $this->_addr_loopback;
   my $dst_port = SNMP_PORT;
   my $listen   = 0;

   # Validate the passed arguments

   foreach (keys %argv) {

      if (/^-?debug$/i) {
         $this->debug($argv{$_});
      } elsif ((/^-?dstaddr$/i) || (/^-?hostname$/i)) {
         $this->[_DSTNAME] = $argv{$_};
         if (!defined($dst_addr = $this->_addr_aton($argv{$_}))) {
            $this->_error(
               "Unable to resolve destination %s address '%s'",
               $this->name, $argv{$_}
            );
         }
      } elsif ((/^-?dstport$/i) || (/^-?port$/i)) {
         if (!defined($dst_port = $this->_serv_aton($argv{$_}))) {
            $this->_error(
               "Unable to resolve destination %s service '%s'",
               $this->name, $argv{$_}
            );
         }
      } elsif ((/^-?srcaddr$/i) || (/^-?localaddr$/i)) {
         if (!defined($src_addr = $this->_addr_aton($argv{$_}))) {
            $this->_error(
               "Unable to resolve local %s address '%s'", $this->name, $argv{$_}
            );
         }
      } elsif ((/^-?srcport$/i) || (/^-?localport$/i)) {
         if (!defined($src_port = $this->_serv_aton($argv{$_}))) {
            $this->_error(
               "Unable to resolve local %s service '%s'", $this->name, $argv{$_}
            );
         }
      } elsif (/^-?domain$/i) {
         if ($argv{$_} ne $this->domain) {
            $this->_error('Invalid Transport Domain [%s]', $argv{$_});
         }
      } elsif ((/^-?maxmsgsize$/i) || (/^-?mtu$/i)) {
         $this->max_msg_size($argv{$_});
      } elsif (/^-?retries$/i) {
         $this->retries($argv{$_});
      } elsif (/^-?timeout$/i) {
         $this->timeout($argv{$_});
      } elsif (/^-?listen$/i) {
         if (($argv{$_} !~ /^\d+$/) || ($argv{$_} < 1)) {
            $this->_error('Expected positive non-zero listen queue size');
         } elsif (!$this->connectionless) { 
            $listen = $argv{$_};
         }
      } else {
         $this->_error("Invalid argument '%s'", $_);
      }

      if (defined($this->[_ERROR])) {
         return wantarray ? (undef, $this->[_ERROR]) : undef;
      }

   }

   # Pack the source address and port information
   $this->[_SRCADDR] = $this->_addr_pack($src_port, $src_addr);

   # Pack the destination address and port information
   $this->[_DSTADDR] = $this->_addr_pack($dst_port, $dst_addr);

   # For all connection-oriented transports and for each unique source 
   # address for connectionless transports, create a new socket. 

   if ((!$this->connectionless) || (!exists($SOCKETS->{$this->[_SRCADDR]}))) {

      # Create and bind a new IO::Socket::INET[6] object

      $this->[_SOCKET] = $this->_socket_create(

         LocalAddr  => $this->_addr_ntoa($src_addr),
         ($src_port) ? ( LocalPort => $src_port ) : (), 

         # For connection-oriented transports, we either listen or
         # attempt to connect to the remote host.

         (!$this->connectionless) ? ($listen) ?
            ( Listen   => $listen ) : 
            ( PeerAddr => $this->_addr_ntoa($dst_addr),
              PeerPort => $dst_port ) : ()

      );

      if (!defined($this->[_SOCKET])) {
         $this->_error($! || 'Unknown error creating socket');
         return wantarray ? (undef, $this->[_ERROR]) : undef;
      }

      # Flag the socket as non-blocking outside of socket creation or 
      # the object instantiation fails on some systems (e.g. MSWin32). 

      $this->[_SOCKET]->blocking(FALSE);

      DEBUG_INFO(
         'opened %s socket [%d]', $this->name, $this->[_SOCKET]->fileno
      );

      # Add the socket to the global socket list with a reference
      # count to track when to close the socket and the maxMsgSize
      # associated with this new object for connectionless transports.

      if ($this->connectionless) {
         $SOCKETS->{$this->[_SRCADDR]} = [ 
            $this->[_SOCKET], 1, $this->[_MAXSIZE]
         ];
      }

   } else {

      DEBUG_INFO(
         'reused %s socket [%d]',
         $this->name, $SOCKETS->{$this->[_SRCADDR]}->[_SHARED_SOCKET]->fileno
      );

      # Bump up the reference count
      $SOCKETS->{$this->[_SRCADDR]}->[_SHARED_REFC]++;

      # Adjust the shared maxMsgSize if necessary
      $this->_shared_maxsize($this->[_MAXSIZE]);

      # Assign the socket to the object
      $this->[_SOCKET] = $SOCKETS->{$this->[_SRCADDR]}->[_SHARED_SOCKET]; 

   }

   # Return the object and empty error message (in list context)
   wantarray ? ($this, '') : $this;
}

sub _shared_maxsize
{
   my ($this, $size) = @_;

   # Connection-oriented transports do not share sockets.
   if (!$this->connectionless) {
      return $this->[_MAXSIZE];
   }

   if (@_ == 2) {

      # Handle calls during object creation.
      if (!defined($this->[_SRCADDR])) {
         return $this->[_MAXSIZE];
      }

      # Update the shared maxMsgSize if the passed
      # value is greater than the current size.

      if ($size > $SOCKETS->{$this->[_SRCADDR]}->[_SHARED_MAXSIZE]) {
         $SOCKETS->{$this->[_SRCADDR]}->[_SHARED_MAXSIZE] = $size;
      }

   }

   $SOCKETS->{$this->[_SRCADDR]}->[_SHARED_MAXSIZE];
}

sub _msg_size_default
{
   MSG_SIZE_DEFAULT;
}

sub _reasm_reset
{
   $_[0]->[_REASM_BUFFER] = '';
   $_[0]->[_REASM_LENGTH] = 0;
}

sub _error
{
   my $this = shift;

   if (!defined($this->[_ERROR])) {
      $this->[_ERROR] = (@_ > 1) ? sprintf(shift(@_), @_) : $_[0];
      if ($this->debug) {
         printf("error: [%d] %s(): %s\n",
            (caller(0))[2], (caller(1))[3], $this->[_ERROR]
         );
      }
   }

   return;
}

sub _error_clear
{
   $! = 0;
   $_[0]->[_ERROR] = undef;
}

{
   my %modules;

   sub load_module
   {
      my ($module) = @_;

      # We attempt to load the required module under the protection of an 
      # eval statement.  If there is a failure, typically it is due to a 
      # missing module required by the requested module and we attempt to 
      # simplify the error message by just listing that module.  We also 
      # need to track failures since require() only produces an error on 
      # the first attempt to load the module.

      # NOTE: Contrary to our typical convention, a return value of "undef"
      # actually means success and a defined value means error.

      return $modules{$module} if (exists($modules{$module}));

      if (!eval("require $module")) {
         if ($@ =~ /locate (\S+\.pm)/) {
            $modules{$module} = err_msg('(Required module %s not found)', $1);
         } else {
            $modules{$module} = err_msg('(%s)', $@);
         }
      } else {
         $modules{$module} = undef;  
      }
   }
}

sub err_msg(@)
{
   my $msg = (@_ > 1) ? sprintf(shift(@_), @_) : $_[0]; 

   if ($DEBUG) {
      printf("error: [%d] %s(): %s\n", (caller(0))[2], (caller(1))[3], $msg);
   }

   $msg;
}

sub DEBUG_INFO
{
   return unless $DEBUG;

   printf(
      sprintf('debug: [%d] %s(): ', (caller(0))[2], (caller(1))[3]) .
      ((@_ > 1) ? shift(@_) : '%s') .
      "\n",
      @_
   );

   $DEBUG;
}

# ============================================================================
1; # [end Net::SNMP::Transport]
