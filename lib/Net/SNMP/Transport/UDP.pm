# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::Transport::UDP;

# $Id: UDP.pm,v 1.2 2001/11/09 14:03:52 dtown Exp $

# Object that handles the UDP/IP Transport layer for the SNMP Engine.

# Copyright (c) 2001 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Sys::Hostname();

use IO::Socket::INET qw(
   SOCK_DGRAM INADDR_ANY INADDR_LOOPBACK inet_aton inet_ntoa sockaddr_in
);

## Version of the Net::SNMP::Transport::UDP module

our $VERSION = v1.0.0;

## Handle importing/exporting of symbols

use Exporter();

our @ISA = qw(Exporter);

our @EXPORT_OK;

our %EXPORT_TAGS = (
   msgsize => [qw(MSG_SIZE_DEFAULT MSG_SIZE_MINIMUM MSG_SIZE_MAXIMUM)],
   ports   => [qw(SNMP_PORT SNMP_TRAP_PORT)],
   retries => [qw(RETRIES_DEFAULT RETRIES_MINIMUM RETRIES_MAXIMUM)],
   timeout => [qw(TIMEOUT_DEFAULT TIMEOUT_MINIMUM TIMEOUT_MAXIMUM)], 
);

Exporter::export_ok_tags(qw(msgsize ports retries timeout));

$EXPORT_TAGS{ALL} = [@EXPORT_OK];

## SNMP ports

sub SNMP_PORT()               { 161 }
sub SNMP_TRAP_PORT()          { 162 }

## msgMaxSize::=INTEGER (484..2147483647)

sub MSG_SIZE_DEFAULT()       { 1472 }  # Ethernet(1500) - IP(20) - UDP(8)
sub MSG_SIZE_MINIMUM()       {  484 }
sub MSG_SIZE_MAXIMUM() { 2147483647 }

sub RETRIES_DEFAULT()          {  1 }
sub RETRIES_MINIMUM()          {  0 }
sub RETRIES_MAXIMUM()          { 20 }

sub TIMEOUT_DEFAULT()        {  5.0 }
sub TIMEOUT_MINIMUM()        {  1.0 }
sub TIMEOUT_MAXIMUM()        { 60.0 } 

## Object array indexes 

sub _DSTNAME() { 0 }                   # Destination hostname
sub _MAXSIZE() { 1 }                   # maxMsgSize
sub _RETRIES() { 2 }                   # Number of retransmissions
sub _TIMEOUT() { 3 }                   # Timeout period in seconds
sub _SOCKET()  { 4 }                   # Socket object
sub _SRCADDR() { 5 }                   # Source sockaddr
sub _DSTADDR() { 6 }                   # Destination sockaddr
sub _ERROR()   { 7 }                   # Error message

## Package variables

our $DEBUG = 0;                        # Debug flag

our $SOCKETS = {};                     # List of opened sockets

our $MAX_SIZE_MSG = MSG_SIZE_DEFAULT;  # Package maxMsgSize 

# [public methods] -----------------------------------------------------------

sub new
{
   my ($class, %argv) = @_;

   my $this = bless [
      'localhost',       # Destination hostname
      MSG_SIZE_DEFAULT,  # maxMsgSize
      RETRIES_DEFAULT,   # Number of retransmissions
      TIMEOUT_DEFAULT,   # Timeout period in seconds
      undef,             # Socket
      undef,             # Source sockaddr
      undef,             # Destination sockaddr
      undef,             # Error message
   ], $class; 

   my $src_addr = INADDR_ANY;
   my $src_port = 0;
   my $dst_addr = INADDR_LOOPBACK;
   my $dst_port = SNMP_PORT;

   # Validate the passed arguments

   foreach (keys %argv) {
      if (/^-?debug$/i) {
         $this->debug($argv{$_});
      } elsif ((/^-?dstaddr$/i) || (/^-?hostname$/i)) {
         $this->[_DSTNAME] = $argv{$_};
         if (!defined($dst_addr = inet_aton($argv{$_}))) {
            $this->_error(
               "Unable to resolve destination address '%s'", $argv{$_}
            );
         }
      } elsif ((/^-?dstport$/i) || (/^-?port$/i)) {
         if (!defined($dst_port = _getservbyname($argv{$_}))) {
            $this->_error(
               "Unable to resolve destination UDP service '%s'", $argv{$_}
            );
         }
      } elsif ((/^-?srcaddr$/i) || (/^-?localaddr$/i)) {
         if (!defined($src_addr = inet_aton($argv{$_}))) {
            $this->_error(
               "Unable to resolve local address '%s'", $argv{$_} 
            );
         }
      } elsif ((/^-?srcport$/i) || (/^-?localport$/i)) {
         if (!defined($src_port = _getservbyname($argv{$_}))) {
            $this->_error(
               "Unable to resolve local UDP service '%s'", $argv{$_}
            );
         }
      } elsif ((/^-?maxmsgsize$/i) || (/^-?mtu$/i)) {
         $this->max_msg_size($argv{$_});
      } elsif (/^-?retries$/i) {
         $this->retries($argv{$_});
      } elsif (/^-?timeout$/i) {
         $this->timeout($argv{$_});
      } else {
         $this->_error("Invalid argument '%s'", $_);
      }

      if (defined($this->[_ERROR])) {
         return wantarray ? (undef, $this->[_ERROR]) : undef;
      }

   }

   # Pack the source address and port information
   $this->[_SRCADDR] = sockaddr_in($src_port, $src_addr);

   # Pack the destination address and port information
   $this->[_DSTADDR] = sockaddr_in($dst_port, $dst_addr);

   # Check the global socket list to see if we already have a
   # socket bound to this local address.
   
   if (!exists($SOCKETS->{$this->[_SRCADDR]})) {

      my $socket = IO::Socket::INET->new(
         Proto => 'udp', Type => SOCK_DGRAM
      );

      if (!defined($socket)) {
         $this->_error('socket(): %s', $!);
         return wantarray ? (undef, $this->[_ERROR]) : undef;
      }

      DEBUG_INFO('opened socket [%d]', $socket->fileno);

      # Bind the socket to the local address
      if (!CORE::bind($socket, $this->[_SRCADDR])) {
         $this->_error('bind(): %s', $!);
         return wantarray ? (undef, $this->[_ERROR]) : undef;
      }

      # Add the socket to the global socket list with a 
      # reference count to track when to close the socket.

      $SOCKETS->{$this->[_SRCADDR]} = [$socket, 1];
 
   } else {

      DEBUG_INFO(
         'reused socket [%d]', $SOCKETS->{$this->[_SRCADDR]}->[0]->fileno
      );

      # Bump up the reference count
      $SOCKETS->{$this->[_SRCADDR]}->[1]++;

   }

   # Assign the socket to the object
   $this->[_SOCKET] = $SOCKETS->{$this->[_SRCADDR]}->[0];      

   # Return the object and empty error message (in list context)
   wantarray ? ($this, '') : $this;
}

sub send
{
   $_[0]->_error_clear;

   if (length($_[1]) > $_[0]->[_MAXSIZE]) {
      return $_[0]->_error('Message size exceeded maxMsgSize');
   }

   $_[0]->[_SOCKET]->send($_[1], 0, $_[0]->[_DSTADDR]) || $_[0]->_error($!);
}

sub recv
{
   $_[0]->_error_clear;

   $_[0]->[_SOCKET]->recv($_[1], $MAX_SIZE_MSG, 0) || $_[0]->_error($!);
}

sub max_msg_size
{
   $_[0]->_error_clear;

   if (@_ == 2) {
      if ($_[1] =~ /^\d+$/) {
         if (($_[1] >= MSG_SIZE_MINIMUM) && ($_[1] <= MSG_SIZE_MAXIMUM)) {
            $_[0]->[_MAXSIZE] = $_[1];
            $MAX_SIZE_MSG = $_[1] if ($_[1] > $MAX_SIZE_MSG);
         } else {
            return $_[0]->_error(
               'Invalid maxMsgSize value [%s], range %d - %d octets',
               $_[1], MSG_SIZE_MINIMUM, MSG_SIZE_MAXIMUM
            );
         }
      } else {
         return $_[0]->_error('Expected positive numeric maxMsgSize value');
      }
   }

   $_[0]->[_MAXSIZE];
}

sub timeout
{
   $_[0]->_error_clear;

   if (@_ == 2) {
      if ($_[1] =~ /^\d+(\.\d+)?$/) {
         if (($_[1] >= TIMEOUT_MINIMUM) && ($_[1] <= TIMEOUT_MAXIMUM)) {
            $_[0]->[_TIMEOUT] = $_[1];
         } else {
            return $_[0]->_error(
               'Invalid timeout value [%s], range %03.01f - %03.01f seconds',
               $_[1], TIMEOUT_MINIMUM, TIMEOUT_MAXIMUM 
            );
         }
      } else {
         return $_[0]->_error('Expected positive numeric timeout value');
      }
   }

   $_[0]->[_TIMEOUT]; 
}

sub retries 
{
   $_[0]->_error_clear;

   if (@_ == 2) {
      if ($_[1] =~ /^\d+$/) {
         if (($_[1] >= RETRIES_MINIMUM) && ($_[1] <= RETRIES_MAXIMUM)) {
            $_[0]->[_RETRIES] = $_[1];
         } else {
            return $_[0]->_error(
               'Invalid retries value [%s], range %d - %d', 
               $_[1], RETRIES_MINIMUM, RETRIES_MAXIMUM 
            );
         }
      } else {
         return $_[0]->_error('Expected positive numeric retries value');
      }
   }

   $_[0]->[_RETRIES];
}

sub srcaddr
{
   my $srcaddr = (sockaddr_in($_[0]->[_SRCADDR]))[1]; 

   if ($srcaddr eq INADDR_ANY) {
      eval {
         $srcaddr = scalar(gethostbyname(&Sys::Hostname::hostname())); 
      };
      $srcaddr = INADDR_ANY if ($@);
   }

   $srcaddr;
}

sub srcport
{
   (sockaddr_in($_[0]->[_SRCADDR]))[0];
}

sub srchost
{
   inet_ntoa($_[0]->srcaddr);
}

sub dstaddr
{
   (sockaddr_in($_[0]->[_DSTADDR]))[1];
}

sub dstport
{
   (sockaddr_in($_[0]->[_DSTADDR]))[0];
}

sub dsthost
{
   inet_ntoa((sockaddr_in($_[0]->[_DSTADDR]))[1]);
}

sub dstname
{
   $_[0]->[_DSTNAME];
}

sub recvaddr
{
   $_[0]->[_SOCKET]->peeraddr;
}

sub recvport
{
   $_[0]->[_SOCKET]->peerport;
}

sub recvhost
{
   $_[0]->[_SOCKET]->peerhost;
}

sub socket
{
   $_[0]->[_SOCKET];
}

sub error
{
   $_[0]->[_ERROR] || '';
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? 1 : 0 : $DEBUG;
}

sub DESTROY
{
   # Decrement the reference count and clear the global reference
   # to the source address if no one is using it. 

   return unless exists($SOCKETS->{$_[0]->[_SRCADDR]});

   if (--$SOCKETS->{$_[0]->[_SRCADDR]}->[1] < 1) {
      delete($SOCKETS->{$_[0]->[_SRCADDR]});
   }
}

# [private methods] ---------------------------------------------------------- 

sub _getservbyname($)
{
   return unless (@_ == 1);

   if ($_[0] !~ /^\d+$/) {
      getservbyname($_[0], 'udp');
   } elsif ($_[0] < 65535) {
      $_[0];
   } else {
      return;
   } 
}

sub _error
{
   my $this = shift;

   if (!defined($this->[_ERROR])) {
      $this->[_ERROR] = sprintf(shift(@_), @_);
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
   $_[0]->[_ERROR] = undef;
}

sub DEBUG_INFO
{
   return unless $DEBUG;

   printf(
      sprintf('debug: [%d] %s(): ', (caller(0))[2], (caller(1))[3]) .
      shift(@_) .
      "\n",
      @_
   );

   $DEBUG;
}

# ============================================================================
1; # [end Net::SNMP::Transport::UDP]
