# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::Transport::UDP;

# $Id: UDP.pm,v 2.0 2004/07/20 13:27:44 dtown Exp $

# Object that handles the UDP/IPv4 Transport Domain for the SNMP Engine.

# Copyright (c) 2001-2004 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Net::SNMP::Transport qw( :_array DOMAIN_UDP );

use IO::Socket::INET qw(
   INADDR_ANY INADDR_LOOPBACK inet_aton inet_ntoa sockaddr_in
);

## Version of the Net::SNMP::Transport::UDP module

our $VERSION = v2.0.0;

## Handle importing/exporting of symbols

use Exporter();

our @ISA = qw( Net::SNMP::Transport Exporter );

sub import
{
   Net::SNMP::Transport->export_to_level(1, @_);
}

## RFC 3411 - snmpEngineMaxMessageSize::=INTEGER (484..2147483647)

sub MSG_SIZE_DEFAULT_UDP4() { 1472 } # Ethernet(1500) - IPv4(20) - UDP(8)

# [public methods] -----------------------------------------------------------

sub new
{
   shift->SUPER::_new(@_);
}

sub send
{
#  my ($this, $buffer) = @_;

   $_[0]->_error_clear;

   if (length($_[1]) > $_[0]->[_MAXSIZE]) {
      return $_[0]->_error('Message size exceeded maxMsgSize');
   }
  
   $_[0]->[_SOCKET]->send($_[1], 0, $_[0]->[_DSTADDR]) || $_[0]->_error($!);
}

sub recv
{
#  my ($this, $buffer) = @_;

   $_[0]->_error_clear;

   my $sa = $_[0]->[_SOCKET]->recv($_[1], $_[0]->_shared_maxsize, 0);

   if (!defined($sa)) {
      return $_[0]->_error($! || 'Unknown recv() error')
   }

   $sa;
}

sub domain
{
   DOMAIN_UDP;
}

sub name 
{
   'UDP/IPv4';
}

# [private methods] ----------------------------------------------------------

sub _msg_size_default
{
   MSG_SIZE_DEFAULT_UDP4;
}

sub _addr_any
{
   INADDR_ANY;
}

sub _addr_loopback
{
   INADDR_LOOPBACK;
}

sub _addr_aton
{
   inet_aton($_[1]);
}

sub _addr_ntoa
{
   inet_ntoa($_[1]);
} 

sub _addr_pack
{
   shift;
   sockaddr_in(@_);
}

sub _serv_aton
{
   my ($this, $serv) = @_;

   if ($serv !~ /^\d+$/) {
      getservbyname($serv, 'udp');
   } elsif ($serv <= 65535) {
      $serv;
   } else {
      return;
   }
}

sub _socket_create
{
   shift;
   IO::Socket::INET->new(Proto => 'udp', @_);
}

sub DEBUG_INFO
{
   return unless $Net::SNMP::Transport::DEBUG;

   printf(
      sprintf('debug: [%d] %s(): ', (caller(0))[2], (caller(1))[3]) .
      ((@_ > 1) ? shift(@_) : '%s') .
      "\n",
      @_
   );

   $Net::SNMP::Transport::DEBUG;
}

# ============================================================================
1; # [end Net::SNMP::Transport::UDP]
