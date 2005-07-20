# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::Transport::TCP;

# $Id: TCP.pm,v 1.1 2005/07/20 13:53:07 dtown Exp $

# Object that handles the TCP/IPv4 Transport Domain for the SNMP Engine.

# Copyright (c) 2004-2005 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Net::SNMP::Transport qw( :_array DOMAIN_TCPIPV4 MSG_SIZE_MAXIMUM FALSE );

use Net::SNMP::Message qw( SEQUENCE );

use IO::Socket::INET qw(
   INADDR_ANY INADDR_LOOPBACK inet_aton inet_ntoa sockaddr_in
);

## Version of the Net::SNMP::Transport::TCP module

our $VERSION = v1.0.1;

## Handle importing/exporting of symbols

use Exporter();

our @ISA = qw( Net::SNMP::Transport Exporter );

sub import
{
   Net::SNMP::Transport->export_to_level(1, @_);
}

## RFC 3411 - snmpEngineMaxMessageSize::=INTEGER (484..2147483647)

sub MSG_SIZE_DEFAULT_TCP4() { 1460 } # Ethernet(1500) - IPv4(20) - TCP(20)

# [public methods] -----------------------------------------------------------

sub new
{
   shift->SUPER::_new(@_);
}

sub accept
{
   my ($this) = @_;

   $this->_error_clear;

   my $socket = $this->[_SOCKET]->accept;

   if (!defined($socket)) {
      return $this->_error($! || 'Unknown accept() error');
   }

   DEBUG_INFO('opened %s socket [%d]', $this->name, $socket->fileno);

   # Create a new object by copying the current object.

   my $new = bless [ @{$this} ], ref($this); 

   # Now update the appropriate fields.

   $new->[_DSTNAME] = $socket->peerhost;
   $new->[_SOCKET]  = $socket;
   $new->[_DSTADDR] = $socket->peername;
   $new->_reasm_reset;

   # Return the new object.
   $new;
}

sub send
{
#  my ($this, $buffer) = @_;

   $_[0]->_error_clear;

   if (length($_[1]) > $_[0]->[_MAXSIZE]) {
      return $_[0]->_error('Message size exceeded maxMsgSize');
   }

   if (!defined($_[0]->[_SOCKET]->connected)) {
      return $_[0]->_error(
         "Not connected to remote host '%s'", $_[0]->[_DSTNAME]
      );
   }

   $_[0]->[_SOCKET]->send($_[1], 0) || $_[0]->_error($!);
}

sub recv
{
#  my ($this, $buffer) = @_;

   $_[0]->_error_clear;

   if (!defined($_[0]->[_SOCKET]->connected)) {
      $_[0]->_reasm_reset;
      return $_[0]->_error(
         "Not connected to remote host '%s'", $_[0]->[_DSTNAME]
      );
   }

   # RCF 3430 Section 2.1 - "It is possible that the underlying TCP 
   # implementation delivers byte sequences that do not align with 
   # SNMP message boundaries.  A receiving SNMP engine MUST therefore 
   # use the length field in the BER-encoded SNMP message to separate 
   # multiple requests sent over a single TCP connection (framing).  
   # An SNMP engine which looses framing (for example due to ASN.1 
   # parse errors) SHOULD close the TCP connection."

   # If the reassembly bufer is empty then there is no partial message
   # waiting for completion.  We must then process the message length
   # to properly determine how much data to receive.

   my $sa;

   if ($_[0]->[_REASM_BUFFER] eq '') {

      my ($msg, $error) = Net::SNMP::Message->new();

      if (!defined($msg)) {
         return $_[0]->_error('Failed to create Message object [%s]', $error);
      }

      # Read enough data to parse the ASN.1 type and length.

      $sa = $_[0]->[_SOCKET]->recv($_[0]->[_REASM_BUFFER], 6, 0);

      if ((!defined($sa)) || ($!)) {
         return $_[0]->_error($! || 'Unknown recv() error');   
      } elsif (!length($_[0]->[_REASM_BUFFER])) {
         return $_[0]->_error(
            "Connection closed by remote host '%s'", $_[0]->[_DSTNAME]
         );
      }
 
      $msg->append($_[0]->[_REASM_BUFFER]);

      $_[0]->[_REASM_LENGTH] = $msg->process(SEQUENCE) || 0;   

      if ((!$_[0]->[_REASM_LENGTH]) || 
           ($_[0]->[_REASM_LENGTH] > MSG_SIZE_MAXIMUM)) 
      {
         $_[0]->_reasm_reset;
         return $_[0]->_error(
            "Message framing lost with remote host '%s'", $_[0]->[_DSTNAME]
         );
      }

      # Add in the bytes parsed to define the expected message length.
      $_[0]->[_REASM_LENGTH] += $msg->index;

   }

   # Setup a temporary buffer for the message and set the length
   # based upon the contents of the reassembly buffer. 

   my $buf = '';
   my $buf_len = length($_[0]->[_REASM_BUFFER]);

   # Read the rest of the message.

   $sa = $_[0]->[_SOCKET]->recv($buf, ($_[0]->[_REASM_LENGTH] - $buf_len), 0);

   if ((!defined($sa)) || ($!)) {
      $_[0]->_reasm_reset;
      return $_[0]->_error($! || 'Unknown recv() error');
   } elsif (!length($buf)) {
      $_[0]->_reasm_reset;
      return $_[0]->_error(
         "Connection closed by remote host '%s'", $_[0]->[_DSTNAME]
      );
   }

   # Now see if we have the complete message.  If it is not complete,
   # success is returned with an empty buffer.  The application must
   # continue to call recv() until the message is reassembled.

   $buf_len += length($buf);
   $_[0]->[_REASM_BUFFER] .= $buf;

   if ($buf_len < $_[0]->[_REASM_LENGTH]) {
      DEBUG_INFO(
         'message is incomplete (expect %u bytes, have %u bytes)',
         $_[0]->[_REASM_LENGTH], $buf_len
      );
      $_[1] = '';
      return $sa || $_[0]->[_SOCKET]->connected;
   } 

   # Validate the maxMsgSize.
   if ($buf_len > $_[0]->[_MAXSIZE]) {
      $_[0]->_reasm_reset;
      return $_[0]->_error('Incoming message size exceeded maxMsgSize');
   }  

   # The message is complete, copy the buffer to the caller.
   $_[1] = $_[0]->[_REASM_BUFFER];

   # Clear the reassembly buffer and length.
   $_[0]->_reasm_reset;
 
   $sa || $_[0]->[_SOCKET]->connected;
}

sub connectionless
{
   FALSE;
}

sub domain
{
   DOMAIN_TCPIPV4;
}

sub name 
{
   'TCP/IPv4';
}

# [private methods] ----------------------------------------------------------

sub _msg_size_default
{
   MSG_SIZE_DEFAULT_TCP4;
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
      getservbyname($serv, 'tcp');
   } elsif ($serv <= 65535) {
      $serv;
   } else {
      return;
   }
}

sub _socket_create
{
   shift;
   IO::Socket::INET->new(Proto => 'tcp', @_);
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
1; # [end Net::SNMP::Transport::TCP]
