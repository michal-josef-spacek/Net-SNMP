# -*- mode: perl -*- 
# ============================================================================

package Net::SNMP::Security::Community;

# $Id: Community.pm,v 1.2 2002/01/01 14:03:44 dtown Exp $

# Object that implements the SNMPv1/v2c Community-based Security Model.

# Copyright (c) 2001-2002 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

require Net::SNMP::Security;

use Net::SNMP::Message qw(
   OCTET_STRING SEQUENCE INTEGER SNMP_VERSION_1 SNMP_VERSION_2C TRUE FALSE
   SECURITY_MODEL_SNMPV1 SECURITY_MODEL_SNMPV2C
); 

## Version of the Net::SNMP::Security::Community module

our $VERSION = v1.0.1;

## Package variables

our $DEBUG = FALSE; 

## Inherit from Net::SNMP::Security

our @ISA = qw(Net::SNMP::Security);

# [public methods] -----------------------------------------------------------

sub new 
{
   my ($class, %argv) = @_;

   # Create a new data structure for the object
   my $this = bless {
      '_error'     => undef,           # Error message
      '_version'   => SNMP_VERSION_1,  # SNMP version
      '_community' => 'public'         # Community
   }, $class;

   # Now validate the passed arguments

   foreach (keys %argv) {
      if (/^-?community$/i) {
         $this->_community($argv{$_}); 
      } elsif (/^-?version$/i) {
         $this->_version($argv{$_});
      } else {
         $this->_error("Invalid argument '%s'", $_);
      }

      if (defined($this->{_error})) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }
   }

   # Return the object and an empty error message (in list context)
   wantarray ? ($this, '') : $this;
}

sub generate_request_msg
{
   my ($this, $pdu, $msg) = @_;

   # Clear any previous errors
   $this->_error_clear;

   return $this->_error('Required PDU and/or Message missing') unless (@_ == 3);

   if ($pdu->version != $this->{_version}) {
      return $this->_error('Invalid version [%d]', $pdu->version);
   }

   # Append the PDU
   if (!defined($msg->append($pdu->copy))) {
      return $this->_error($msg->error);
   }

   # community::=OCTET STRING
   if (!defined($msg->prepare(OCTET_STRING, $this->{_community}))) {
      return $this->_error($msg->error);
   }

   # version::=INTEGER
   if (!defined($msg->prepare(INTEGER, $this->{_version}))) {
      return $_[0]->_error($msg->error);
   }

   # message::=SEQUENCE
   if (!defined($msg->prepare(SEQUENCE, $msg->clear))) {
      return $_[0]->_error($msg->error);
   }

   # Return the message
   $msg;
}

sub process_incoming_msg
{
   my ($this, $msg) = @_;

   # Clear any previous errors
   $this->_error_clear;

   return $this->_error('Required Message missing') unless (@_ == 2);

   if ($msg->community ne $this->{_community}) {
      return $this->_error('Invalid community [%s]', $msg->community);
   }

   TRUE;
}

sub security_model
{
   # RFC 2571 - SnmpSecurityModel::=TEXTUAL-CONVENTION 

   if ($_[0]->{_version} == SNMP_VERSION_2C) {
      SECURITY_MODEL_SNMPV2C;
   } else {
      SECURITY_MODEL_SNMPV1; 
   }
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

# [private methods] ----------------------------------------------------------

sub _community
{
   return $_[0]->_error('Community not defined') unless defined($_[1]);
   
   $_[0]->{_community} = $_[1];
}

sub _version
{
   if (($_[1] != SNMP_VERSION_1) && ($_[1] != SNMP_VERSION_2C)) {
      return $_[0]->_error('Invalid SNMP version specified [%s]', $_[1]);
   }

   $_[0]->{_version} = $_[1];
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
1; # [end Net::SNMP::Security::Community]

