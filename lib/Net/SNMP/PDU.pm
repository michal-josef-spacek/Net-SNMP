# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::PDU;

# $Id: PDU.pm,v 1.4 2002/05/06 12:30:37 dtown Exp $

# Object used to represent a SNMP PDU. 

# Copyright (c) 2001-2002 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Net::SNMP::Message qw(:ALL);

## Version of the Net::SNMP::PDU module

our $VERSION = v1.0.2;

## Handle importing/exporting of symbols

use Exporter();

our @ISA = qw(Net::SNMP::Message Exporter);

sub import
{
   Net::SNMP::Message->export_to_level(1, @_);
}

## Package variables

our $DEBUG = FALSE;  # Debug flag

## Initialize the global request-id/msgID.  

our $REQUEST_ID = int(rand((2**16) - 1) + (time() & 0xff));


# [public methods] -----------------------------------------------------------

sub new
{
   my $class = shift;

   # We play some games here to allow us to "convert" a Message into a PDU. 

   my $this = ref($_[0]) ? bless shift(@_), $class : $class->SUPER::new;

   # Override or initialize fields inherited from the base class
 
   $this->{_error_status} = 0;
   $this->{_error_index}  = 0;
   $this->{_scoped_pdu}   = FALSE;
   $this->{_translate}    = TRANSLATE_ALL;

   my (%argv) = @_;

   # Validate the passed arguments

   foreach (keys %argv) {
      if (/^-?callback$/i) {
         $this->callback($argv{$_});
      } elsif (/^-?contextengineid/i) {
         $this->context_engine_id($argv{$_});
      } elsif (/^-?contextname/i) {
         $this->context_name($argv{$_});
      } elsif (/^-?debug$/i) {
         $this->debug($argv{$_});
      } elsif (/^-?leadingdot$/i) {
         $this->leading_dot($argv{$_});
      } elsif (/^-?maxmsgsize$/i) {
         $this->max_msg_size($argv{$_});
      } elsif (/^-?security$/i) {
         $this->security($argv{$_});
      } elsif (/^-?translate$/i) {
         $this->{_translate} = $argv{$_};
      } elsif (/^-?transport$/i) {
         $this->transport($argv{$_});
      } elsif (/^-?version$/i) {
         $this->version($argv{$_});
      } else {
         $this->_error("Invalid argument '%s'", $_);
      }
      if (defined($this->{_error})) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }
   }

   if (!defined($this->{_transport})) {
      $this->_error('No Transport Layer defined');
      return wantarray ? (undef, $this->{_error}) : undef;
   }

   return wantarray ? ($this, '') : $this;
}

sub prepare_get_request
{
#  my ($this, $oids) = @_;

   $_[0]->_error_clear;

   $_[0]->_prepare_pdu(GET_REQUEST, $_[0]->_create_oid_null_pairs($_[1]));
}

sub prepare_get_next_request
{
#  my ($this, $oids) = @_; 

   $_[0]->_error_clear;

   $_[0]->_prepare_pdu(GET_NEXT_REQUEST, $_[0]->_create_oid_null_pairs($_[1]));
}

sub prepare_set_request
{
#  my ($this, $trios) = @_; 

   $_[0]->_error_clear;

   $_[0]->_prepare_pdu(SET_REQUEST, $_[0]->_create_oid_value_pairs($_[1]));
}

sub prepare_trap
{
#  my ($this, $enterprise, $addr, $generic, $specific, $time, $trios) = @_;

   $_[0]->_error_clear;

   return $_[0]->_error('Missing arguments for Trap-PDU') if (@_ < 6);

   # enterprise

   if (!defined($_[1])) {

      # Use iso(1).org(3).dod(6).internet(1).private(4).enterprises(1) 
      # for the default enterprise.

      $_[0]->{_enterprise} = '1.3.6.1.4.1';

   } elsif ($_[1] !~ /^\.?\d+\.\d+(?:\.\d+)*/) {
      return $_[0]->_error(
         'Expected enterprise as an OBJECT IDENTIFIER in dotted notation'
      );
   } else {
      $_[0]->{_enterprise} = $_[1];
   }

   # agent-addr

   if (!defined($_[2])) {

      # See if we can get the agent-addr from the Transport
      # Layer.  If not, we return an error.

      if (defined($_[0]->{_transport})) {
         $_[0]->{_agent_addr} = $_[0]->{_transport}->srchost;
      }
      if ((!exists($_[0]->{_agent_addr})) || 
          ($_[0]->{_agent_addr} eq '0.0.0.0'))
      {
         return $_[0]->_error('Unable to resolve local agent-addr');
      }
 
   } elsif ($_[2] !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
      return $_[0]->_error('Expected agent-addr in dotted notation');
   } else {
      $_[0]->{_agent_addr} = $_[2];
   } 

   # generic-trap

   if (!defined($_[3])) {

      # Use enterpriseSpecific(6) for the generic-trap type.
      $_[0]->{_generic_trap} = ENTERPRISE_SPECIFIC;

   } elsif ($_[3] !~ /^\d+$/) {
      return $_[0]->_error('Expected positive numeric generic-trap type');
   } else {
      $_[0]->{_generic_trap} = $_[3];
   }

   # specific-trap

   if (!defined($_[4])) {
      $_[0]->{_specific_trap} = 0;
   } elsif ($_[4] !~ /^\d+$/) {
      return $_[0]->_error('Expected positive numeric specific-trap type');
   } else {
      $_[0]->{_specific_trap} = $_[4];
   }

   # time-stamp

   if (!defined($_[5])) {

      # Use the "uptime" of the script for the time-stamp.
      $_[0]->{_time_stamp} = ((time() - $^T) * 100);

   } elsif ($_[5] !~ /^\d+$/) {
      return $_[0]->_error('Expected positive numeric time-stamp');
   } else {
      $_[0]->{_time_stamp} = $_[5];
   }

   $_[0]->_prepare_pdu(TRAP, $_[0]->_create_oid_value_pairs($_[6]));
}

sub prepare_get_bulk_request
{
#  my ($this, $repeaters, $repetitions, $oids) = @_;

   $_[0]->_error_clear;

   return $_[0]->_error('Missing arguments for GetBulkRequest-PDU') if (@_ < 3);

   # non-repeaters

   if (!defined($_[1])) {
      $_[0]->{_error_status} = 0;
   } elsif ($_[1] !~ /^\d+$/) {
      return $_[0]->_error('Expected positive numeric non-repeaters value');
   } elsif ($_[1] > 2147483647) { 
      return $_[0]->_error('Exceeded maximum non-repeaters value [2147483647]');
   } else {
      $_[0]->{_error_status} = $_[1];
   }

   # max-repetitions

   if (!defined($_[2])) {
      $_[0]->{_error_index} = 0;
   } elsif ($_[2] !~ /^\d+$/) {
      return $_[0]->_error('Expected positive numeric max-repetitions value');
   } elsif ($_[2] > 2147483647) {
      return $_[0]->_error(
         'Exceeded maximum max-repetitions value [2147483647]'
      );
   } else {
      $_[0]->{_error_index} = $_[2];
   }

   # Some sanity checks

   if (defined($_[3]) && (ref($_[3]) eq 'ARRAY')) {

      if ($_[0]->{_error_status} > @{$_[3]}) {
         return $_[0]->_error(
            'Non-repeaters greater than the number of variable-bindings'
         );
      }

      if (($_[0]->{_error_status} == @{$_[3]}) && ($_[0]->{_error_index} != 0))
      {
         return $_[0]->_error( 
            'Non-repeaters equals the number of variable-bindings and ' .
            'max-repetitions is not equal to zero'
         );
      }
   }

   $_[0]->_prepare_pdu(GET_BULK_REQUEST, $_[0]->_create_oid_null_pairs($_[3]));
}

sub prepare_inform_request
{
#  my ($this, $trios) = @_;

   $_[0]->_error_clear;

   $_[0]->_prepare_pdu(INFORM_REQUEST, $_[0]->_create_oid_value_pairs($_[1]));
}

sub prepare_snmpv2_trap
{
#  my ($this, $trios) = @_;

   $_[0]->_error_clear;

   $_[0]->_prepare_pdu(SNMPV2_TRAP, $_[0]->_create_oid_value_pairs($_[1]));
}

sub prepare_report
{
#  my ($this, $trios) = @_;

   $_[0]->_error_clear;

   $_[0]->_prepare_pdu(REPORT, $_[0]->_create_oid_value_pairs($_[1]));
}

sub process_pdu
{
   $_[0]->_process_pdu;
}

sub process_pdu_sequence
{
   $_[0]->_process_pdu_sequence;
}

sub process_var_bind_list
{
   $_[0]->_process_var_bind_list;
}

sub expect_response
{
   if (($_[0]->{_pdu_type} == GET_RESPONSE) ||
       ($_[0]->{_pdu_type} == TRAP)         ||
       ($_[0]->{_pdu_type} == SNMPV2_TRAP)  ||
       ($_[0]->{_pdu_type} == REPORT)) 
   {
      return FALSE;
   }

   TRUE;
}

sub pdu_type
{
   $_[0]->{_pdu_type};
}

sub request_id
{
   $_[0]->{_request_id};
}

sub error_status
{
   $_[0]->{_error_status};
}

sub error_index
{
   $_[0]->{_error_index};
}

sub enterprise
{
   $_[0]->{_enterprise}; 
}

sub agent_addr
{
   $_[0]->{_agent_addr};
}

sub generic_trap
{
   $_[0]->{_generic_trap};
}

sub specific_trap
{
   $_[0]->{_specific_trap};
}

sub time_stamp
{
   $_[0]->{_time_stamp};
}

sub var_bind_list
{
   return if defined($_[0]->{_error});

   (@_ == 2) ? $_[0]->{_var_bind_list} = $_[1] : $_[0]->{_var_bind_list}; 
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

# [private methods] ----------------------------------------------------------

sub _prepare_pdu
{
#  my ($this, $type, $var_bind_list) = @_;

   # Do not do anything if there has already been an error
   return $_[0]->_error if defined($_[0]->{_error});

   # Make sure the PDU type was passed
   return $_[0]->_error('No SNMP PDU type defined') unless (@_ > 0);

   # Set the PDU type
   $_[0]->{_pdu_type} = $_[1];

   # Clear the buffer
   $_[0]->_buffer_get;

   # Make sure the request-id has been set
   if (!exists($_[0]->{_request_id})) {
      $_[0]->{_request_id} = _create_request_id();
   }

   # We need to encode eveything in reverse order so the
   # objects end up in the correct place.

   # Encode the variable-bindings
   if (!defined($_[0]->_prepare_var_bind_list($_[2] || []))) {
      return $_[0]->_error;
   }
   
   if ($_[0]->{_pdu_type} != TRAP) { # PDU::=SEQUENCE

      # error-index/max-repetitions::=INTEGER 
      if (!defined($_[0]->prepare(INTEGER, $_[0]->{_error_index}))) {
         return $_[0]->_error;
      }

      # error-status/non-repeaters::=INTEGER
      if (!defined($_[0]->prepare(INTEGER, $_[0]->{_error_status}))) {
         return $_[0]->_error;
      }

      # request-id::=INTEGER  
      if (!defined($_[0]->prepare(INTEGER, $_[0]->{_request_id}))) {
         return $_[0]->_error;
      }

   } else { # Trap-PDU::=IMPLICIT SEQUENCE

      # time-stamp::=TimeTicks 
      if (!defined($_[0]->prepare(TIMETICKS, $_[0]->{_time_stamp}))) {
         return $_[0]->_error;
      }

      # specific-trap::=INTEGER 
      if (!defined($_[0]->prepare(INTEGER, $_[0]->{_specific_trap}))) {
         return $_[0]->_error;
      }

      # generic-trap::=INTEGER  
      if (!defined($_[0]->prepare(INTEGER, $_[0]->{_generic_trap}))) {
         return $_[0]->_error;
      }

      # agent-addr::=NetworkAddress 
      if (!defined($_[0]->prepare(IPADDRESS, $_[0]->{_agent_addr}))) {
         return $_[0]->_error;
      }

      # enterprise::=OBJECT IDENTIFIER 
      if (!defined($_[0]->prepare(OBJECT_IDENTIFIER, $_[0]->{_enterprise}))) {
         return $_[0]->_error;
      }

   }

   # PDUs::=CHOICE 
   $_[0]->prepare($_[0]->{_pdu_type}, $_[0]->_buffer_get);
}

sub _prepare_var_bind_list
{
   my ($this, $var_bind) = @_;

   # The passed array is expected to consist of groups of four values
   # consisting of two sets of ASN.1 types and their values.

   if (@{$var_bind} % 4) {
      return $this->_error(
         'Invalid number of VarBind parameters [%d]', scalar(@{$var_bind})
      );
   }

   # Encode the objects from the end of the list, so they are wrapped
   # into the packet as expected.  Also, check to make sure that the
   # OBJECT IDENTIFIER is in the correct place.

   my ($type, $value);
   my $buffer = $this->_buffer_get;

   while (@{$var_bind}) {

      # value::=ObjectSyntax
      $value = pop(@{$var_bind});
      $type  = pop(@{$var_bind});
      if (!defined($this->prepare($type, $value))) {
         return $this->_error;
      }

      # name::=ObjectName
      $value = pop(@{$var_bind});
      $type  = pop(@{$var_bind});
      if ($type != OBJECT_IDENTIFIER) {
         return $this->_error('Expected OBJECT IDENTIFIER in VarBindList');
      }
      if (!defined($this->prepare($type, $value))) {
         return $this->_error;
      }

      # VarBind::=SEQUENCE 
      if (!defined($this->prepare(SEQUENCE, $this->_buffer_get))) {
         return $this->_error;
      }
      substr($buffer, 0, 0) = $this->_buffer_get;
   }

   # VarBindList::=SEQUENCE OF VarBind
   $this->prepare(SEQUENCE, $buffer);
}

sub _create_oid_null_pairs
{
#  my ($this, $oids) = @_;

   return [] unless defined($_[1]);

   if (ref($_[1]) ne 'ARRAY') {
      return $_[0]->_error('Expected array reference for variable-bindings');
   }

   my $pairs = [];

   for (@{$_[1]}) {
      if (!/^\.?\d+\.\d+(?:\.\d+)*/) {
         return $_[0]->_error('Expected OBJECT IDENTIFIER in dotted notation');
      }
      push(@{$pairs}, OBJECT_IDENTIFIER, $_, NULL, '');
   }

   $pairs;
}

sub _create_oid_value_pairs
{
#  my ($this, $trios) = @_;

   return [] unless defined($_[1]);

   if (ref($_[1]) ne 'ARRAY') {
      return $_[0]->_error('Expected array reference for variable-bindings');
   }

   if (@{$_[1]} % 3) {
      return $_[0]->_error(
         'Expected [OBJECT IDENTIFIER, ASN.1 type, object value] combination'
      );
   }

   my $pairs = [];

   for (my $i = 0; $i < $#{$_[1]}; $i += 3) {
      if ($_[1]->[$i] !~ /^\.?\d+\.\d+(?:\.\d+)*/) {
         return $_[0]->_error('Expected OBJECT IDENTIFIER in dotted notation');
      }
      push(@{$pairs},
         OBJECT_IDENTIFIER, $_[1]->[$i], $_[1]->[$i+1], $_[1]->[$i+2]
      );
   }

   $pairs;
}

sub _process_pdu
{
   return $_[0]->_error unless defined($_[0]->_process_pdu_sequence);

   $_[0]->_process_var_bind_list;
}

sub _process_pdu_sequence
{
#  my ($this) = @_;

   # PDUs::=CHOICE
   if (!defined($_[0]->{_pdu_type} = $_[0]->process)) {
      return $_[0]->_error;
   }

   if ($_[0]->{_pdu_type} != TRAP) { # PDU::=SEQUENCE

      # request-id::=INTEGER
      if (!defined($_[0]->{_request_id} = $_[0]->process(INTEGER))) {
         return $_[0]->_error;
      }
      # error-status::=INTEGER
      if (!defined($_[0]->{_error_status} = $_[0]->process(INTEGER))) {
         return $_[0]->_error;
      }
      # error-index::=INTEGER
      if (!defined($_[0]->{_error_index} = $_[0]->process(INTEGER))) {
         return $_[0]->_error;
      }

      # Indicate that we have an SNMP error
      if (($_[0]->{_error_status}) || ($_[0]->{_error_index})) {
         $_[0]->_error(
            'Received %s error-status at error-index %d',
            _error_status_itoa($_[0]->{_error_status}), $_[0]->{_error_index}
         );
      } 

   } else { # Trap-PDU::=IMPLICIT SEQUENCE

      # enterprise::=OBJECT IDENTIFIER
      if (!defined($_[0]->{_enterprise} = $_[0]->process(OBJECT_IDENTIFIER))) {
         return $_[0]->_error;
      }
      # agent-addr::=NetworkAddress
      if (!defined($_[0]->{_agent_addr} = $_[0]->process(IPADDRESS))) {
         return $_[0]->_error;
      }
      # generic-trap::=INTEGER
      if (!defined($_[0]->{_generic_trap} = $_[0]->process(INTEGER))) {
         return $_[0]->_error;
      }
      # specific-trap::=INTEGER
      if (!defined($_[0]->{_specific_trap} = $_[0]->process(INTEGER))) {
         return $_[0]->_error;
      }
      # time-stamp::=TimeTicks
      if (!defined($_[0]->{_time_stamp} = $_[0]->process(TIMETICKS))) {
         return $_[0]->_error;
      }

   }

   TRUE;
}

sub _process_var_bind_list
{
#  my ($this) = @_;

   my $value;

   # VarBindList::=SEQUENCE
   if (!defined($value = $_[0]->process(SEQUENCE))) {
      return $_[0]->_error;
   }

   # Using the length of the VarBindList SEQUENCE, 
   # calculate the end index.

   my $end = $_[0]->index + $value;

   $_[0]->{_var_bind_list} = {};

   my $oid;

   while ($_[0]->index < $end) {

      # VarBind::=SEQUENCE
      if (!defined($_[0]->process(SEQUENCE))) {
         return $_[0]->_error;
      }
      # name::=ObjectName
      if (!defined($oid = $_[0]->process(OBJECT_IDENTIFIER))) {
         return $_[0]->_error;
      }
      # value::=ObjectSyntax
      if (!defined($value = $_[0]->process)) {
         return $_[0]->_error;
      }

      # Create a hash consisting of the OBJECT IDENTIFIER as a
      # key and the ObjectSyntax as the value.  If there is a
      # duplicate OBJECT IDENTIFIER in the VarBindList, we pad
      # that OBJECT IDENTIFIER with spaces to make a unique
      # key in the hash.

      while (exists($_[0]->{_var_bind_list}->{$oid})) {
         $oid .= ' '; # Pad with spaces
      }

      DEBUG_INFO("{ %s => %s }", $oid, $value);
      $_[0]->{_var_bind_list}->{$oid} = $value;

   }

   # Return an error based on the contents of the VarBindList
   # if we received a Report-PDU.

   return $_[0]->_report_pdu_error if ($_[0]->{_pdu_type} == REPORT);

   # Return the var_bind_list hash
   $_[0]->{_var_bind_list};
}

sub _create_request_id()
{
   (++$REQUEST_ID > ((2**31) - 1)) ? $REQUEST_ID = ($^T & 0xff) : $REQUEST_ID;
}

{
   my @error_status = qw(
      noError
      tooBig
      noSuchName
      badValue
      readOnly
      genError
      noAccess
      wrongType
      wrongLength
      wrongEncoding
      wrongValue
      noCreation
      inconsistentValue
      resourceUnavailable
      commitFailed
      undoFailed
      authorizationError
      notWritable
      inconsistentName
   );

   sub _error_status_itoa
   {
      return '??' unless (@_ == 1);

      if (($_[0] > $#error_status) || ($_[0] < 0)) {
         return sprintf("??(%d)", $_[0]);
      }

      sprintf("%s(%d)", $error_status[$_[0]], $_[0]);
   }
}

{
   my %report_oids = (
      '1.3.6.1.6.3.11.2.1.1' => 'snmpUnknownSecurityModels',
      '1.3.6.1.6.3.11.2.1.2' => 'snmpInvalidMsgs',
      '1.3.6.1.6.3.11.2.1.3' => 'snmpUnknownPDUHandlers',
      '1.3.6.1.6.3.15.1.1.1' => 'usmStatsUnsupportedSecLevels',
      '1.3.6.1.6.3.15.1.1.2' => 'usmStatsNotInTimeWindows',
      '1.3.6.1.6.3.15.1.1.3' => 'usmStatsUnknownUserNames',
      '1.3.6.1.6.3.15.1.1.4' => 'usmStatsUnknownEngineIDs',
      '1.3.6.1.6.3.15.1.1.5' => 'usmStatsWrongDigests',
      '1.3.6.1.6.3.15.1.1.6' => 'usmStatsDecryptionErrors'
   );

   sub _report_pdu_error
   {
      my ($this) = @_;

      # Remove the leading dot (if present) and replace
      # the dotted notation of the OBJECT IDENTIFIER
      # with the text representation if it is known.

      my $count = 0;
      my %var_bind_list;

      map {

         my $oid = $_;
         $oid =~ s/^\.//;

         $count++;

         map { $oid =~ s/\Q$_/$report_oids{$_}/; } keys(%report_oids);

         $var_bind_list{$oid} = $this->{_var_bind_list}->{$_};

      } keys(%{$this->{_var_bind_list}});

     
      if ($count == 1) {
 
         # Return the OBJECT IDENTIFIER and value.
            
         my $oid = (keys(%var_bind_list))[0];

         $this->_error(
            'Received %s Report-PDU with value %s', $oid, $var_bind_list{$oid}
         );
 
      } elsif ($count > 1) {

         # Return a list of OBJECT IDENTIFIERs.

         $this->_error(
            'Received Report-PDU [%s]', join(', ', keys(%var_bind_list))
         );

      } else {

         $this->_error('Received empty Report-PDU');

      }
   }
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
1; # [end Net::SNMP::Message]
