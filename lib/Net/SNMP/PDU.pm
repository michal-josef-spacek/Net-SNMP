# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::PDU;

# $Id: PDU.pm,v 1.5 2003/05/06 11:00:46 dtown Exp $

# Object used to represent a SNMP PDU. 

# Copyright (c) 2001-2003 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Net::SNMP::Message qw(:ALL);

## Version of the Net::SNMP::PDU module

our $VERSION = v1.0.3;

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
   my ($this, $oids) = @_;

   $this->_error_clear;

   $this->_prepare_pdu(GET_REQUEST, $this->_create_oid_null_pairs($oids));
}

sub prepare_get_next_request
{
   my ($this, $oids) = @_; 

   $this->_error_clear;

   $this->_prepare_pdu(GET_NEXT_REQUEST, $this->_create_oid_null_pairs($oids));
}

sub prepare_get_response
{
   my ($this, $trios) = @_;

   $this->_error_clear;

   $this->_prepare_pdu(GET_RESPONSE, $this->_create_oid_value_pairs($trios));
}

sub prepare_set_request
{
   my ($this, $trios) = @_; 

   $this->_error_clear;

   $this->_prepare_pdu(SET_REQUEST, $this->_create_oid_value_pairs($trios));
}

sub prepare_trap
{
   my ($this, $enterprise, $addr, $generic, $specific, $time, $trios) = @_;

   $this->_error_clear;

   return $this->_error('Missing arguments for Trap-PDU') if (@_ < 6);

   # enterprise

   if (!defined($enterprise)) {

      # Use iso(1).org(3).dod(6).internet(1).private(4).enterprises(1) 
      # for the default enterprise.

      $this->{_enterprise} = '1.3.6.1.4.1';

   } elsif ($enterprise !~ /^\.?\d+\.\d+(?:\.\d+)*/) {
      return $this->_error(
         'Expected enterprise as an OBJECT IDENTIFIER in dotted notation'
      );
   } else {
      $this->{_enterprise} = $enterprise;
   }

   # agent-addr

   if (!defined($addr)) {

      # See if we can get the agent-addr from the Transport
      # Layer.  If not, we return an error.

      if (defined($this->{_transport})) {
         $this->{_agent_addr} = $this->{_transport}->srchost;
      }
      if (!exists($this->{_agent_addr}) || $this->{_agent_addr} eq '0.0.0.0') { 
         return $this->_error('Unable to resolve local agent-addr');
      }
 
   } elsif ($addr !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
      return $this->_error('Expected agent-addr in dotted notation');
   } else {
      $this->{_agent_addr} = $addr;
   } 

   # generic-trap

   if (!defined($generic)) {

      # Use enterpriseSpecific(6) for the generic-trap type.
      $this->{_generic_trap} = ENTERPRISE_SPECIFIC;

   } elsif ($generic !~ /^\d+$/) {
      return $this->_error('Expected positive numeric generic-trap type');
   } else {
      $this->{_generic_trap} = $generic;
   }

   # specific-trap

   if (!defined($specific)) {
      $this->{_specific_trap} = 0;
   } elsif ($specific !~ /^\d+$/) {
      return $this->_error('Expected positive numeric specific-trap type');
   } else {
      $this->{_specific_trap} = $specific;
   }

   # time-stamp

   if (!defined($time)) {

      # Use the "uptime" of the script for the time-stamp.
      $this->{_time_stamp} = ((time() - $^T) * 100);

   } elsif ($time !~ /^\d+$/) {
      return $this->_error('Expected positive numeric time-stamp');
   } else {
      $this->{_time_stamp} = $time;
   }

   $this->_prepare_pdu(TRAP, $this->_create_oid_value_pairs($trios));
}

sub prepare_get_bulk_request
{
   my ($this, $repeaters, $repetitions, $oids) = @_;

   $this->_error_clear;

   return $this->_error('Missing arguments for GetBulkRequest-PDU') if (@_ < 3);

   # non-repeaters

   if (!defined($repeaters)) {
      $this->{_error_status} = 0;
   } elsif ($repeaters !~ /^\d+$/) {
      return $this->_error('Expected positive numeric non-repeaters value');
   } elsif ($repeaters > 2147483647) { 
      return $this->_error('Exceeded maximum non-repeaters value [2147483647]');
   } else {
      $this->{_error_status} = $repeaters;
   }

   # max-repetitions

   if (!defined($repetitions)) {
      $this->{_error_index} = 0;
   } elsif ($repetitions !~ /^\d+$/) {
      return $this->_error('Expected positive numeric max-repetitions value');
   } elsif ($repetitions > 2147483647) {
      return $this->_error(
         'Exceeded maximum max-repetitions value [2147483647]'
      );
   } else {
      $this->{_error_index} = $repetitions;
   }

   # Some sanity checks

   if (defined($oids) && (ref($oids) eq 'ARRAY')) {

      if ($this->{_error_status} > @{$oids}) {
         return $this->_error(
            'Non-repeaters greater than the number of variable-bindings'
         );
      }

      if (($this->{_error_status} == @{$oids}) && (!$this->{_error_index})) {
         return $this->_error( 
            'Non-repeaters equals the number of variable-bindings and ' .
            'max-repetitions is not equal to zero'
         );
      }
   }

   $this->_prepare_pdu(GET_BULK_REQUEST, $this->_create_oid_null_pairs($oids));
}

sub prepare_inform_request
{
   my ($this, $trios) = @_;

   $this->_error_clear;

   $this->_prepare_pdu(INFORM_REQUEST, $this->_create_oid_value_pairs($trios));
}

sub prepare_snmpv2_trap
{
   my ($this, $trios) = @_;

   $this->_error_clear;

   $this->_prepare_pdu(SNMPV2_TRAP, $this->_create_oid_value_pairs($trios));
}

sub prepare_report
{
   my ($this, $trios) = @_;

   $this->_error_clear;

   $this->_prepare_pdu(REPORT, $this->_create_oid_value_pairs($trios));
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

   if (@_ == 2) {

      # The VarBindList HASH is being updated from an external
      # source.  We need to update the VarBind names ARRAY to
      # correspond to the new keys of the HASH.  If the updated
      # information is valid, we will use lexicographical ordering
      # for the ARRAY entries since we do not have a PDU to use
      # to determine the ordering. 

      if (!defined($_[1]) || (ref($_[1]) ne 'HASH')) {

         $_[0]->{_var_bind_names} = [];
         $_[0]->{_var_bind_list}  = undef;

      } else {

         @{$_[0]->{_var_bind_names}} =
            map  { $_->[0] }
            sort { $a->[1] cmp $b->[1] }
            map  {
               my $oid = $_;
               $oid =~ s/^\.//o;
               [$_, pack('N*', split('\.', $oid))]
            } keys(%{$_[1]});

         $_[0]->{_var_bind_list} = $_[1];

      }

   }

   $_[0]->{_var_bind_list};
}

sub var_bind_names
{
   return [] if defined($_[0]->{_error}) || !defined($_[0]->{_var_bind_names});

   $_[0]->{_var_bind_names};
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

# [private methods] ----------------------------------------------------------

sub _prepare_pdu
{
   my ($this, $type, $var_bind) = @_;

   # Do not do anything if there has already been an error
   return $this->_error if defined($this->{_error});

   # Make sure the PDU type was passed
   return $this->_error('No SNMP PDU type defined') unless (@_ > 0);

   # Set the PDU type
   $this->{_pdu_type} = $type;

   # Clear the buffer
   $this->_buffer_get;

   # Make sure the request-id has been set
   if (!exists($this->{_request_id})) {
      $this->{_request_id} = _create_request_id();
   }

   # We need to encode everything in reverse order so the
   # objects end up in the correct place.

   # Encode the variable-bindings
   if (!defined($this->_prepare_var_bind_list($var_bind || []))) {
      return $this->_error;
   }
   
   if ($this->{_pdu_type} != TRAP) { # PDU::=SEQUENCE

      # error-index/max-repetitions::=INTEGER 
      if (!defined($this->prepare(INTEGER, $this->{_error_index}))) {
         return $this->_error;
      }

      # error-status/non-repeaters::=INTEGER
      if (!defined($this->prepare(INTEGER, $this->{_error_status}))) {
         return $this->_error;
      }

      # request-id::=INTEGER  
      if (!defined($this->prepare(INTEGER, $this->{_request_id}))) {
         return $this->_error;
      }

   } else { # Trap-PDU::=IMPLICIT SEQUENCE

      # time-stamp::=TimeTicks 
      if (!defined($this->prepare(TIMETICKS, $this->{_time_stamp}))) {
         return $this->_error;
      }

      # specific-trap::=INTEGER 
      if (!defined($this->prepare(INTEGER, $this->{_specific_trap}))) {
         return $this->_error;
      }

      # generic-trap::=INTEGER  
      if (!defined($this->prepare(INTEGER, $this->{_generic_trap}))) {
         return $this->_error;
      }

      # agent-addr::=NetworkAddress 
      if (!defined($this->prepare(IPADDRESS, $this->{_agent_addr}))) {
         return $this->_error;
      }

      # enterprise::=OBJECT IDENTIFIER 
      if (!defined($this->prepare(OBJECT_IDENTIFIER, $this->{_enterprise}))) {
         return $this->_error;
      }

   }

   # PDUs::=CHOICE 
   $this->prepare($this->{_pdu_type}, $this->_buffer_get);
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
   my ($this, $oids) = @_;

   return [] unless defined($oids);

   if (ref($oids) ne 'ARRAY') {
      return $this->_error('Expected array reference for variable-bindings');
   }

   my $pairs = [];

   for (@{$oids}) {
      if (!/^\.?\d+\.\d+(?:\.\d+)*/) {
         return $this->_error('Expected OBJECT IDENTIFIER in dotted notation');
      }
      push(@{$pairs}, OBJECT_IDENTIFIER, $_, NULL, '');
   }

   $pairs;
}

sub _create_oid_value_pairs
{
   my ($this, $trios) = @_;

   return [] unless defined($trios);

   if (ref($trios) ne 'ARRAY') {
      return $this->_error('Expected array reference for variable-bindings');
   }

   if (@{$trios} % 3) {
      return $this->_error(
         'Expected [OBJECT IDENTIFIER, ASN.1 type, object value] combination'
      );
   }

   my $pairs = [];

   for (my $i = 0; $i < $#{$trios}; $i += 3) {
      if ($trios->[$i] !~ /^\.?\d+\.\d+(?:\.\d+)*/) {
         return $this->_error('Expected OBJECT IDENTIFIER in dotted notation');
      }
      push(@{$pairs},
         OBJECT_IDENTIFIER, $trios->[$i], $trios->[$i+1], $trios->[$i+2]
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
   my ($this) = @_;

   # PDUs::=CHOICE
   if (!defined($this->{_pdu_type} = $this->process)) {
      return $this->_error;
   }

   if ($this->{_pdu_type} != TRAP) { # PDU::=SEQUENCE

      # request-id::=INTEGER
      if (!defined($this->{_request_id} = $this->process(INTEGER))) {
         return $this->_error;
      }
      # error-status::=INTEGER
      if (!defined($this->{_error_status} = $this->process(INTEGER))) {
         return $this->_error;
      }
      # error-index::=INTEGER
      if (!defined($this->{_error_index} = $this->process(INTEGER))) {
         return $this->_error;
      }

      # Indicate that we have an SNMP error
      if (($this->{_error_status}) || ($this->{_error_index})) {
         $this->_error(
            'Received %s error-status at error-index %d',
            _error_status_itoa($this->{_error_status}), $this->{_error_index}
         );
      } 

   } else { # Trap-PDU::=IMPLICIT SEQUENCE

      # enterprise::=OBJECT IDENTIFIER
      if (!defined($this->{_enterprise} = $this->process(OBJECT_IDENTIFIER))) {
         return $this->_error;
      }
      # agent-addr::=NetworkAddress
      if (!defined($this->{_agent_addr} = $this->process(IPADDRESS))) {
         return $this->_error;
      }
      # generic-trap::=INTEGER
      if (!defined($this->{_generic_trap} = $this->process(INTEGER))) {
         return $this->_error;
      }
      # specific-trap::=INTEGER
      if (!defined($this->{_specific_trap} = $this->process(INTEGER))) {
         return $this->_error;
      }
      # time-stamp::=TimeTicks
      if (!defined($this->{_time_stamp} = $this->process(TIMETICKS))) {
         return $this->_error;
      }

   }

   TRUE;
}

sub _process_var_bind_list
{
   my ($this) = @_;

   my $value;

   # VarBindList::=SEQUENCE
   if (!defined($value = $this->process(SEQUENCE))) {
      return $this->_error;
   }

   # Using the length of the VarBindList SEQUENCE, 
   # calculate the end index.

   my $end = $this->index + $value;

   $this->{_var_bind_list}  = {};
   $this->{_var_bind_names} = [];

   my $oid;

   while ($this->index < $end) {

      # VarBind::=SEQUENCE
      if (!defined($this->process(SEQUENCE))) {
         return $this->_error;
      }
      # name::=ObjectName
      if (!defined($oid = $this->process(OBJECT_IDENTIFIER))) {
         return $this->_error;
      }
      # value::=ObjectSyntax
      if (!defined($value = $this->process)) {
         return $this->_error;
      }

      # Create a hash consisting of the OBJECT IDENTIFIER as a
      # key and the ObjectSyntax as the value.  If there is a
      # duplicate OBJECT IDENTIFIER in the VarBindList, we pad
      # that OBJECT IDENTIFIER with spaces to make a unique
      # key in the hash.

      while (exists($this->{_var_bind_list}->{$oid})) {
         $oid .= ' '; # Pad with spaces
      }

      DEBUG_INFO('{ %s => %s }', $oid, $value);
      $this->{_var_bind_list}->{$oid} = $value;

      # Create an array with the ObjectName OBJECT IDENTIFIERs
      # so that the order in which the VarBinds where encoded
      # in the PDU can be retrieved later.

      push(@{$this->{_var_bind_names}}, $oid);

   }

   # Return an error based on the contents of the VarBindList
   # if we received a Report-PDU.

   return $this->_report_pdu_error if ($this->{_pdu_type} == REPORT);

   # Return the var_bind_list hash
   $this->{_var_bind_list};
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
         return sprintf('??(%d)', $_[0]);
      }

      sprintf('%s(%d)', $error_status[$_[0]], $_[0]);
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
1; # [end Net::SNMP::PDU]
