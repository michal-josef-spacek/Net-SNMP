# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::MessageProcessing;

# $Id: MessageProcessing.pm,v 1.2 2001/11/09 14:03:52 dtown Exp $

# Object that implements the Message Processing module.

# Copyright (c) 2001 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Net::SNMP::Message qw(:versions :v3seclevels :types asn1_itoa TRUE FALSE);
use Net::SNMP::PDU();

## Version of the Net::SNMP::MessageProcessing module

our $VERSION = v1.0.0;

## Package variables

our $INSTANCE;         # Reference to the Singleton object

our $DEBUG = FALSE;    # Debug flag

our $MSG_HANDLES = {}; # Cached request messages

# [public methods] -----------------------------------------------------------

sub instance
{
   $INSTANCE || ($INSTANCE = Net::SNMP::MessageProcessing->_new);
}

sub prepare_outgoing_msg
{
   my ($this, $pdu) = @_;

   # Clear any previous errors
   $this->_error_clear;

   if ((@_ != 2) || (!ref($pdu))) {
      return $this->_error('Missing or invalid PDU reference');
   }

   # We must have a Security Model in order to prepare the message. 
   if (!defined($pdu->security)) {
      return $this->_error('No Security Model defined');
   }

   # Create a new Message
   my ($msg, $error) = Net::SNMP::Message->new(
      -callback   => $pdu->callback,
      -leadingdot => $pdu->leading_dot,
      -security   => $pdu->security,
      -translate  => $pdu->translate,
      -transport  => $pdu->transport,
      -version    => $pdu->version
   );
   return $this->_error($error) unless defined($msg);

   if ($pdu->version == SNMP_VERSION_3) {

      # scopedPDU::=SEQUENCE
      if (!defined($pdu->prepare_v3_scoped_pdu)) {
         return $this->_error($pdu->error);
      }

      # msgGlobalData::=SEQUENCE
      if (!defined($msg->prepare_v3_global_data($pdu))) {
         return $this->_error($msg->error);
      }

   }

   # Pass off to the Security Model
   if (!defined($pdu->security->generate_request_msg($pdu, $msg))) {
      return $this->_error($pdu->security->error);
   }

   # Cache and return the new Message
   ($pdu->expect_response) ? ($MSG_HANDLES->{$pdu->msg_id} = $msg) : $msg;
}

sub prepare_data_elements
{
   my ($this, $msg) = @_;

   # Clear any previous errors
   $this->_error_clear;

   if ((@_ != 2) || (!ref($msg))) {
      return $this->_error('Missing or invalid Message reference');
   }

   # message::=SEQUENCE
   return $this->_error($msg->error) unless defined($msg->process(SEQUENCE));

   # version::=INTEGER
   if (!defined($msg->version($msg->process(INTEGER)))) {
      return $this->_error($msg->error); 
   }

   # Find the message in the cache
   my $tx_msg;

   if ($msg->version == SNMP_VERSION_3) {

      if (!defined($msg->process_v3_global_data)) {
         return $this->_error($msg->error); 
      }
      
      if (!exists($MSG_HANDLES->{$msg->msg_id})) {
         return $this->_error('Unknown msgID [%d]', $msg->msg_id);
      }

      $tx_msg = delete($MSG_HANDLES->{$msg->msg_id}); 

   } else {

      if (!defined($msg->process_v1_v2c_community)) {
         return $this->_error($msg->error); 
      }

      # Cast the Message to a PDU
      if (!defined($msg = Net::SNMP::PDU->new($msg))) {
         return $this->_error('Failed to allocate new PDU');
      }

      if (!defined($msg->process_pdu_sequence)) {
         return $this->_error($msg->error);
      }

      if ($msg->pdu_type != GET_RESPONSE) {
          return $this->_error(
             'Expected %s, but found %s', 
             asn1_itoa(GET_RESPONSE), asn1_itoa($msg->pdu_type)
          ); 
      }
      
      if (!exists($MSG_HANDLES->{$msg->request_id})) {
         return $this->_error('Unknown request-id [%d]', $msg->request_id);
      }

      $tx_msg = delete($MSG_HANDLES->{$msg->request_id});

   }

   # Add the callback
   $msg->callback($tx_msg->callback);

   # Copy the timeout_id
   $msg->timeout_id($tx_msg->timeout_id);

   # Now that we have found the matching request for this response
   # we return a FALSE error instead of undefined so that the error
   # gets propagated back to the user.

   # Compare the Security Models
   if ($msg->msg_security_model != $tx_msg->security->security_model) {
      $this->_error(
         'Unknown securityModel [%d]', $msg->msg_security_model
      );
      return FALSE;
   }

   # Pass off to the Security Model
   if (!defined($tx_msg->security->process_incoming_msg($msg))) {
      $this->_error($tx_msg->security->error);
      return FALSE;
   } 

   if ($msg->version == SNMP_VERSION_3) {

      # Adjust our maxMsgSize if necessary
      if ($msg->msg_max_size < $tx_msg->max_msg_size) {
         DEBUG_INFO('new maxMsgSize = %d', $msg->msg_max_size);
         if (!defined($tx_msg->max_msg_size($msg->msg_max_size))) {
            $this->_error($tx_msg->error);
            return FALSE;
         }
      }

      # scopedPDU
      if (!defined($msg->process_v3_scoped_pdu)) {
         $this->_error($msg->error);
         return FALSE;
      }

      # Cast the Message to a PDU
      if (!defined($msg = Net::SNMP::PDU->new($msg))) {
         $this->_error('Failed to allocate new PDU');
         return FALSE;
      }

      if (!defined($msg->process_pdu_sequence)) {
         $this->_error($msg->error);
         return FALSE;
      }

      if ($msg->pdu_type != REPORT) {

         if ($msg->pdu_type != GET_RESPONSE) {
            $this->_error(
               'Expected %s, but found %s',
               asn1_itoa(GET_RESPONSE), asn1_itoa($msg->pdu_type)
            );
            return FALSE;
         }
      
         # Compare the contextEngineID
         if ($msg->context_engine_id ne $tx_msg->context_engine_id) {
            $this->_error(
               'Unknown contextEngineID [%s]',
               unpack('H*', $msg->context_engine_id)
            );
            return FALSE;
         }

         # Compare the contextName
         if ($msg->context_name ne $tx_msg->context_name) {
            $this->_error(
               'Unknown contextName [%s]', $msg->context_name
            );
            return FALSE;
         }

         # Check the request-id
         if ($msg->request_id != $tx_msg->msg_id) {
            $this->_error('Invalid request-id [%d]', $msg->request_id);
            return FALSE;
         }
      }

   }

   # Adjust the "leading dot" and "translate" parameters
   $msg->leading_dot($tx_msg->leading_dot);
   $msg->translate($tx_msg->translate);

   # VarBindList::=SEQUENCE
   if (!defined($msg->process_var_bind_list)) {
     $this->_error($msg->error);
     return FALSE;
   }

   # Return the PDU
   $msg;
}

sub msg_handle_delete
{
   my ($this, $handle) = @_;

   # Clear any previous errors
   $this->_error_clear;

   return $this->_error('No msgHandle specified') unless (@_ == 2);

   if (!exists($MSG_HANDLES->{$handle})) {
      return $this->_error('Unknown msgHandle [%d]', $handle);
   }

   delete($MSG_HANDLES->{$handle});
}

sub error
{
   $_[0]->[0] || '';
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

# [private methods] ----------------------------------------------------------

sub _new
{
   my ($class) = @_;

   # The constructor is private since we only want one
   # MessageProcessing object.

   bless [ undef ], $class; 
}

sub _error
{
   my $this = shift;

   if (!defined($this->[0])) {
      $this->[0] = sprintf(shift(@_), @_);
      if ($this->debug) {
         printf("error: [%d] %s(): %s\n",
            (caller(0))[2], (caller(1))[3], $this->[0]
         );
      }
   }

   return;
}

sub _error_clear
{
   $_[0]->[0] = undef;
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
1; # [end Net::SNMP::MessageProcessing]
