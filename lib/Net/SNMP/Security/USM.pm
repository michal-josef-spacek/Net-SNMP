# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::Security::USM;

# $Id: USM.pm,v 1.4 2002/05/06 12:30:37 dtown Exp $

# Object that implements the SNMPv3 User-based Security Model.

# Copyright (c) 2001-2002 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

require Net::SNMP::Security;

use Net::SNMP::Message qw(
   :msgFlags :securityLevels asn1_itoa
   OCTET_STRING SEQUENCE INTEGER SNMP_VERSION_3 SECURITY_MODEL_USM TRUE FALSE
); 

use Sys::Hostname qw(hostname);

use Crypt::DES();
use Digest::MD5();
use Digest::SHA1();
use Digest::HMAC();

## Version of the Net::SNMP::Security::USM module

our $VERSION = v1.0.2;

## Package variables

our $ENGINE_ID;      # Our authoritativeEngineID 

our $DEBUG = FALSE;  # Debug flag

## Handle importing/exporting of symbols

use Exporter();

our @ISA = qw(Exporter Net::SNMP::Security);

our @EXPORT_OK = qw(
   AUTH_PROTOCOL_HMACMD5 AUTH_PROTOCOL_HMACSHA
   SECURITY_LEVEL_NOAUTHNOPRIV SECURITY_LEVEL_AUTHNOPRIV 
   SECURITY_LEVEL_AUTHPRIV
); 

our %EXPORT_TAGS = (
   levels      => [
      qw( SECURITY_LEVEL_NOAUTHNOPRIV SECURITY_LEVEL_AUTHNOPRIV
          SECURITY_LEVEL_AUTHPRIV )
   ],
   authprotos  => [qw(AUTH_PROTOCOL_HMACMD5 AUTH_PROTOCOL_HMACSHA)],
   ALL         => [@EXPORT_OK]
);

## Authentication protocols

sub AUTH_PROTOCOL_HMACMD5()     { 2 }  # usmHMACMD5AuthProtocol
sub AUTH_PROTOCOL_HMACSHA()     { 3 }  # usmHMACSHAAuthProtocol

## Privacy protocols

sub PRIV_PROTOCOL_DES()         { 2 }  # usmDESPrivProtocol

BEGIN
{
   # Initialize our snmpEngineID using the algorithm described
   # in RFC 2571.

   # SnmpEngineID ::= TEXTUAL-CONVENTION

   # The first bit is set to one to indicate that the RFC 2571
   # algorithm is being used.  The first fours bytes are to be
   # the agent's SNMP management private enterprise number, but
   # they are set to all zeros. The fifth byte is set to one to
   # indicate that the final four bytes are a IPv4 address.

   eval { 
   $ENGINE_ID = pack('H10', '8000000001') . scalar(gethostbyname(hostname()));
   };

   # Fallback in case gethostbyname() or hostname() fail
   $ENGINE_ID = pack('x11H2', '01') if ($@);
}

# [public methods] -----------------------------------------------------------

sub new
{
   my ($class, %argv) = @_;

   # Create a new data structure for the object
   my $this = bless {
      '_error'              => undef,                 # Error message
      '_version'            => SNMP_VERSION_3,        # version 
      '_authoritative'      => FALSE,                 # Authoritative flag
      '_discovered'         => FALSE,                 # Engine discovery flag
      '_synchronized'       => FALSE,                 # Synchronization flag
      '_engine_id'          => '',                    # snmpEngineID
      '_engine_boots'       => 0,                     # snmpEngineBoots
      '_engine_time'        => 0,                     # snmpEngineTime
      '_latest_engine_time' => 0,                     # latestReceivedEngineTime
      '_time_epoc'          => time(),                # snmpEngineBoots epoc
      '_user_name'          => '',                    # securityName 
      '_auth_key'           => undef,                 # authKey 
      '_auth_password'      => undef,                 # Authentication password 
      '_auth_protocol'      => AUTH_PROTOCOL_HMACMD5, # authProtocol 
      '_priv_key'           => undef,                 # privKey 
      '_priv_password'      => undef,                 # Privacy password
      '_priv_protocol'      => PRIV_PROTOCOL_DES,     # privProtocol
      '_security_level'     => SECURITY_LEVEL_NOAUTHNOPRIV
   }, $class;

   # We first need to find out if we are an authoritative engine
   foreach (keys %argv) {
      if (/^-?authoritative$/i) {
         $this->{_authoritative} = (delete($argv{$_})) ? TRUE : FALSE;
      }
   }

   # Now validate the rest of the passed arguments

   foreach (keys %argv) {

      if (/^-?version$/i) {
         $this->_version($argv{$_});
      } elsif (/^-?debug$/i) {
         $this->debug($argv{$_});
      } elsif ((/^-?engineid$/i) && ($this->{_authoritative})) {
         $this->_engine_id($argv{$_});
      } elsif (/^-?username$/i) {
         $this->_user_name($argv{$_});
      } elsif (/^-?authkey$/i) {
         $this->_auth_key($argv{$_}); 
      } elsif (/^-?authpassword$/i) {
         $this->_auth_password($argv{$_});
      } elsif (/^-?authprotocol$/i) {
         $this->_auth_protocol($argv{$_});
      } elsif (/^-?privkey$/i) {
         $this->_priv_key($argv{$_});
      } elsif (/^-?privpassword$/i) {
         $this->_priv_password($argv{$_});
      } else {
         $this->_error("Invalid argument '%s'", $_);
      }

      if (defined($this->{_error})) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }

   }

   # Set the authoritativeEngineID if the user did not provide one

   if ($this->{_authoritative}) {
      $this->{_engine_id}    = $ENGINE_ID if ($this->{_engine_id} eq '');
      $this->{_synchronized} = TRUE;
      $this->{_discovered}   = TRUE;
   }

   # Define the securityParameters
   if (!defined($this->_security_params)) {
      return wantarray ? (undef, $this->{_error}) : undef;
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

   # Validate PDU type with snmpEngine type
   if ($pdu->expect_response) {
      if ($this->{_authoritative}) {
         return $this->_error(
            'Must be a non-authoritative SNMP engine to generate a %s', 
            asn1_itoa($pdu->pdu_type)
         );
      }
   } else {
      if (!$this->{_authoritative}) {
         return $this->_error(
            'Must be an authoritative SNMP engine to generate a %s',
            asn1_itoa($pdu->pdu_type)
         );
      }
   }

   # Extract the msgGlobalData out of the message
   my $msg_global_data = $msg->clear;

   my $pdu_buffer  = $pdu->copy;
   my $priv_params = '';

   # encryptedPDU::=OCTET STRING
   if ($this->security_level > SECURITY_LEVEL_AUTHNOPRIV) {
      if (!defined($this->_encrypt_data($msg, $priv_params, $pdu_buffer))) {
         return $this->_error;
      }
   }

   # msgPrivacyParameters::=OCTET STRING
   if (!defined($msg->prepare(OCTET_STRING, $priv_params))) {
      return $this->_error($msg->error);
   }

   # msgAuthenticationParameters::=OCTET STRING

   my $auth_params = '';
   my $auth_location = 0;

   if ($this->security_level > SECURITY_LEVEL_NOAUTHNOPRIV) {
   
      # Save the location to fill in msgAuthenticationParameters later
      $auth_location = $msg->length + 12 + length($pdu_buffer);

      # Set the msgAuthenticationParameters to all zeros
      $auth_params = pack('x12');
   }

   if (!defined($msg->prepare(OCTET_STRING, $auth_params))) {
      return $this->_error($msg->error);
   }

   # msgUserName::=OCTET STRING 
   if (!defined($msg->prepare(OCTET_STRING, $this->_user_name))) {
      return $this->_error($msg->error);
   } 

   # msgAuthoritativeEngineTime::=INTEGER  
   if (!defined($msg->prepare(INTEGER, $this->_engine_time))) {
      return $this->_error($msg->error);
   }

   # msgAuthoritativeEngineBoots::=INTEGER
   if (!defined($msg->prepare(INTEGER, $this->_engine_boots))) {
      return $this->_error($msg->error);
   }

   # msgAuthoritativeEngineID
   if (!defined($msg->prepare(OCTET_STRING, $this->_engine_id))) {
      return $this->_error($msg->error);
   }

   # UsmSecurityParameters::= SEQUENCE
   if (!defined($msg->prepare(SEQUENCE, $msg->clear))) {
      return $this->_error($msg->error);
   }

   # msgSecurityParameters::=OCTET STRING
   if (!defined($msg->prepare(OCTET_STRING, $msg->clear))) {
      return $this->_error($msg->error);
   }

   # Append the PDU
   if (!defined($msg->append($pdu_buffer))) {
      return $this->_error($msg->error);
   }

   # Prepend the msgGlobalData
   if (!defined($msg->prepend($msg_global_data))) {
      return $this->_error($msg->error);
   }

   # version::=INTEGER
   if (!defined($msg->prepare(INTEGER, $pdu->version))) {
      return $this->_error($msg->error);
   }

   # message::=SEQUENCE
   if (!defined($msg->prepare(SEQUENCE, $msg->clear))) {
      return $this->_error($msg->error);
   }

   # Apply authentication
   if ($this->security_level > SECURITY_LEVEL_NOAUTHNOPRIV) {
      if (!defined($this->_authenticate_outgoing_msg($msg, $auth_location))) {
         return $this->_error($msg->error);
      }
   }

   # Return the Message
   $msg;
}

sub process_incoming_msg
{
   my ($this, $msg) = @_;

   # Clear any previous errors
   $this->_error_clear;

   return $this->_error('Required Message missing') unless (@_ == 2);

   # msgSecurityParameters::=OCTET STRING

   my $params = $msg->process(OCTET_STRING);
   return $this->_error($msg->error) unless defined($params);

   # Need to move the buffer index back to the begining of the data
   # portion of the OCTET STRING that contains the msgSecurityParameters.

   $msg->index($msg->index - length($params));

   # UsmSecurityParameters::=SEQUENCE
   return $this->_error($msg->error) unless defined($msg->process(SEQUENCE));

   # msgAuthoritativeEngineID::=OCTET STRING
   my $auth_engine_id;
   if (!defined($auth_engine_id = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error);
   }

   # msgAuthoritativeEngineBoots::=INTEGER
   my $auth_engine_boots;
   if (!defined($auth_engine_boots = $msg->process(INTEGER))) {
      return $this->_error($msg->error); 
   }
   if (($auth_engine_boots < 0) || ($auth_engine_boots > 2147483647)) {
      return $this->_error(
         'Invalid msgAuthoritativeEngineBoots value [%d]', $auth_engine_boots 
      );
   }

   # msgAuthoritativeEngineTime::=INTEGER
   my $auth_engine_time;
   if (!defined($auth_engine_time = $msg->process(INTEGER))) {
      return $this->_error($msg->error);
   }
   if (($auth_engine_time < 0) || ($auth_engine_time > 2147483647)) {
      return $this->_error(
         'Invalid msgAuthoritativeEngineTime value [%d]', $auth_engine_time 
      );
   }

   # msgUserName::=OCTET STRING
   my $user_name;
   if (!defined($user_name = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error); 
   }

   # msgAuthenticationParameters::=OCTET STRING
   my $auth_params;
   if (!defined($auth_params = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error); 
   }

   # We need to zero out the msgAuthenticationParameters in order 
   # to compute the HMAC properly.

   if (my $len = length($auth_params)) {
      substr(${$msg->reference}, ($msg->index - $len), $len) = pack("x$len");
   }

   # msgPrivacyParameters::=OCTET STRING
   my $priv_params;
   if (!defined($priv_params = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error); 
   }

   # Validate the msgAuthoritativeEngineID and msgUserName
  
   if ($this->{_discovered}) {

      if ($auth_engine_id ne $this->_engine_id) {
         return $this->_error(
            'Unknown securityEngineID [%s]', unpack('H*', $auth_engine_id)
         );
      }

      if ($user_name ne $this->_user_name) {
         return $this->_error('Unknown securityName [%s]', $user_name);
      }

   } else {

      # Handle authoritativeEngineID discovery
      if (!defined($this->_engine_id_discovery($auth_engine_id))) {
         return $this->_error;
      }

   }

   # Get the securityLevel of the incoming message from the msgFlags

   my $security_level = SECURITY_LEVEL_NOAUTHNOPRIV;
   my $msg_flags = $msg->msg_flags;

   if ($msg_flags & MSG_FLAGS_AUTH) {

      $security_level = SECURITY_LEVEL_AUTHNOPRIV;

      if ($msg_flags & MSG_FLAGS_PRIV) {
         $security_level = SECURITY_LEVEL_AUTHPRIV;
      }

   } elsif ($msg_flags & MSG_FLAGS_PRIV) {

      # RFC 2572 - Section 7.2 1d: "If the authFlag is not set  
      # and privFlag is set... ...the message is discarded..."

      return $this->_error('Invalid msgFlags [0x%02x]', $msg_flags);
   } 

   # RFC 2572 - Section 7.2 1e: "Any other bits... ...are ignored."
   if ($msg_flags & ~MSG_FLAGS_MASK) {
      DEBUG_INFO('questionable msgFlags [0x%02x]', $msg_flags);
   }

   # Validate the incoming securityLevel

   if ($security_level > $this->security_level) {
      return $this->_error('Unsupported securityLevel [%d]', $security_level);
   }

 
   if ($security_level > SECURITY_LEVEL_NOAUTHNOPRIV) {

      # Authenticate the message
      if (!defined($this->_authenticate_incoming_msg($msg, $auth_params))) { 
         return $this->_error;
      }

      # Synchronize the time
      $this->_synchronize($auth_engine_boots, $auth_engine_time);

      # Check for timeliness
      if (!defined($this->_timeliness($auth_engine_boots, $auth_engine_time))) {
         return $this->_error;
      }

      if ($security_level > SECURITY_LEVEL_AUTHNOPRIV) {

         # encryptedPDU::=OCTET STRING

         my $cipher;
         if (!defined($cipher = $msg->process(OCTET_STRING))) {
            return $this->_error($msg->error);
         }

         if (!defined($this->_decrypt_data($msg, $priv_params, $cipher))) {
            return $this->_error;
         }

      }

   }

   TRUE;
}

sub auth_key
{
   $_[0]->_auth_key;
}

sub engine_id
{
   $_[0]->_engine_id;
}

sub security_level
{
   $_[0]->{_security_level};
}

sub security_model
{
   # RFC 2571 - SnmpSecurityModel::=TEXTUAL-CONVENTION

   SECURITY_MODEL_USM;
}

sub discovered
{
   if ($_[0]->{_security_level} > SECURITY_LEVEL_NOAUTHNOPRIV) {
      ($_[0]->{_discovered} && $_[0]->{_synchronized});
   } else {
      $_[0]->{_discovered};
   }
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

# [private methods] ----------------------------------------------------------

sub _version
{
   if ($_[1] != SNMP_VERSION_3) {
      return $_[0]->_error('Invalid SNMP version specified [%s]', $_[1]);
   }

   $_[0]->{_version} = $_[1];
}

sub _engine_id
{
   if (@_ == 2) {
      if ($_[1] =~ /^(?i:0x)?([a-fA-F0-9]{10,64})$/) {
         $_[0]->{_engine_id} = pack('H*', length($1) % 2 ? '0'.$1 : $1);
      } else {
         $_[0]->_error('Invalid authoritativeEngineID format specified');
      }
   }

   $_[0]->{_engine_id};
}

sub _user_name
{
   if (@_ == 2) {
      if ($_[1] eq '') {
         return $_[0]->_error('Empty userName specified');
      } elsif (length($_[1]) > 32) {
         return $_[0]->_error('Invalid userName length [%d]', length($_[1]));
      }
      $_[0]->{_user_name} = $_[1];
   }

   ($_[0]->{_discovered}) ? $_[0]->{_user_name} : 'initial';
}

sub _auth_key
{
   if (@_ == 2) {
      if ($_[1] =~ /^(?i:0x)?([a-fA-F0-9]{32,40})$/) {
         $_[0]->{_auth_key} = pack('H*', length($1) % 2 ? '0'.$1 : $1); 
      } else {
         return $_[0]->_error('Invalid authKey specified');
      }
   }

   $_[0]->{_auth_key};
}

sub _auth_password
{
   if (@_ == 2) {
      if ($_[1] eq '') {
         return $_[0]->_error('Empty authentication password specified');
      } 
      $_[0]->{_auth_password} = $_[1];
   }

   $_[0]->{_auth_password};
}

sub _auth_protocol
{
   my ($this, $proto) = @_;

   if (@_ == 2) {
    
      my $protocols = {
         'md5'  => AUTH_PROTOCOL_HMACMD5,
         'sha1' => AUTH_PROTOCOL_HMACSHA
      };

      if ($proto eq '') {
         return $this->_error('Empty authProtocol specified');
      }

      my @match = grep(/^\Q$proto/i, keys(%{$protocols}));

      if (@match != 1) {
         return $this->_error('Unknown authProtocol specified [%s]', $proto);
      }

      $this->{_auth_protocol} = $protocols->{$match[0]};
   }

   $this->{_auth_protocol};
}

sub _priv_key
{
   if (@_ == 2) {
      if ($_[1] =~ /^(?i:0x)?([a-fA-F0-9]{32,40})$/) {
         $_[0]->{_priv_key} = pack('H*', length($1) % 2 ? '0'.$1 : $1); 
      } else {
         return $_[0]->_error('Invalid privKey specified');
      }
   }

   $_[0]->{_priv_key};
}

sub _priv_password
{
   if (@_ == 2) {
      if ($_[1] eq '') {
         return $_[0]->_error('Empty privacy password specified');
      }
      $_[0]->{_priv_password} = $_[1];
   }

   $_[0]->{_priv_password};
}

sub _engine_boots
{
   ($_[0]->{_synchronized}) ? $_[0]->{_engine_boots} : 0;
}

sub _engine_time
{
   return 0 unless ($_[0]->{_synchronized});

   $_[0]->{_engine_time} = time() - $_[0]->{_time_epoc};

   if ($_[0]->{_engine_time} > 2147483647) {
      DEBUG_INFO('snmpEngineTime rollover');
      if (++$_[0]->{_engine_boots} == 2147483647) {
         die('FATAL: Unable to handle snmpEngineBoots value');
      }
      $_[0]->{_engine_time} -= 2147483647;
      $_[0]->{_time_epoc} = time() - $_[0]->{_engine_time};
      if (!$_[0]->{_authoritative}) {
         $_[0]->{_synchronized} = FALSE;
         return $_[0]->{_latest_engine_time} = 0;
      } 
   }

   if ($_[0]->{_engine_time} < 0) {
      die('FATAL: Unable to handle snmpEngineTime value');
   }

   $_[0]->{_engine_time};
}

sub _security_params
{
   my ($this) = @_;

   # Clear any previous error messages
   $this->_error_clear;

   # We must have an usmUserName
   if ($this->{_user_name} eq '') {
      return $this->_error('Required userName not specified');
   }

   if (defined($this->{_auth_key})) {

      # Validate the length based on the protocol
      if (!$this->_key_valid($this->{_auth_key})) {
         return $this->_error('Invalid authKey specified');
      }
      $this->{_auth_password} = undef;
      if ($this->{_discovered}) {
         $this->{_security_level} = SECURITY_LEVEL_AUTHNOPRIV;
      }

   } elsif ((defined($this->{_auth_password})) && ($this->{_discovered})) {

      $this->{_auth_key} = $this->_key_generate($this->{_auth_password});
      $this->{_security_level} = SECURITY_LEVEL_AUTHNOPRIV;

   }

   # You must have authentication to have privacy
   if (!defined($this->{_auth_key}) && !defined($this->{_auth_password})) {
      if (defined($this->{_priv_key}) || defined($this->{_priv_password})) {
         return $this->_error(
            'Unsupported securityLevel (privacy requires the use of ' .
            'authentication)'
         );
      }
   }

   if (defined($this->{_priv_key})) {

      # Validate the length based on the protocol
      if (!$this->_key_valid($this->{_priv_key})) {
         return $this->_error('Invalid privKey specified');
      }
      $this->{_priv_password} = undef;
      if ($this->{_discovered}) {
         $this->{_security_level} = SECURITY_LEVEL_AUTHPRIV;
      }

   } elsif ((defined($this->{_priv_password})) && ($this->{_discovered})) {

      $this->{_priv_key} = $this->_key_generate($this->{_priv_password});
      $this->{_security_level} = SECURITY_LEVEL_AUTHPRIV;

   }   

   DEBUG_INFO('securityLevel = %d', $this->{_security_level});
      
   $this->{_security_level};         
}

sub _engine_id_discovery
{
   my ($this, $engine_id) = @_;

   return TRUE if ($this->{_authoritative});

   if ((length($engine_id) >= 5) && (length($engine_id) <= 32)) {
      DEBUG_INFO('engineID = 0x%s', unpack('H*', $engine_id));
      $this->{_engine_id}  = $engine_id;
      $this->{_discovered} = TRUE;
      if (!defined($this->_security_params)) {
         $this->{_discovered} = FALSE;
         return $this->_error;
      }
   } else {
      return $this->_error(
         'Invalid msgAuthoritativeEngineID length [%d]', length($engine_id)
      );
   }

   TRUE;
}

sub _synchronize
{
   my ($this, $msg_boots, $msg_time) = @_;

   return TRUE if ($this->{_authoritative});
   return TRUE if ($this->{_security_level} < SECURITY_LEVEL_AUTHNOPRIV);

   if (($msg_boots > $this->_engine_boots) ||
       (($msg_boots == $this->_engine_boots) && 
        ($msg_time > $this->{_latest_engine_time})))
   {

      DEBUG_INFO(
         'update: engineBoots = %d, engineTime = %d', $msg_boots, $msg_time 
      );

      $this->{_engine_boots} = $msg_boots;
      $this->{_latest_engine_time} = $this->{_engine_time} = $msg_time;
      $this->{_time_epoc} = time() - $this->{_engine_time};

      if (!$this->{_synchronized}) {
         $this->{_synchronized} = TRUE;
         if (!defined($this->_security_params)) {
            return ($this->{_synchronized} = FALSE);
         } 
      }

      TRUE; 

   } else {

      DEBUG_INFO(
         'no update: engineBoots = %d, msgBoots = %d; ' .
         'latestTime = %d, msgTime = %d',
         $this->_engine_boots, $msg_boots, 
         $this->{_latest_engine_time}, $msg_time
      );

      FALSE;

   } 
}

sub _timeliness
{
   my ($this, $msg_boots, $msg_time) = @_;

   return TRUE if ($this->{_security_level} < SECURITY_LEVEL_AUTHNOPRIV);

   # Retrieve a local copy of our snmpEngineBoots and snmpEngineTime 
   # to avoid the possibilty of using different values in each of 
   # the comparisons.  
 
   my $engine_time  = $this->_engine_time;
   my $engine_boots = $this->_engine_boots;

   if ($engine_boots == 2147483647) {
      $this->{_synchronized} = FALSE;
      return $this->_error('Not in time window');
   }

   if ($this->{_authoritative}) {

      if ($msg_boots != $engine_boots) {
         return $this->_error('Not in time window');
      }
      if (($msg_time < ($engine_time - 150)) || 
          ($msg_time > ($engine_time + 150))) 
      {
         return $this->_error('Not in time window');
      }

   } else {

      if ($msg_boots < $engine_boots) {
         return $this->_error('Not in time window');
      }
      if (($msg_boots == $engine_boots) && ($msg_time < ($engine_time - 150))) {
         return $this->_error('Not in time window');
      }

   }

   TRUE;
}

sub _authenticate_outgoing_msg
{
   my ($this, $msg, $auth_location) = @_;

   if (!$auth_location) {
      return $this->_error(
         'Authentication failure (Unable to set msgAuthenticationParameters)'
      );
   }

   # Calculate the HMAC
   my $hmac = $this->_auth_hmac($msg);

   return $this->_error unless defined($hmac);

   # Set the msgAuthenticationParameters
   substr(${$msg->reference}, -$auth_location, 12) = $hmac; 
}

sub _authenticate_incoming_msg
{
   my ($this, $msg, $auth_params) = @_;

   # Authenticate the message
   if ($auth_params ne $this->_auth_hmac($msg)) {
      return $this->_error('Authentication failure');
   }
   DEBUG_INFO('authentication passed');

   TRUE;
}

sub _auth_hmac
{
   my ($this, $msg) = @_;

   if (!defined($this->{_auth_key})) {
      return $this->_error('Required authKey not defined');
   }

   my $hmac;

   if ($this->{_auth_protocol} == AUTH_PROTOCOL_HMACMD5) {
      $hmac = Digest::HMAC->new($this->{_auth_key}, 'Digest::MD5');
   } elsif ($this->{_auth_protocol} == AUTH_PROTOCOL_HMACSHA) {
      $hmac = Digest::HMAC->new($this->{_auth_key}, 'Digest::SHA1');
   }

   if (!defined($hmac)) {
      return $this->_error('Authentication failure (HMAC create)');
   }

   substr($hmac->add(${$msg->reference})->digest, 0, 12);
}

sub _encrypt_data
{
#  my ($this, $msg, $priv_params, $pdu_buffer) = @_;

   if (!defined(
         $_[1]->prepare(OCTET_STRING, $_[0]->_priv_encrypt_des($_[2], $_[3]))
      ))
   {
      return $_[0]->_error('Encryption error');
   }
  
   # Set the PDU buffer equal to the encryptedPDU
   $_[3] = $_[1]->clear; 
}

sub _decrypt_data
{
#  my ($this, $msg, $priv_params, $cipher) = @_;

   # Clear the Message buffer
   $_[1]->clear;

   # Put the decrypted data back into the Message buffer
   if (!defined($_[1]->prepend($_[0]->_priv_decrypt_des($_[2], $_[3])))) {
      return $_[0]->_error($_[1]->error);
   }
   if (!$_[1]->length) {
      return $_[0]->_error($_[1]->error);
   }   

   # See if the decrypted data starts with a SEQUENCE
   if (!defined($_[1]->process(SEQUENCE))) {
      return $_[0]->_error('Decryption error');
   }
   $_[1]->index(0); # Reset the index

   DEBUG_INFO('privacy passed');

   TRUE;
}

sub _priv_encrypt_des
{
#  my ($this, $priv_params, $plain) = @_;

   if (!defined($_[0]->{_priv_key})) {
      return $_[0]->_error('Required privKey not defined');
   }

   # Pad the plain text if necessary.  "The actual pad value is 
   # irrelevant..." according RFC 2574 Section 8.1.1.2.  However,
   # there are some agents out there that expect each of the
   # padding byte(s) be set to the size of the padding.

   if ((my $pad = (8 - (length($_[2]) % 8))) < 8) {
      $_[2] .= pack('C', $pad) x $pad;
   }

   my $des = Crypt::DES->new(substr($_[0]->{_priv_key}, 0, 8));

   # Create and set the salt
   $_[1] = pack('NN', $_[0]->_engine_boots, int(rand((2**31) - 1)));

   # Create the initial vector (IV)
   my $iv = substr(substr($_[0]->{_priv_key}, 8, 16) ^ $_[1], 0, 8);

   my $cipher = '';

   # Perform CBC
   while($_[2] =~ /(.{8})/gs) {
      $cipher .= $iv = $des->encrypt($1 ^ $iv);
   }

   $cipher;
}

sub _priv_decrypt_des
{
#  my ($this, $priv_params, $cipher) = @_;

   if (!defined($_[0]->{_priv_key})) {
      return $_[0]->_error('Required privKey not defined');
   }

   if (length($_[1]) != 8) {
      return $_[0]->_error(
        'Invalid msgPrivParameters length [%d]', length($_[1])
      );
   }

   if (length($_[2]) % 8) {
      return $_[0]->_error('Invalid DES cipher length');
   }

   my $des = Crypt::DES->new(substr($_[0]->{_priv_key}, 0, 8));

   # Create the initial vector (IV)
   my $iv = substr($_[0]->{_priv_key}, 8, 8) ^ $_[1];

   my $plain = '';

   # Perform CBC
   while ($_[2] =~ /(.{8})/gs) {
      $plain .= $iv ^ $des->decrypt($1);
      $iv = $1;
   }

   $plain;
}

sub _key_generate
{
#  my ($this, $password) = @_;

   return unless (@_ == 2) && defined($_[0]->{_engine_id}) && defined($_[1]);

   if ($_[0]->{_auth_protocol} == AUTH_PROTOCOL_HMACMD5) {
      $_[0]->_password_localize_md5($_[1]);
   } elsif ($_[0]->{_auth_protocol} == AUTH_PROTOCOL_HMACSHA) {
      $_[0]->_password_localize_sha($_[1]);
   } else {
      return;
   }
}

sub _key_valid
{
#  my ($this, $key) = @_;

   my $len = ($_[0]->{_auth_protocol} == AUTH_PROTOCOL_HMACMD5) ? 16 : 20;

   if (length($_[1]) != $len) {
      return FALSE;
   }

   TRUE;
}

sub _password_localize_md5
{
#  my ($this, $password) = @_;

   return unless (@_ == 2);

   my $md5 = Digest::MD5->new;

   # Create the initial digest using the password
   my $d = $_[1] x int(2**20 / length($_[1])) .
           substr($_[1], 0,(2**20 % length($_[1])));

   $d = substr($md5->add($d)->digest, 0, 16);

   # Localize the key with the authoritativeEngineID
   substr($md5->add($d . $_[0]->{_engine_id} . $d)->digest, 0 , 16);
}

sub _password_localize_sha
{
#  my ($this, $password) = @_;

   return unless (@_ == 2);

   my $sha1 = Digest::SHA1->new;

   # Create the initial digest using the password
   my $d = $_[1] x int(2**20 / length($_[1])) .
           substr($_[1], 0,(2**20 % length($_[1])));

   $d = substr($sha1->add($d)->digest, 0, 20);

   # Localize the key with the authoritativeEngineID
   substr($sha1->add($d . $_[0]->{_engine_id} . $d)->digest, 0 , 20);
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
1; # [end Net::SNMP::Security::USM]
