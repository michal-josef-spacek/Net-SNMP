# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::Security::USM;

# $Id: USM.pm,v 2.1 2003/09/09 12:44:54 dtown Exp $

# Object that implements the SNMPv3 User-based Security Model.

# Copyright (c) 2001-2003 David M. Town <dtown@cpan.org>
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

our $VERSION = v2.0.1;

## Package variables

our $ENGINE_ID;      # Our authoritativeEngineID 

our $DEBUG = FALSE;  # Debug flag

## Handle importing/exporting of symbols

use Exporter();

our @ISA = qw(Exporter Net::SNMP::Security);

our @EXPORT_OK = qw(
   AUTH_PROTOCOL_NONE AUTH_PROTOCOL_HMACMD5 AUTH_PROTOCOL_HMACSHA
   PRIV_PROTOCOL_NONE PRIV_PROTOCOL_DES PRIV_PROTOCOL_3DESEDE
   PRIV_PROTOCOL_AESCFB128 PRIV_PROTOCOL_AESCFB192 PRIV_PROTOCOL_AESCFB256
   SECURITY_LEVEL_NOAUTHNOPRIV SECURITY_LEVEL_AUTHNOPRIV 
   SECURITY_LEVEL_AUTHPRIV
); 

our %EXPORT_TAGS = (
   levels      => [
      qw( SECURITY_LEVEL_NOAUTHNOPRIV SECURITY_LEVEL_AUTHNOPRIV
          SECURITY_LEVEL_AUTHPRIV )
   ],
   authprotos  => [
      qw( AUTH_PROTOCOL_NONE AUTH_PROTOCOL_HMACMD5 AUTH_PROTOCOL_HMACSHA )
   ],
   privprotos  => [
      qw( PRIV_PROTOCOL_NONE PRIV_PROTOCOL_DES PRIV_PROTOCOL_3DESEDE 
          PRIV_PROTOCOL_AESCFB128 PRIV_PROTOCOL_AESCFB192 
          PRIV_PROTOCOL_AESCFB256 )
   ],
   ALL         => [@EXPORT_OK]
);

## Authentication protocols

sub AUTH_PROTOCOL_NONE()    { '1.3.6.1.6.3.10.1.1.1' } # usmNoAuthProtocol
sub AUTH_PROTOCOL_HMACMD5() { '1.3.6.1.6.3.10.1.1.2' } # usmHMACMD5AuthProtocol
sub AUTH_PROTOCOL_HMACSHA() { '1.3.6.1.6.3.10.1.1.3' } # usmHMACSHAAuthProtocol

## Privacy protocols

sub PRIV_PROTOCOL_NONE()    { '1.3.6.1.6.3.10.1.2.1' } # usmNoPrivProtocol
sub PRIV_PROTOCOL_DES()     { '1.3.6.1.6.3.10.1.2.2' } # usmDESPrivProtocol

# The privacy protocols below have been implemented using the draft 
# specifications intended to extend the User-based Security Model 
# defined in RFC 3414.  Since the object definitions have not been 
# standardized, they have been based on the Extended Security Options 
# Consortium MIB found at http://www.snmp.com/eso/esoConsortiumMIB.txt.

# Extension to Support Triple-DES EDE <draft-reeder-snmpv3-usm-3desede-00.txt> 
# Reeder and Gudmunsson; October 1999, expired April 2000 

# usm3DESPrivProtocol 
sub PRIV_PROTOCOL_3DESEDE()   { '1.3.6.1.4.1.14832.1.1' }

# AES Cipher Algorithm in the USM <draft-blumenthal-aes-usm-04.txt>
# Blumenthal, Maino, and McCloghrie; October 2002, expired April 2003 

# usmAESCfb128PrivProtocol
sub PRIV_PROTOCOL_AESCFB128() { '1.3.6.1.4.1.14832.1.2' } 

# usmAESCfb192PrivProtocol
sub PRIV_PROTOCOL_AESCFB192() { '1.3.6.1.4.1.14832.1.3' }

# usmAESCfb256PrivProtocol
sub PRIV_PROTOCOL_AESCFB256() { '1.3.6.1.4.1.14832.1.4' } 
                                                         
our $NO_AES_SUPPORT;

BEGIN
{
   # Attempt to load the Crypt::Rijndael module.  If this module is 
   # not found, disable support for the AES Cipher Algorithm.

   if (!eval('require Crypt::Rijndael')) {
      if ($@ =~ /(\S+\.pm)/) {
         $NO_AES_SUPPORT = sprintf(' (Required module %s not found)', $1);
      } else {
         $NO_AES_SUPPORT = sprintf(' (%s)', $@);
      }
   }

   # Initialize our snmpEngineID using the algorithm described
   # in RFC 3411.

   # SnmpEngineID ::= TEXTUAL-CONVENTION

   # The first bit is set to one to indicate that the RFC 3411 
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
      '_auth_data'          => undef,                 # Authentication data
      '_auth_key'           => undef,                 # authKey 
      '_auth_password'      => undef,                 # Authentication password 
      '_auth_protocol'      => AUTH_PROTOCOL_HMACMD5, # authProtocol
      '_priv_data'          => undef,                 # Privacy data
      '_priv_key'           => undef,                 # privKey 
      '_priv_password'      => undef,                 # Privacy password
      '_priv_protocol'      => PRIV_PROTOCOL_DES,     # privProtocol
      '_security_level'     => SECURITY_LEVEL_NOAUTHNOPRIV
   }, $class;

   # We first need to find out if we are an authoritative SNMP
   # engine and set the authProtocol and privProtocol if they 
   # have been provided.

   foreach (keys %argv) {

      if (/^-?authoritative$/i) {
         $this->{_authoritative} = (delete($argv{$_})) ? TRUE : FALSE;
      } elsif (/^-?authprotocol$/i) {
         $this->_auth_protocol(delete($argv{$_}));
      } elsif (/^-?privprotocol$/i) {
         $this->_priv_protocol(delete($argv{$_}));
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
      $this->{_engine_boots} = 1;
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

   # AES in the USM Section 3.1.2.1 - "The 128-bit IV is obtained as
   # the concatenation of the... ...snmpEngineBoots, ...snmpEngineTime,
   # and a local 64-bit integer.  We store the current snmpEngineBoots
   # and snmpEngineTime before encrypting the PDU so that the computed
   # IV matches the transmitted msgAuthoritativeEngineBoots and
   # msgAuthoritativeEngineTime.

   my $msg_engine_time  = $this->_engine_time;
   my $msg_engine_boots = $this->_engine_boots;

   # Copy the PDU into a "plain text" buffer
   my $pdu_buffer  = $pdu->copy;
   my $priv_params = '';

   # encryptedPDU::=OCTET STRING
   if ($this->{_security_level} > SECURITY_LEVEL_AUTHNOPRIV) {
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

   if ($this->{_security_level} > SECURITY_LEVEL_NOAUTHNOPRIV) {
   
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
   if (!defined($msg->prepare(INTEGER, $msg_engine_time))) {
      return $this->_error($msg->error);
   }

   # msgAuthoritativeEngineBoots::=INTEGER
   if (!defined($msg->prepare(INTEGER, $msg_engine_boots))) {
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
   if ($this->{_security_level} > SECURITY_LEVEL_NOAUTHNOPRIV) {
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

   my $msg_params = $msg->process(OCTET_STRING);
   return $this->_error($msg->error) unless defined($msg_params);

   # Need to move the buffer index back to the begining of the data
   # portion of the OCTET STRING that contains the msgSecurityParameters.

   $msg->index($msg->index - length($msg_params));

   # UsmSecurityParameters::=SEQUENCE
   return $this->_error($msg->error) unless defined($msg->process(SEQUENCE));

   # msgAuthoritativeEngineID::=OCTET STRING
   my $msg_engine_id;
   if (!defined($msg_engine_id = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error);
   }

   # msgAuthoritativeEngineBoots::=INTEGER (0..2147483647)
   my $msg_engine_boots;
   if (!defined($msg_engine_boots = $msg->process(INTEGER))) {
      return $this->_error($msg->error); 
   }
   if (($msg_engine_boots < 0) || ($msg_engine_boots > 2147483647)) {
      return $this->_error(
         'Invalid incoming msgAuthoritativeEngineBoots value [%d]', 
         $msg_engine_boots 
      );
   }

   # msgAuthoritativeEngineTime::=INTEGER (0..2147483647)
   my $msg_engine_time;
   if (!defined($msg_engine_time = $msg->process(INTEGER))) {
      return $this->_error($msg->error);
   }
   if (($msg_engine_time < 0) || ($msg_engine_time > 2147483647)) {
      return $this->_error(
         'Invalid incoming msgAuthoritativeEngineTime value [%d]', 
         $msg_engine_time
      );
   }

   # msgUserName::=OCTET STRING (SIZE(0..32))
   my $msg_user_name;
   if (!defined($msg_user_name = $msg->process(OCTET_STRING))) {
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
      if ($len != 12) {
         return $this->_error(
            'Invalid incoming msgAuthenticationParameters length [%d octet%s]',
            $len, $len != 1 ? 's' : ''
         );
      }
      substr(${$msg->reference}, ($msg->index - 12), 12) = pack('x12');
   }

   # msgPrivacyParameters::=OCTET STRING
   my $priv_params;
   if (!defined($priv_params = $msg->process(OCTET_STRING))) {
      return $this->_error($msg->error); 
   }

   # Validate the msgAuthoritativeEngineID and msgUserName
  
   if ($this->{_discovered}) {

      if ($msg_engine_id ne $this->_engine_id) {
         return $this->_error(
            'Unknown incoming msgAuthoritativeEngineID [%s]', 
            unpack('H*', $msg_engine_id)
         );
      }

      if ($msg_user_name ne $this->_user_name) {
         return $this->_error(
            'Unknown incoming msgUserName [%s]', $msg_user_name
         );
      }

   } else {

      # Handle authoritativeEngineID discovery
      if (!defined($this->_engine_id_discovery($msg_engine_id))) {
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

      # RFC 3412 - Section 7.2 1d: "If the authFlag is not set  
      # and privFlag is set... ...the message is discarded..."

      return $this->_error('Invalid incoming msgFlags [0x%02x]', $msg_flags);
   } 

   # RFC 3412 - Section 7.2 1e: "Any other bits... ...are ignored."
   if ($msg_flags & ~MSG_FLAGS_MASK) {
      DEBUG_INFO('questionable msgFlags [0x%02x]', $msg_flags);
   }

   # Validate the incoming securityLevel

   if ($security_level > $this->{_security_level}) {
      return $this->_error('Unsupported securityLevel [%d]', $security_level);
   }

 
   if ($security_level > SECURITY_LEVEL_NOAUTHNOPRIV) {

      # Authenticate the message
      if (!defined($this->_authenticate_incoming_msg($msg, $auth_params))) { 
         return $this->_error;
      }

      # Synchronize the time
      if (!$this->_synchronize($msg_engine_boots, $msg_engine_time)) {
         return $this->_error;
      }

      # Check for timeliness
      if (!defined($this->_timeliness($msg_engine_boots, $msg_engine_time))) {
         return $this->_error;
      }

      if ($security_level > SECURITY_LEVEL_AUTHNOPRIV) {

         # Validate the msgPrivacyParameters length.

         if (length($priv_params) != 8) {
            return $this->_error(
               'Invalid incoming msgPrivacyParameters length [%d octet%s]', 
               length($priv_params), length($priv_params) != 1 ? 's' : '' 
            );
         }

         # AES in the USM Section 3.1.2.1 - "The 128-bit IV is
         # obtained as the concatenation of the... ...snmpEngineBoots,
         # ...snmpEngineTime, and a local 64-bit integer.  ...The
         # 64-bit integer must be placed in the msgPrivacyParameters
         # field..."  We must prepend the snmpEngineBoots and
         # snmpEngineTime as received in order to compute the IV.

         if (($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB128) ||
             ($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB192) ||
             ($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB256))
         {
            substr($priv_params, 0, 0) = pack(
               'NN', $msg_engine_boots, $msg_engine_time
            );
         }

         # encryptedPDU::=OCTET STRING

         $this->_decrypt_data($msg, $priv_params, $msg->process(OCTET_STRING));

      } else {

         TRUE;

      }

   } else {

      TRUE;

   }
}

sub user_name
{
   $_[0]->{_user_name};
}

sub auth_protocol
{
   if ($_[0]->{_security_level} > SECURITY_LEVEL_NOAUTHNOPRIV) {
      $_[0]->{_auth_protocol};
   } else {
      AUTH_PROTOCOL_NONE;
   }
}

sub auth_key
{
   $_[0]->{_auth_key};
}

sub priv_protocol
{
   if ($_[0]->{_security_level} > SECURITY_LEVEL_AUTHNOPRIV) {
      $_[0]->{_priv_protocol};
   } else {
      PRIV_PROTOCOL_NONE;
   }
}

sub priv_key
{
   $_[0]->{_priv_key};
}

sub engine_id
{
   $_[0]->{_engine_id};
}

sub engine_boots
{
   $_[0]->_engine_boots;
}

sub engine_time
{
   $_[0]->_engine_time;
}

sub security_level
{
   $_[0]->{_security_level};
}

sub security_model
{
   # RFC 3411 - SnmpSecurityModel::=TEXTUAL-CONVENTION

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
         return $_[0]->_error('Invalid authoritativeEngineID format specified');
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
         return $_[0]->_error(
            'Invalid userName length [%d octet%s]', 
            length($_[1]), length($_[1]) != 1 ? 's' : ''
         );
      }
      $_[0]->{_user_name} = $_[1];
   }

   # RFC 3414 Section 4 - "Discovery... ...msgUserName of zero-length..."

   ($_[0]->{_discovered}) ? $_[0]->{_user_name} : '';
}

sub _auth_key
{
   if (@_ == 2) {
      if ($_[1] =~ /^(?i:0x)?([a-fA-F0-9]+)$/) {
         $_[0]->{_auth_key} = pack('H*', length($1) % 2 ? '0'.$1 : $1); 
         if (!defined($_[0]->_auth_key_validate)) {
            return $_[0]->_error;
         }
      } else {
         return $_[0]->_error('Invalid authKey format specified');
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
         'md5',                 AUTH_PROTOCOL_HMACMD5,
         'hmacmd5',             AUTH_PROTOCOL_HMACMD5,
         AUTH_PROTOCOL_HMACMD5, AUTH_PROTOCOL_HMACMD5,
         'sha1',                AUTH_PROTOCOL_HMACSHA,
         'hmacsha',             AUTH_PROTOCOL_HMACSHA,
         AUTH_PROTOCOL_HMACSHA, AUTH_PROTOCOL_HMACSHA 
      };

      if ($proto eq '') {
         return $this->_error('Empty authProtocol specified');
      }

      my @match = grep(/^\Q$proto/i, keys(%{$protocols}));

      if (@match > 1) {
         return $this->_error('Ambiguous authProtocol specified [%s]', $proto);
      }

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

      if ($_[1] =~ /^(?i:0x)?([a-fA-F0-9]+)$/) {

         $_[0]->{_priv_key} = pack('H*', length($1) % 2 ? '0'.$1 : $1);

         # For backwards compatibility with previous versions of
         # this module truncate 20 byte SHA1 keys to 16 bytes. 

         if (length($_[0]->{_priv_key}) == 20) {
            $_[0]->{_priv_key} = substr($_[0]->{_priv_key}, 0, 16);
         }

         if (!defined($_[0]->_priv_key_validate)) {
            return $_[0]->_error;
         }

      } else {

         return $_[0]->_error('Invalid privKey format specified');

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

sub _priv_protocol
{
   my ($this, $proto) = @_;

   if (@_ == 2) {

      my $protocols = {
         'des',                   PRIV_PROTOCOL_DES,
         'cbcdes',                PRIV_PROTOCOL_DES,
         PRIV_PROTOCOL_DES,       PRIV_PROTOCOL_DES,
         '3desede',               PRIV_PROTOCOL_3DESEDE,
         'cbc3desede',            PRIV_PROTOCOL_3DESEDE,
         PRIV_PROTOCOL_3DESEDE,   PRIV_PROTOCOL_3DESEDE,
         'aes128cfb',             PRIV_PROTOCOL_AESCFB128,
         'aescfb128',             PRIV_PROTOCOL_AESCFB128,
         PRIV_PROTOCOL_AESCFB128, PRIV_PROTOCOL_AESCFB128,
         'aes192cfb',             PRIV_PROTOCOL_AESCFB192,
         'aescfb192',             PRIV_PROTOCOL_AESCFB192,
         PRIV_PROTOCOL_AESCFB192, PRIV_PROTOCOL_AESCFB192,
         'aes256cfb',             PRIV_PROTOCOL_AESCFB256,
         'aescfb256',             PRIV_PROTOCOL_AESCFB256,
         PRIV_PROTOCOL_AESCFB256, PRIV_PROTOCOL_AESCFB256,
      };

      if ($proto eq '') {
         return $this->_error('Empty privProtocol specified');
      }

      my @match = grep(/^\Q$proto/i, keys(%{$protocols}));

      if (@match > 1) {
         return $this->_error('Ambiguous privProtocol specified [%s]', $proto);
      }

      if (@match != 1) {
         return $this->_error('Unknown privProtocol specified [%s]', $proto);
      }

      $this->{_priv_protocol} = $protocols->{$match[0]};

      # Validate the support of the AES cipher algorithm.

      if (defined($NO_AES_SUPPORT) &&
          (($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB128) ||
           ($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB192) ||
           ($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB256)))
      {
         return $this->_error(
            'No support for privProtocol [%s]' . $NO_AES_SUPPORT, $proto
         ); 
      }
   }

   $this->{_priv_protocol};
}

sub _engine_boots
{
   ($_[0]->{_synchronized}) ? $_[0]->{_engine_boots} : 0;
}

sub _engine_time
{
   my ($this) = @_;

   return 0 unless ($this->{_synchronized});

   $this->{_engine_time} = time() - $this->{_time_epoc};

   if ($this->{_engine_time} > 2147483647) {
      DEBUG_INFO('snmpEngineTime rollover');
      if (++$this->{_engine_boots} == 2147483647) {
         die('FATAL: Unable to handle snmpEngineBoots value');
      }
      $this->{_engine_time} -= 2147483647;
      $this->{_time_epoc} = time() - $this->{_engine_time};
      if (!$this->{_authoritative}) {
         $this->{_synchronized} = FALSE;
         return $this->{_latest_engine_time} = 0;
      } 
   }

   if ($this->{_engine_time} < 0) {
      die('FATAL: Unable to handle snmpEngineTime value');
   }

   $this->{_engine_time};
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

   # Define the authentication parameters

   if ((defined($this->{_auth_password})) && ($this->{_discovered})) {
      if (!defined($this->{_auth_key})) {
         return $this->_error unless defined($this->_auth_key_generate);
      }
      $this->{_auth_password} = undef;
   }

   if (defined($this->{_auth_key})) {

      # Validate the key based on the protocol
      if (!defined($this->_auth_key_validate)) {
         return $this->_error('Invalid authKey specified');
      }

      # Initialize the authentication data 
      if (!defined($this->_auth_data_init)) {
         return $this->_error('Failed to initialize authentication data');
      }

      if ($this->{_discovered}) {
         $this->{_security_level} = SECURITY_LEVEL_AUTHNOPRIV;
      }

   }

   # You must have authentication to have privacy

   if (!defined($this->{_auth_key}) && !defined($this->{_auth_password})) {
      if (defined($this->{_priv_key}) || defined($this->{_priv_password})) {
         return $this->_error(
            'Unsupported securityLevel (privacy requires authentication)'
         );
      }
   }

   # Define the privacy parameters

   if ((defined($this->{_priv_password})) && ($this->{_discovered})) {
      if (!defined($this->{_priv_key})) {
         return $this->_error unless defined($this->_priv_key_generate);
      }
      $this->{_priv_password} = undef;
   }

   if (defined($this->{_priv_key})) {

      # Validate the key based on the protocol
      if (!defined($this->_priv_key_validate)) {
         return $this->_error('Invalid privKey specified');
      }

      # Initialize the privacy data 
      if (!defined($this->_priv_data_init)) {
         return $this->_error('Failed to initialize privacy data');
      }

      if ($this->{_discovered}) {
         $this->{_security_level} = SECURITY_LEVEL_AUTHPRIV;
      }

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
         'Invalid incoming msgAuthoritativeEngineID length [%d octet%s]', 
         length($engine_id), length($engine_id) != 1 ? 's' : ''
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

      TRUE;

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

   if (!$this->{_authoritative}) {

      if ($msg_boots < $engine_boots) {
         return $this->_error('Incoming message not in time window');
      }
      if (($msg_boots == $engine_boots) && ($msg_time < ($engine_time - 150))) {
         return $this->_error('Incoming message not in time window');
      }

   } else {

      if ($msg_boots != $engine_boots) {
         return $this->_error('Incoming message not in time window');
      }
      if (($msg_time < ($engine_time - 150)) ||
          ($msg_time > ($engine_time + 150)))
      {
         return $this->_error('Incoming message not in time window');
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

   # Set the msgAuthenticationParameters
   substr(${$msg->reference}, -$auth_location, 12) = $this->_auth_hmac($msg); 
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
#  my ($this, $msg) = @_;

   return '' unless defined($_[0]->{_auth_data}) && defined($_[1]);

   substr($_[0]->{_auth_data}->reset->add(${$_[1]->reference})->digest, 0, 12);
}

sub _auth_data_init
{
   my ($this) = @_;

   if (!defined($this->{_auth_key})) {
      return $this->_error('Required authKey not defined');
   }

   return $this->{_auth_data} if defined($this->{_auth_data});

   if ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACMD5) {

      $this->{_auth_data} =
         Digest::HMAC->new($this->{_auth_key}, 'Digest::MD5');

   } elsif ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACSHA) {

      $this->{_auth_data} = 
         Digest::HMAC->new($this->{_auth_key}, 'Digest::SHA1');

   } else {

      return $this->_error(
         'Unknown authProtocol [%s]', $this->{_auth_protocol}
      );

   }
} 

{
   my $encrypt = 
   {
      PRIV_PROTOCOL_DES,       \&_priv_encrypt_des,          
      PRIV_PROTOCOL_3DESEDE,   \&_priv_encrypt_3desede,
      PRIV_PROTOCOL_AESCFB128, \&_priv_encrypt_aescfbxxx,
      PRIV_PROTOCOL_AESCFB192, \&_priv_encrypt_aescfbxxx,
      PRIV_PROTOCOL_AESCFB256, \&_priv_encrypt_aescfbxxx
   };

   sub _encrypt_data
   {
   #  my ($this, $msg, $priv_params, $plain) = @_;

      if (!exists($encrypt->{$_[0]->{_priv_protocol}})) {
         return $_[0]->_error('Encryption error (Unknown protocol)');
      }

      if (!defined(
            $_[1]->prepare(
               OCTET_STRING, 
               $_[0]->${\$encrypt->{$_[0]->{_priv_protocol}}}($_[2], $_[3])
            )
         ))
      {
         return $_[0]->_error('Encryption error');
      }

      # Set the PDU buffer equal to the encryptedPDU
      $_[3] = $_[1]->clear;
   }
}

{
   my $decrypt =
   {
      PRIV_PROTOCOL_DES,       \&_priv_decrypt_des,
      PRIV_PROTOCOL_3DESEDE,   \&_priv_decrypt_3desede,
      PRIV_PROTOCOL_AESCFB128, \&_priv_decrypt_aescfbxxx,
      PRIV_PROTOCOL_AESCFB192, \&_priv_decrypt_aescfbxxx,
      PRIV_PROTOCOL_AESCFB256, \&_priv_decrypt_aescfbxxx
   };

   sub _decrypt_data
   {
   #  my ($this, $msg, $priv_params, $cipher) = @_;

      # Make sure there is data to decrypt.
      if (!defined($_[3])) {
         return $_[0]->_error($_[1]->error || 'Decryption error (No data)');
      }

      if (!exists($decrypt->{$_[0]->{_priv_protocol}})) {
         return $_[0]->_error('Decryption error (Unknown protocol)');
      }

      # Clear the Message buffer
      $_[1]->clear;

      # Put the decrypted data back into the Message buffer
      if (!defined(
            $_[1]->prepend(
               $_[0]->${\$decrypt->{$_[0]->{_priv_protocol}}}($_[2], $_[3])
            )
         )) 
      {
         return $_[0]->_error($_[1]->error);
      }
      return $_[0]->_error($_[1]->error) unless ($_[1]->length);

      # See if the decrypted data starts with a SEQUENCE
      if (!defined($_[1]->process(SEQUENCE))) {
         return $_[0]->_error('Decryption error');
      }
      $_[1]->index(0); # Reset the index

      DEBUG_INFO('privacy passed');

      TRUE;
   }
}

sub _priv_data_init
{
   my ($this) = @_;

   if (!defined($this->{_priv_key})) {
      return $this->_error('Required privKey not defined');
   }

   return TRUE if defined($this->{_priv_data}); 

   my $init =
   {
      PRIV_PROTOCOL_DES,       \&_priv_data_init_des,
      PRIV_PROTOCOL_3DESEDE,   \&_priv_data_init_3desede,
      PRIV_PROTOCOL_AESCFB128, \&_priv_data_init_aescfbxxx,
      PRIV_PROTOCOL_AESCFB192, \&_priv_data_init_aescfbxxx,
      PRIV_PROTOCOL_AESCFB256, \&_priv_data_init_aescfbxxx
   };

   if (!exists($init->{$this->{_priv_protocol}})) {
      return $this->_error(
         'Unknown privProtocol [%s]', $this->{_priv_protocol}
      );
   }

   $this->${\$init->{$this->{_priv_protocol}}}();
}

sub _priv_data_init_des
{
   my ($this) = @_;

   if (!defined($this->{_priv_key})) {
      return $this->_error('Required privKey not defined');
   }

   # Create the DES object
   $this->{_priv_data}->{des} = 
      Crypt::DES->new(substr($this->{_priv_key}, 0, 8));

   # Extract the pre-IV
   $this->{_priv_data}->{pre_iv} = substr($this->{_priv_key}, 8, 8);

   # Initialize the salt
   $this->{_priv_data}->{salt} = int(rand(~0));
 
   TRUE;
}

sub _priv_encrypt_des
{
#  my ($this, $priv_params, $plain) = @_;

   if (!defined($_[0]->{_priv_data})) {
      return $_[0]->_error('Required privacy data not defined');
   }

   # Always pad the plain text data.  "The actual pad value is 
   # irrelevant..." according RFC 3414 Section 8.1.1.2.  However,
   # there are some agents out there that expect "standard block
   # padding" where each of the padding byte(s) are set to the size 
   # of the padding (even for data that is a multiple of block size).

   my $pad = 8 - (length($_[2]) % 8);
   $_[2] .= pack('C', $pad) x $pad;

   # Create and set the salt
   if (++$_[0]->{_priv_data}->{salt} == ~0) {
      $_[0]->{_priv_data}->{salt} = 0;
   }
   $_[1] = pack('NN', $_[0]->{_engine_boots}, $_[0]->{_priv_data}->{salt});

   # Create the initial vector (IV)
   my $iv = $_[0]->{_priv_data}->{pre_iv} ^ $_[1];

   my $cipher = '';

   # Perform Cipher Block Chaining (CBC) 
   while($_[2] =~ /(.{8})/gs) {
      $cipher .= $iv = $_[0]->{_priv_data}->{des}->encrypt($1 ^ $iv);
   }

   $cipher;
}

sub _priv_decrypt_des
{
#  my ($this, $priv_params, $cipher) = @_;

   if (!defined($_[0]->{_priv_data})) {
      return $_[0]->_error('Required privacy data not defined');
   }

   if (length($_[1]) != 8) {
      return $_[0]->_error(
        'Invalid msgPrivParameters length [%d octet%s]', 
        length($_[1]), length($_[1]) != 1 ? 's' : ''
      );
   }

   if (length($_[2]) % 8) {
      return $_[0]->_error('DES cipher length not multiple of block size');
   }

   # Create the initial vector (IV)
   my $iv = $_[0]->{_priv_data}->{pre_iv} ^ $_[1];

   my $plain = '';

   # Perform Cipher Block Chaining (CBC) 
   while ($_[2] =~ /(.{8})/gs) {
      $plain .= $iv ^ $_[0]->{_priv_data}->{des}->decrypt($1);
      $iv = $1;
   }

   $plain;
}

sub _priv_data_init_3desede
{
   my ($this) = @_;

   if (!defined($this->{_priv_key})) {
      return $this->_error('Required privKey not defined');
   }

   # Create the 3 DES objects

   $this->{_priv_data}->{des1} =
      Crypt::DES->new(substr($this->{_priv_key}, 0, 8));
   $this->{_priv_data}->{des2} =
      Crypt::DES->new(substr($this->{_priv_key}, 8, 8));
   $this->{_priv_data}->{des3} =
      Crypt::DES->new(substr($this->{_priv_key}, 16, 8));

   # Extract the pre-IV
   $this->{_priv_data}->{pre_iv} = substr($this->{_priv_key}, 24, 8);

   # Initialize the salt
   $this->{_priv_data}->{salt} = int(rand(~0));

   # Assign a hash algorithm to "bit spread" the salt

   if ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACMD5) {
      $this->{_priv_data}->{hash} = Digest::MD5->new;
   } elsif ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACSHA) {
      $this->{_priv_data}->{hash} = Digest::SHA1->new;
   }

   TRUE;
}

sub _priv_encrypt_3desede
{
#  my ($this, $priv_params, $plain) = @_;

   if (!defined($_[0]->{_priv_data})) {
      return $_[0]->_error('Required privacy data not defined');
   }

   # Pad the plain text data using "standard block padding". 
   my $pad = 8 - (length($_[2]) % 8);
   $_[2] .= pack('C', $pad) x $pad;

   # Create and set the salt
   if (++$_[0]->{_priv_data}->{salt} == ~0) {
      $_[0]->{_priv_data}->{salt} = 0;
   }
   $_[1] = pack('NN', $_[0]->{_engine_boots}, $_[0]->{_priv_data}->{salt});

   # 3DES-EDE for USM Section 5.1.1.1.2 - "To achieve effective 
   # bit spreading, the complete 8-octet 'salt' value SHOULD be 
   # hashed using the usmUserAuthProtocol."

   if (exists($_[0]->{_priv_data}->{hash})) {
      $_[1] = substr($_[0]->{_priv_data}->{hash}->add($_[1])->digest, 0, 8);
   }

   # Create the initial vector (IV)
   my $iv = $_[0]->{_priv_data}->{pre_iv} ^ $_[1];

   my $cipher = '';

   # Perform Cipher Block Chaining (CBC)
   while($_[2] =~ /(.{8})/gs) {
      $cipher .= $iv =
         $_[0]->{_priv_data}->{des3}->encrypt(
            $_[0]->{_priv_data}->{des2}->decrypt(
               $_[0]->{_priv_data}->{des1}->encrypt($1 ^ $iv)
            )
         );
   }

   $cipher;
}

sub _priv_decrypt_3desede
{
#  my ($this, $priv_params, $cipher) = @_;

   if (!defined($_[0]->{_priv_data})) {
      return $_[0]->_error('Required privacy data not defined');
   }

   if (length($_[1]) != 8) {
      return $_[0]->_error(
        'Invalid msgPrivParameters length [%d octet%s]',
        length($_[1]), length($_[1]) != 1 ? 's' : ''
      );
   }

   if (length($_[2]) % 8) {
      return $_[0]->_error('3DES-EDE cipher length not multiple of block size');
   }

   # Create the initial vector (IV)
   my $iv = $_[0]->{_priv_data}->{pre_iv} ^ $_[1];

   my $plain = '';

   # Perform Cipher Block Chaining (CBC) 
   while ($_[2] =~ /(.{8})/gs) {
      $plain .= 
         $iv ^ $_[0]->{_priv_data}->{des1}->decrypt(
                  $_[0]->{_priv_data}->{des2}->encrypt(
                     $_[0]->{_priv_data}->{des3}->decrypt($1)
                  )
               );
      $iv = $1;
   }

   $plain;
}

sub _priv_data_init_aescfbxxx
{
   my ($this) = @_;

   if (!defined($this->{_priv_key})) {
      return $this->_error('Required privKey not defined');
   }

   # Create the AES (Rijndael) object with a 128, 192, or 256 bit key.

   $this->{_priv_data}->{aes} = 
      Crypt::Rijndael->new($this->{_priv_key}, Crypt::Rijndael::MODE_CFB);

   # Initialize the salt
   $this->{_priv_data}->{salt1} = int(rand(~0));
   $this->{_priv_data}->{salt2} = int(rand(~0));

   TRUE;
}

sub _priv_encrypt_aescfbxxx
{
#  my ($this, $priv_params, $plain) = @_;

   if (!defined($_[0]->{_priv_data})) {
      return $_[0]->_error('Required privacy data not defined');
   }

   # Validate the plain text length
   my $length = length($_[2]);
   if ($length <= 16) {
      return $_[0]->_error('AES plain text length not greater than block size');
   }

   # Create and set the salt
   if (++$_[0]->{_priv_data}->{salt1} == ~0) {
      $_[0]->{_priv_data}->{salt1} = 0;
      if (++$_[0]->{_priv_data}->{salt2} == ~0) {
         $_[0]->{_priv_data}->{salt2} = 0;
      }
   }
   $_[1] = pack(
      'NN', $_[0]->{_priv_data}->{salt2}, $_[0]->{_priv_data}->{salt1}
   );

   # AES in the USM Section - Section 3.1.3 "The last ciphertext 
   # block is produced by exclusive-ORing the last plaintext segment 
   # of r bits (r is less or equal to 128) with the segment of the r 
   # most significant bits of the last output block."  
   
   # This operation is identical to those performed on the previous 
   # blocks except for the fact that the block can be less than the 
   # block size.  We can just pad the last block and operate on it as 
   # usual and then ignore the padding after encrypting.

   $_[2] .= "\000" x (16 - ($length % 16));

   # Create the IV by concatenating "...the generating SNMP engine's 
   # 32-bit snmpEngineBoots, the SNMP engine's 32-bit  snmpEngineTime, 
   # and a local 64-bit integer..." 

   $_[0]->{_priv_data}->{aes}->set_iv(
      pack('NN', $_[0]->{_engine_boots}, $_[0]->{_engine_time}) . $_[1]
   );

   # Let the Crypt::Rijndael module perform 128 bit Cipher Feedback 
   # (CFB) and return the result minus the "internal" padding.

   substr($_[0]->{_priv_data}->{aes}->encrypt($_[2]), 0, $length);
}

sub _priv_decrypt_aescfbxxx
{
#  my ($this, $priv_params, $cipher) = @_;

   if (!defined($_[0]->{_priv_data})) {
      return $_[0]->_error('Required privacy data not defined');
   }

   # Validate the msgPrivParameters length.  We assume that the
   # msgAuthoritativeEngineBoots and msgAuthoritativeEngineTime
   # have been prepended to the msgPrivParameters to create the
   # required 128 bit IV.

   if (length($_[1]) != 16) {
       return $_[0]->_error(
          'Invalid AES IV length [%d octet%s]', 
          length($_[1]), (length($_[1]) != 1) ? 's' : ''
       );
   }

   # Validate the cipher length
   my $length = length($_[2]);
   if ($length <= 16) {
      return $_[0]->_error('AES cipher length not greater than block size');
   }

   # AES in the USM Section - Section 3.1.4 "The last ciphertext 
   # block (whose size r is less or equal to 128) is less or equal 
   # to 128) is exclusive-ORed with the segment of the r most 
   # significant bits of the last output block to recover the last 
   # plaintext block of r bits."

   # This operation is identical to those performed on the previous
   # blocks except for the fact that the block can be less than the
   # block size.  We can just pad the last block and operate on it as
   # usual and then ignore the padding after decrypting.

   $_[2] .= "\000" x (16 - ($length % 16));

   # Use the msgPrivParameters as the IV.
   $_[0]->{_priv_data}->{aes}->set_iv($_[1]); 

   # Let the Crypt::Rijndael module perform 128 bit Cipher Feedback
   # (CFB) and return the result minus the "internal" padding.

   substr($_[0]->{_priv_data}->{aes}->decrypt($_[2]), 0, $length);
}

sub _auth_key_generate
{
   my ($this) = @_;

   if (!defined($this->{_engine_id}) || !defined($this->{_auth_password})) {
      return $this->_error('Unable to generate authKey');
   }

   $this->{_auth_key} = $this->_password_localize($this->{_auth_password});
}

sub _auth_key_validate
{
   my ($this) = @_;

   my $key_len =
   {
      AUTH_PROTOCOL_HMACMD5,    [ 16, 'HMAC-MD5'  ],
      AUTH_PROTOCOL_HMACSHA,    [ 20, 'HMAC-SHA1' ],
   };

   if (!exists($key_len->{$this->{_auth_protocol}})) {
      return $this->_error(
         'Unknown authProtocol [%s]', $this->{_auth_protocol}
      );
   }

   if (length($this->{_auth_key}) != $key_len->{$this->{_auth_protocol}}->[0])
   {
      return $this->_error(
         'Invalid %s authKey length [%d octet%s]',
         $key_len->{$this->{_auth_protocol}}->[1], 
         length($this->{_auth_key}), length($this->{_auth_key}) != 1 ? 's' : '' 
      );
   }

   TRUE;
}

sub _priv_key_generate
{
   my ($this) = @_;

   if (!defined($this->{_engine_id}) || !defined($this->{_priv_password})) {
      return $this->_error('Unable to generate privKey');
   }

   $this->{_priv_key} = $this->_password_localize($this->{_priv_password});

   return $this->_error unless defined($this->{_priv_key});

   if ($this->{_priv_protocol} eq PRIV_PROTOCOL_3DESEDE) {

      # 3DES-EDE for USM Section 2.1 - "To acquire the necessary
      # number of key bits, the password-to-key algorithm may be
      # chained using its output as further input in order to
      # generate an appropriate number of key bits."

      $this->{_priv_key} .= $this->_password_localize($this->{_priv_key}); 

   } elsif (($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB192) ||
            ($this->{_priv_protocol} eq PRIV_PROTOCOL_AESCFB256))
   {
      # AES in the USM Section 3.1.2.1 - "...if the size of the 
      # localized key is not large enough to generate an encryption 
      # key... ...set Kul = Kul || Hnnn(Kul) where Hnnn is the hash 
      # function for the authentication protocol..."

      my $hnnn;

      if ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACMD5) {
         $hnnn = Digest::MD5->new;
      } elsif ($this->{_auth_protocol} eq AUTH_PROTOCOL_HMACSHA) {
         $hnnn = Digest::SHA1->new;
      } else {
         return $this->_error(
            'Unknown authProtocol [%s]', $this->{_auth_protocol}
         );
      }

      $this->{_priv_key} .= $hnnn->add($this->{_priv_key})->digest;

   }

   # Truncate the privKey to the appropriate length.

   my $key_len =
   {
      PRIV_PROTOCOL_DES,        16,  # RFC 3414 Section 8.2.1
      PRIV_PROTOCOL_3DESEDE,    32,  # 3DES-EDE for USM Section 5.2.1
      PRIV_PROTOCOL_AESCFB128,  16,  # AES in the USM Section 3.2.1
      PRIV_PROTOCOL_AESCFB192,  24,  # AES in the USM Section 3.2.1
      PRIV_PROTOCOL_AESCFB256,  32   # AES in the USM Section 3.2.1
   };

   if (!exists($key_len->{$this->{_priv_protocol}})) {
      return $this->_error(
         'Unknown privProtocol [%s]', $this->{_priv_protocol}
      );
   }

   $this->{_priv_key} = 
      substr($this->{_priv_key}, 0, $key_len->{$this->{_priv_protocol}}); 
}

sub _priv_key_validate
{
   my ($this) = @_;

   my $key_len =
   {
      PRIV_PROTOCOL_DES,        [ 16, 'DES'         ],  
      PRIV_PROTOCOL_3DESEDE,    [ 32, '3DES-EDE'    ], 
      PRIV_PROTOCOL_AESCFB128,  [ 16, 'AES-CFB-128' ],
      PRIV_PROTOCOL_AESCFB192,  [ 24, 'AES-CFB-192' ],
      PRIV_PROTOCOL_AESCFB256,  [ 32, 'AES-CFB-256' ]
   };

   if (!exists($key_len->{$this->{_priv_protocol}})) {
      return $this->_error(
         'Unknown privProtocol [%s]', $this->{_priv_protocol}
      );
   }

   if (length($this->{_priv_key}) != $key_len->{$this->{_priv_protocol}}->[0])
   {
      return $this->_error(
         'Invalid %s privKey length [%d octet%s]',
         $key_len->{$this->{_priv_protocol}}->[1], 
         length($this->{_priv_key}), length($this->{_priv_key}) != 1 ? 's' : ''
      );
   }
  
   if ($this->{_priv_protocol} eq PRIV_PROTOCOL_3DESEDE) {

      # 3DES-EDE for USM Section 5.1.1.1.1 "The checks for difference 
      # and weakness... ...should be performed when the key is assigned.
      # If any of the mandated tests fail, then the whole key MUST be 
      # discarded and an appropriate exception noted."

      if (substr($this->{_priv_key}, 0, 8) eq substr($this->{_priv_key}, 8, 8)) 
      {
         return $this->_error('Invalid 3DES-EDE privKey [K1 equals K2]');
      }

      if (substr($this->{_priv_key}, 8, 8) eq substr($this->{_priv_key}, 16, 8))
      {
         return $this->_error('Invalid 3DES-EDE privKey [K2 equals K3]');
      }

      if (substr($this->{_priv_key}, 0, 8) eq substr($this->{_priv_key}, 16, 8))
      {
         return $this->_error('Invalid 3DES-EDE privKey [K1 equals K3]');
      }

   }

   TRUE;
}

sub _password_localize
{
   my ($this, $password) = @_;

   my $digests =
   {
      AUTH_PROTOCOL_HMACMD5,  'Digest::MD5',
      AUTH_PROTOCOL_HMACSHA,  'Digest::SHA1',
   };

   if (!exists($digests->{$this->{_auth_protocol}})) {
      return $this->_error(
         'Unknown authProtocol [%s]', $this->{_auth_protocol}
      );
   }

   my $digest = $digests->{$this->{_auth_protocol}}->new;

   # Create the initial digest using the password

   my $d = my $pad = $password x ((2048 / length($password)) + 1);

   for (my $count = 0; $count < 2**20; $count += 2048) {
      $digest->add(substr($d, 0, 2048, ''));
      $d .= $pad;
   }
   $d = $digest->digest;

   # Localize the key with the authoritativeEngineID

   $digest->add($d . $this->{_engine_id} . $d)->digest;
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
