# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::Message;

# $Id: Message.pm,v 1.3 2002/01/01 14:03:44 dtown Exp $

# Object used to represent a SNMP message. 

# Copyright (c) 2001-2002 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Math::BigInt();

## Version of the Net::SNMP::Message module

our $VERSION = v1.0.1;

## Handle exporting of symbols

use Exporter();

our @ISA = qw(Exporter);

our @ASN1_TYPES = qw(
   INTEGER INTEGER32 OCTET_STRING NULL OBJECT_IDENTIFIER SEQUENCE
   IPADDRESS COUNTER COUNTER32 GAUGE GAUGE32 UNSIGNED32 TIMETICKS
   OPAQUE COUNTER64 NOSUCHOBJECT NOSUCHINSTANCE ENDOFMIBVIEW
   GET_REQUEST GET_NEXT_REQUEST GET_RESPONSE SET_REQUEST TRAP
   GET_BULK_REQUEST INFORM_REQUEST SNMPV2_TRAP REPORT
);

our @GENERICTRAP = qw(
   COLD_START WARM_START LINK_DOWN LINK_UP AUTHENTICATION_FAILURE
   EGP_NEIGHBOR_LOSS ENTERPRISE_SPECIFIC
);

our @MSG_FLAGS = qw(
   MSG_FLAGS_NOAUTHNOPRIV MSG_FLAGS_AUTH MSG_FLAGS_PRIV
   MSG_FLAGS_REPORTABLE MSG_FLAGS_MASK
);

our @SECURITY_MODELS = qw(
   SECURITY_MODEL_ANY SECURITY_MODEL_SNMPV1 SECURITY_MODEL_SNMPV2C 
   SECURITY_MODEL_USM
);

our @SECURITY_LEVELS = qw(
   SECURITY_LEVEL_NOAUTHNOPRIV SECURITY_LEVEL_AUTHNOPRIV 
   SECURITY_LEVEL_AUTHPRIV
);

our @TRANSLATE = qw(
   TRANSLATE_NONE TRANSLATE_OCTET_STRING TRANSLATE_NULL TRANSLATE_TIMETICKS
   TRANSLATE_OPAQUE TRANSLATE_NOSUCHOBJECT TRANSLATE_NOSUCHINSTANCE
   TRANSLATE_ENDOFMIBVIEW TRANSLATE_UNSIGNED TRANSLATE_ALL
);

our @VERSIONS = qw(SNMP_VERSION_1 SNMP_VERSION_2C SNMP_VERSION_3);

our @EXPORT_OK = (
   @ASN1_TYPES, @GENERICTRAP, @TRANSLATE, @SECURITY_MODELS, @SECURITY_LEVELS,
   @MSG_FLAGS, @VERSIONS, qw(asn1_ticks_to_time asn1_itoa TRUE FALSE) 
);

our %EXPORT_TAGS = (
   generictrap    => [@GENERICTRAP],
   msgFlags       => [@MSG_FLAGS],
   securityModels => [@SECURITY_MODELS],
   securityLevels => [@SECURITY_LEVELS],
   translate      => [@TRANSLATE],
   types          => [@ASN1_TYPES],
   versions       => [@VERSIONS],
   ALL            => [@EXPORT_OK]
);

## ASN.1 Basic Encoding Rules type definitions

sub INTEGER()                  { 0x02 }  # INTEGER
sub INTEGER32()                { 0x02 }  # Integer32           - SNMPv2c
sub OCTET_STRING()             { 0x04 }  # OCTET STRING
sub NULL()                     { 0x05 }  # NULL
sub OBJECT_IDENTIFIER()        { 0x06 }  # OBJECT IDENTIFIER
sub SEQUENCE()                 { 0x30 }  # SEQUENCE

sub IPADDRESS()                { 0x40 }  # IpAddress
sub COUNTER()                  { 0x41 }  # Counter
sub COUNTER32()                { 0x41 }  # Counter32           - SNMPv2c
sub GAUGE()                    { 0x42 }  # Gauge
sub GAUGE32()                  { 0x42 }  # Gauge32             - SNMPv2c
sub UNSIGNED32()               { 0x42 }  # Unsigned32          - SNMPv2c
sub TIMETICKS()                { 0x43 }  # TimeTicks
sub OPAQUE()                   { 0x44 }  # Opaque
sub COUNTER64()                { 0x46 }  # Counter64           - SNMPv2c

sub NOSUCHOBJECT()             { 0x80 }  # noSuchObject        - SNMPv2c
sub NOSUCHINSTANCE()           { 0x81 }  # noSuchInstance      - SNMPv2c
sub ENDOFMIBVIEW()             { 0x82 }  # endOfMibView        - SNMPv2c

sub GET_REQUEST()              { 0xa0 }  # GetRequest-PDU
sub GET_NEXT_REQUEST()         { 0xa1 }  # GetNextRequest-PDU
sub GET_RESPONSE()             { 0xa2 }  # GetResponse-PDU
sub SET_REQUEST()              { 0xa3 }  # SetRequest-PDU
sub TRAP()                     { 0xa4 }  # Trap-PDU
sub GET_BULK_REQUEST()         { 0xa5 }  # GetBulkRequest-PDU  - SNMPv2c
sub INFORM_REQUEST()           { 0xa6 }  # InformRequest-PDU   - SNMPv2c
sub SNMPV2_TRAP()              { 0xa7 }  # SNMPv2-Trap-PDU     - SNMPv2c
sub REPORT()                   { 0xa8 }  # Report-PDU          - SNMPv3

## SNMP RFC version definitions

sub SNMP_VERSION_1()           { 0x00 }  # RFC 1157 SNMPv1
sub SNMP_VERSION_2C()          { 0x01 }  # RFC 1901 Community-based SNMPv2
sub SNMP_VERSION_3()           { 0x03 }  # RFC 2272 SNMPv3

## RFC 1157 generic-trap definitions

sub COLD_START()                  { 0 }  # coldStart(0)
sub WARM_START()                  { 1 }  # warmStart(1)
sub LINK_DOWN()                   { 2 }  # linkDown(2)
sub LINK_UP()                     { 3 }  # linkUp(3)
sub AUTHENTICATION_FAILURE()      { 4 }  # authenticationFailure(4)
sub EGP_NEIGHBOR_LOSS()           { 5 }  # egpNeighborLoss(5)
sub ENTERPRISE_SPECIFIC()         { 6 }  # enterpriseSpecific(6)

## RFC 2272 - msgFlags::=OCTET STRING

sub MSG_FLAGS_NOAUTHNOPRIV()   { 0x00 }  # Means noAuthNoPriv
sub MSG_FLAGS_AUTH()           { 0x01 }  # authFlag
sub MSG_FLAGS_PRIV()           { 0x02 }  # privFlag
sub MSG_FLAGS_REPORTABLE()     { 0x04 }  # reportableFlag
sub MSG_FLAGS_MASK()           { 0x07 }

## RFC 2571 - SnmpSecurityLevel::=TEXTUAL-CONVENTION

sub SECURITY_LEVEL_NOAUTHNOPRIV() { 1 }  # noAuthNoPriv
sub SECURITY_LEVEL_AUTHNOPRIV()   { 2 }  # authNoPriv
sub SECURITY_LEVEL_AUTHPRIV()     { 3 }  # authPriv

## RFC 2571 - SnmpSecurityModel::=TEXTUAL-CONVENTION

sub SECURITY_MODEL_ANY()          { 0 }  # Reserved for 'any'
sub SECURITY_MODEL_SNMPV1()       { 1 }  # Reserved for SNMPv1
sub SECURITY_MODEL_SNMPV2C()      { 2 }  # Reserved for SNMPv2c
sub SECURITY_MODEL_USM()          { 3 }  # User-Based Security Model (USM) 

## Translation masks

sub TRANSLATE_NONE()           { 0x00 }  # Bit masks used to determine
sub TRANSLATE_OCTET_STRING()   { 0x01 }  # if a specific ASN.1 type is
sub TRANSLATE_NULL()           { 0x02 }  # translated into a "human
sub TRANSLATE_TIMETICKS()      { 0x04 }  # readable" form.
sub TRANSLATE_OPAQUE()         { 0x08 }
sub TRANSLATE_NOSUCHOBJECT()   { 0x10 }
sub TRANSLATE_NOSUCHINSTANCE() { 0x20 }
sub TRANSLATE_ENDOFMIBVIEW()   { 0x40 }
sub TRANSLATE_UNSIGNED()       { 0x80 }
sub TRANSLATE_ALL()            { 0xff }

## Truth values 

sub TRUE()                     { 0x01 } 
sub FALSE()                    { 0x00 }

## Package variables

our $DEBUG = FALSE;                      # Debug flag

our $AUTOLOAD;                           # Used by the AUTOLOAD method

# [public methods] -----------------------------------------------------------

sub new
{
   my ($class, %argv) = @_;

   # Create a new data structure for the object
   my $this = bless {
      '_buffer'      =>  '',              # Serialized message buffer
      '_error'       =>  undef,           # Error message
      '_index'       =>  0,               # Buffer index
      '_leading_dot' =>  FALSE,           # Prepend leading dot on OIDs
      '_length'      =>  0,               # Buffer length
      '_security'    =>  undef,           # Security Model object
      '_translate'   =>  TRANSLATE_NONE,  # Translation mode
      '_transport'   =>  undef,           # Transport Layer object
      '_version'     =>  SNMP_VERSION_1   # SNMP version
   }, $class;

   # Validate the passed arguments

   foreach (keys %argv) {
      if (/^-?callback$/i) {
         $this->callback($argv{$_});
      } elsif (/^-?debug$/i) {
         $this->debug($argv{$_});
      } elsif (/^-?leadingdot$/i) {
         $this->leading_dot($argv{$_});
      } elsif (/^-?translate$/i) {
         $this->translate($argv{$_});
      } elsif (/^-?transport$/i) {
         $this->transport($argv{$_});
      } elsif (/^-?security$/i) {
         $this->security($argv{$_});
      } elsif (/^-?version$/i) {
         $this->version($argv{$_});
      } else {
         $this->_error("Invalid argument '%s'", $_);
      }
      if (defined($this->{_error})) {
         return wantarray ? (undef, $this->{_error}) : undef;
      }
   }

   return wantarray ? ($this, '') : $this;
}

{
   my $prepare_methods = {
      INTEGER,            '_prepare_integer',
      OCTET_STRING,       '_prepare_octet_string',
      NULL,               '_prepare_null',
      OBJECT_IDENTIFIER,  '_prepare_object_identifier',
      SEQUENCE,           '_prepare_sequence',
      IPADDRESS,          '_prepare_ipaddress',
      COUNTER,            '_prepare_counter',
      GAUGE,              '_prepare_gauge',
      TIMETICKS,          '_prepare_timeticks',
      OPAQUE,             '_prepare_opaque',
      COUNTER64,          '_prepare_counter64',
      NOSUCHOBJECT,       '_prepare_nosuchobject',
      NOSUCHINSTANCE,     '_prepare_nosuchinstance',
      ENDOFMIBVIEW,       '_prepare_endofmibview',
      GET_REQUEST,        '_prepare_get_request',
      GET_NEXT_REQUEST,   '_prepare_get_next_request',
      GET_RESPONSE,       '_prepare_get_response',
      SET_REQUEST,        '_prepare_set_request',
      TRAP,               '_prepare_trap',
      GET_BULK_REQUEST,   '_prepare_get_bulk_request',
      INFORM_REQUEST,     '_prepare_inform_request',
      SNMPV2_TRAP,        '_prepare_v2_trap'
   };

   sub prepare 
   {
   #  my ($this, $type, $value) = @_;

      return $_[0]->_error('ASN.1 type not defined') unless (@_ > 1);
      return $_[0]->_error if defined($_[0]->{_error});

      if (exists($prepare_methods->{$_[1]})) {
         $_[0]->${\$prepare_methods->{$_[1]}}($_[2]);
      } else {
         $_[0]->_error('Unknown ASN.1 type [%s]', $_[1]);
      }
   }
}

{
   my $process_methods = {
      INTEGER,            '_process_integer32',
      OCTET_STRING,       '_process_octet_string',
      NULL,               '_process_null',
      OBJECT_IDENTIFIER,  '_process_object_identifier',
      SEQUENCE,           '_process_sequence',
      IPADDRESS,          '_process_ipaddress',
      COUNTER,            '_process_counter',
      GAUGE,              '_process_gauge',
      TIMETICKS,          '_process_timeticks',
      OPAQUE,             '_process_opaque',
      COUNTER64,          '_process_counter64',
      NOSUCHOBJECT,       '_process_nosuchobject',
      NOSUCHINSTANCE,     '_process_nosuchinstance',
      ENDOFMIBVIEW,       '_process_endofmibview',
      GET_REQUEST,        '_process_get_request',
      GET_NEXT_REQUEST,   '_process_get_next_request',
      GET_RESPONSE,       '_process_get_response',
      SET_REQUEST,        '_process_set_request',
      TRAP,               '_process_trap',
      GET_BULK_REQUEST,   '_process_get_bulk_request',
      INFORM_REQUEST,     '_process_inform_request',
      SNMPV2_TRAP,        '_process_v2_trap',
      REPORT,             '_process_report'
   };

   sub process 
   {
   #  my ($this, $type) = @_;

      return $_[0]->_error if defined($_[0]->{_error});

      return $_[0]->_error unless defined(my $type = $_[0]->_buffer_get(1));

      $type = unpack('C', $type);

      if (exists($process_methods->{$type})) {
         if ((@_ == 2) && ($type != $_[1])) {
            return $_[0]->_error(
               'Expected %s, but found %s', asn1_itoa($_[1]), asn1_itoa($type)
            );
         }
         $_[0]->${\$process_methods->{$type}}($type);;
      } else {
         $_[0]->_error('Unknown ASN.1 type [0x%02x]', $type);
      }
   }
}

sub process_v1_v2c_community
{
   # community::=OCTET STRING
   $_[0]->{_community} = $_[0]->process(OCTET_STRING);
}

sub prepare_v3_global_data
{
   my ($this, $pdu) = @_;

   return $this->_error('No PDU defined') unless (@_ == 2);

   return TRUE if ($pdu->version < SNMP_VERSION_3);

   # We must have a Security Model in order to prepare the message.
   if (!defined($pdu->security)) {
      return $this->_error('No Security Model defined');
   }

   # msgSecurityModel::=INTEGER
   if (!defined($this->prepare(INTEGER, $pdu->security->security_model))) {
      return $this->_error;
   }

   # msgFlags::=OCTET STRING

   my $level = $pdu->security->security_level;
   $this->{_msg_flags} = MSG_FLAGS_NOAUTHNOPRIV | MSG_FLAGS_REPORTABLE;

   if ($level == SECURITY_LEVEL_AUTHNOPRIV) {
      $this->{_msg_flags} |= MSG_FLAGS_AUTH;
   } elsif ($level == SECURITY_LEVEL_AUTHPRIV) {
      $this->{_msg_flags} |= MSG_FLAGS_AUTH | MSG_FLAGS_PRIV;
   }

   if (!$pdu->expect_response) {
      $this->{_msg_flags} &= ~MSG_FLAGS_REPORTABLE;
   }

   if (!defined($this->prepare(OCTET_STRING, pack('C', $this->{_msg_flags})))) {
      $this->_error;
   }

   # msgMaxSize::=INTEGER
   if (!defined(
         $this->prepare(INTEGER, $this->{_msg_max_size} = $pdu->max_msg_size)
      )) 
   {
      return $this->_error;
   }

   # msgID::=INTEGER
   if (!defined($this->prepare(INTEGER, $this->{_msg_id} = $pdu->request_id))) {
      return $_[0]->_error;
   }

   # msgGlobalData::=SEQUENCE
   $this->prepare(SEQUENCE, $this->_buffer_get);
}

sub process_v3_global_data
{
   my ($this) = @_;

   return TRUE if ($this->version < SNMP_VERSION_3);

   # msgGlobalData::=SEQUENCE
   return $this->_error unless defined($this->process(SEQUENCE));

   # msgID::=INTEGER
   if (!defined($this->{_msg_id} = $this->process(INTEGER))) {
      return $this->_error;
   }

   # msgMaxSize::=INTEGER
   if (!defined($this->{_msg_max_size} = $this->process(INTEGER))) {
      return $this->_error;
   }

   # msgFlags::=OCTET STRING
   if (!defined($this->{_msg_flags} = $this->process(OCTET_STRING))) {
      return $this->_error;
   }
   $this->{_msg_flags} = unpack('C', $this->{_msg_flags});

   # msgSecurityModel::=INTEGER
   $this->{_msg_security_model} = $this->process(INTEGER);
}

sub prepare_v3_scoped_pdu
{
   my ($this) = @_;

   if (($this->{_version} < SNMP_VERSION_3) || ($this->{_scoped_pdu})) {
      return TRUE;
   }

   # Set the flag indicating that this is a scopedPDU
   $this->{_scoped_pdu} = TRUE;

   # contextName::=OCTET STRING
   if (!defined($this->prepare(OCTET_STRING, $this->context_name))) {
      return $this->_error;
   }

   # contextEngineID::=OCTET STRING
   if (!defined($this->prepare(OCTET_STRING, $this->context_engine_id))) {
      return $this->_error;
   }
   
   # scopedPDU::=SEQUENCE
   $this->prepare(SEQUENCE, $this->_buffer_get);
}

sub process_v3_scoped_pdu
{
   my ($this) = @_;

   if ($this->{_version} < SNMP_VERSION_3) {
      return TRUE;
   }

   # Set the flag indicating that this is a scopedPDU
   $this->{_scoped_pdu} = TRUE;

   # scopedPDU::=SEQUENCE
   return $this->_error unless defined($this->process(SEQUENCE));

   # contextEngineID::=OCTET STRING
   if (!defined($this->{_context_engine_id} = $this->process(OCTET_STRING))) {
      return $this->_error;
   }

   # contextName::=OCTET STRING
   $this->{_context_name} = $this->process(OCTET_STRING);
}

sub context_engine_id
{
   if (@_ == 2) {
      if ((CORE::length($_[1]) >= 5) && (CORE::length($_[1]) <= 32)) {
         $_[0]->{_context_engine_id} = $_[1];
      } else {
         return $_[0]->_error(
            'Invalid contextEngineID length [%d octet%s]', 
            CORE::length($_[1]), (CORE::length($_[1]) != 1) ? 's' : ''
         );
      }
   }

   if (defined($_[0]->{_context_engine_id})) {
      $_[0]->{_context_engine_id};
   } elsif (defined($_[0]->{_security})) {
      $_[0]->{_security}->engine_id;
   } else {
      '';
   }
}

sub context_name
{
   if (@_ == 2) {
      if (CORE::length($_[1]) > 32) {
         return $_[0]->_error(
            'Invalid contextName length [%d octets]', CORE::length($_[1])
         );
      } else {
         $_[0]->{_context_name} = $_[1];
      }
   }

   $_[0]->{_context_name} || '';
}

sub msg_id
{
   $_[0]->{_msg_id} || $_[0]->{_request_id} || 0;  
}

sub msg_flags
{
   defined($_[0]->{_msg_flags}) ? $_[0]->{_msg_flags} : 0;
}

sub msg_max_size
{
   $_[0]->{_msg_max_size} || 0;
}

sub msg_security_model
{
   if (defined($_[0]->{_msg_security_model})) {

      $_[0]->{_msg_security_model};

   } else {

      if ($_[0]->{_version} == SNMP_VERSION_1) {
         SECURITY_MODEL_SNMPV1; 
      } elsif ($_[0]->{_version} == SNMP_VERSION_2C) {
         SECURITY_MODEL_SNMPV2C;
      } elsif ($_[0]->{_version} == SNMP_VERSION_3) {
         SECURITY_MODEL_USM;
      } else {
         SECURITY_MODEL_ANY;
      }

   }
}

sub community
{
   defined($_[0]->{_community}) ? $_[0]->{_community} : '';
}

sub version
{
   if (@_ == 2) {
      if (($_[1] == SNMP_VERSION_1)  ||
          ($_[1] == SNMP_VERSION_2C) ||
          ($_[1] == SNMP_VERSION_3))
      {
         $_[0]->{_version} = $_[1];
      } else {
         return $_[0]->_error('Unknown or unsupported version [%s]', $_[1]);
      }
   }

   $_[0]->{_version};
}

sub error_status 
{ 
   0; # noError 
}

sub error_index
{ 
   0;
} 

sub var_bind_list 
{
   undef;
}  

#
# Security Model accessor methods
#

sub security
{
   if (@_ == 2) {
      if (defined($_[1])) {
         $_[0]->{_security} = $_[1];
      } else {
         $_[0]->_error_clear;
         return $_[0]->_error('No Security Model defined');
      }
   }

   $_[0]->{_security};
}

#
# Transport Layer accessor methods
#

sub transport
{
   if (@_ == 2) {
      if (defined($_[1])) {
         $_[0]->{_transport} = $_[1];
      } else {
         $_[0]->_error_clear;
         return $_[0]->_error('No Transport Layer defined');
         
      }
   }

   $_[0]->{_transport};
}

sub dstname
{
   defined($_[0]->{_transport}) ? $_[0]->{_transport}->dstname : '';
}

sub max_msg_size
{
   if (defined($_[0]->{_transport})) { 
      if (@_ != 2) {
         $_[0]->{_transport}->max_msg_size;
      } else {
         $_[0]->_error_clear;
         $_[0]->{_transport}->max_msg_size($_[1]) ||
            $_[0]->_error($_[0]->{_transport}->error); 
      }
   } else {
      0;
   }
}

sub retries
{
   defined($_[0]->{_transport}) ? $_[0]->{_transport}->retries : 0; 
}

sub timeout
{
   defined($_[0]->{_transport}) ? $_[0]->{_transport}->timeout : 0;
}

sub send
{
   $_[0]->_error_clear;

   if (!defined($_[0]->{_transport})) {
      return $_[0]->_error('No Transport Layer defined');
   }

   DEBUG_INFO(
      'address %s, port %d', 
      $_[0]->{_transport}->dsthost, $_[0]->{_transport}->dstport
   );
   $_[0]->_buffer_dump;

   $_[0]->{_transport}->send($_[0]->{_buffer}) || 
      $_[0]->_error($_[0]->{_transport}->error);
}

sub recv 
{
   $_[0]->_error_clear;

   if (!defined($_[0]->{_transport})) {
      return $_[0]->_error('No Transport Layer defined');
   }

   my $sa = $_[0]->{_transport}->recv($_[0]->{_buffer});

   if (defined($sa)) {

      $_[0]->{_length} = CORE::length($_[0]->{_buffer});

      DEBUG_INFO(
         'address %s, port %d',
         $_[0]->{_transport}->recvhost, $_[0]->{_transport}->recvport
      );
      $_[0]->_buffer_dump;

      $sa;

   } else {

      $_[0]->_error($_[0]->{_transport}->error);

   }
}

#
# Data representation methods
#

sub translate
{
   (@_ == 2) ? $_[0]->{_translate} = $_[1] : $_[0]->{_translate};
}

sub leading_dot
{
   (@_ == 2) ? $_[0]->{_leading_dot} = $_[1] : $_[0]->{_leading_dot};
}

#
# Callback handler methods
#

sub callback
{
   if (@_ == 2) {
      if (ref($_[1]) eq 'CODE') {
         $_[0]->{_callback} = $_[1];
      } elsif (!defined($_[1])) {
         $_[0]->{_callback} = undef;
      } 
   }

   $_[0]->{_callback};
}

sub callback_execute
{
   if (!defined($_[0]->{_callback})) {
      DEBUG_INFO('no callback');
      return TRUE;
   }

   # Protect ourselves from user error.
   eval { $_[0]->{_callback}->($_[0]); };

   # We clear the callback in case it was a 
   # closure which might hold up the reference
   # count of the calling object.

   $_[0]->{_callback} = undef;

   ($@) ? $_[0]->_error($@) : TRUE; 
}

sub timeout_id
{
   (@_ == 2) ? $_[0]->{_timeout_id} = $_[1] : $_[0]->{_timeout_id};
}

#
# Buffer manipulation methods
#

sub index
{
   if ((@_ == 2) && ($_[1] >= 0) && ($_[1] <= $_[0]->{_length})) {
      $_[0]->{_index} = $_[1];
   }

   $_[0]->{_index};
}

sub length
{
   $_[0]->{_length};
}

sub prepend
{
   shift->_buffer_put(@_);
}

sub append
{
   shift->_buffer_append(@_);
}

sub copy 
{
   $_[0]->{_buffer};
}

sub reference
{
   \$_[0]->{_buffer};
}

sub clear
{
   $_[0]->_buffer_get;
}

#
# Debug/error handling methods
#

sub error
{
   my $this = shift;

   if (@_) {
      if (defined($_[0])) {
         $this->{_error} = sprintf(shift(@_), @_);
         if ($this->debug) {
            printf("error: [%d] %s(): %s\n",
               (caller(0))[2], (caller(1))[3], $this->{_error}
            );
         }
      } else {
         $this->{_error} = undef;
      }
   }

   $this->{_error} || '';
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

sub AUTOLOAD
{
   return if $AUTOLOAD =~ /::DESTROY$/;

   $AUTOLOAD =~ s/.*://;

   $_[0]->_error('Feature not supported [%s]', $AUTOLOAD);
}

# [private methods] ----------------------------------------------------------

#
# Basic Encoding Rules (BER) process methods
#

sub _prepare_type_length
{
#  my ($this, $type, $value) = @_;

   return $_[0]->_error('ASN.1 type not defined') unless defined($_[1]);

   my $length = CORE::length($_[2]);

   if ($length < 0x80) {
      $_[0]->_buffer_put(pack('C2', $_[1], $length) . $_[2]);
   } elsif ($length <= 0xff) {
      $_[0]->_buffer_put(pack('C3', $_[1], 0x81, $length) . $_[2]);
   } elsif ($length <= 0xffff) {
      $_[0]->_buffer_put(pack('CCn', $_[1], 0x82, $length) . $_[2]);
   } else {
      $_[0]->_error('Unable to prepare ASN.1 length');
   }
}

sub _prepare_integer
{
   return $_[0]->_error('INTEGER value not defined') unless defined($_[1]);

   if ($_[1] !~ /^-?\d+$/) {
      return $_[0]->_error('Expected numeric INTEGER value');
   }

   $_[0]->_prepare_integer32(INTEGER, $_[1]);
}

sub _prepare_unsigned32
{
   if (!defined($_[2])) {
      return $_[0]->_error('%s value not defined', asn1_itoa($_[1]));
   }

   if ($_[2] !~ /^\d+$/) {
      return $_[0]->_error(
         'Expected positive numeric %s value', asn1_itoa($_[1])
      );
   }

   $_[0]->_prepare_integer32($_[1], $_[2]);
}

sub _prepare_integer32
{
   my ($this, $type, $int32) = @_;

   if (!defined($int32)) {
      return $this->_error('%s value not defined', asn1_itoa($type));
   }

   # Determine if the value is positive or negative
   my $negative = ($int32 =~ /^-/);

   # Check to see if the most significant bit is set, if it is we
   # need to prefix the encoding with a zero byte.

   my $size   = 4;     # Assuming 4 byte integers
   my $prefix = FALSE;
   my $value  = '';

   if ((($int32 & 0xff000000) & 0x80000000) && (!$negative)) {
      $size++;
      $prefix = TRUE;
   }

   # Remove occurances of nine consecutive ones (if negative) or zeros
   # from the most significant end of the two's complement integer.

   while ((((!($int32 & 0xff800000))) ||
           ((($int32 & 0xff800000) == 0xff800000) && ($negative))) &&
           ($size > 1))
   {
      $size--;
      $int32 <<= 8;
   }

   # Add a zero byte so the integer is decoded as a positive value
   if ($prefix) {
      $value .= pack('x');
      $size--;
   }

   # Build the integer
   while ($size-- > 0) {
      $value .= pack('C', (($int32 & 0xff000000) >> 24));
      $int32 <<= 8;
   }

   # Encode ASN.1 header
   $_[0]->_prepare_type_length($type, $value);
}

sub _prepare_octet_string
{
   return $_[0]->_error('OCTET STRING value not defined') unless defined($_[1]);

   $_[0]->_prepare_type_length(OCTET_STRING, $_[1]);
}

sub _prepare_null
{
   $_[0]->_prepare_type_length(NULL, '');
}

sub _prepare_object_identifier
{
   my ($this, $oid) = @_;

   if (!defined($oid)) {
      return $this->_error('OBJECT IDENTIFIER value not defined');
   }

   # Input is expected in dotted notation, so break it up into subids
   my @subids = split(/\./, $oid);

   # If there was a leading dot on _any_ OBJECT IDENTIFIER passed to
   # a prepare method, return a leading dot on _all_ of the OBJECT
   # IDENTIFIERs in the process methods.

   if ($subids[0] eq '') {
      DEBUG_INFO('leading dot present');
      $this->{_leading_dot} = TRUE;
      shift(@subids);
   }

   # ISO/IEC 8825 - Specification of Basic Encoding Rules for Abstract
   # Syntax Notation One (ASN.1) dictates that the first two subidentifiers 
   # are encoded into the first identifier using the the equation: 
   # subid = ((first * 40) + second).

   # We return an error if there are not at least two subidentifiers.

   if (scalar(@subids) < 2) {
      return $this->_error(
         'Expected at least two subidentifiers in an OBJECT IDENTIFIER'
      );
   } 

   # The first subidentifiers are limited to ccitt(0), iso(1), and 
   # joint-iso-ccitt(2) as defined by RFC 1155. 

   if ($subids[0] > 2) {
      return $this->_error(
         'An OBJECT IDENTIFIER must begin with either 0 (ccitt), 1 ' .
         '(iso), or 2 (joint-iso-ccitt)'
      );
   }

   # If the first subidentifier is 0 or 1, the second is limited to 0 - 39.

   if (($subids[0] < 2) && ($subids[1] >= 40)) {
      return $this->_error(
         'The second subidentifier in the OBJECT IDENTIFIER must be ' .
         'less than 40'
      );
   } elsif ($subids[1] >= (~0 - 80)) {
      return $this->_error(
         'The second subidentifier in the OBJECT IDENTIFIER must be ' .
         'less than %u',
         (~0 - 80)
      );
   }

   # Now apply: subid = ((first * 40) + second)

   $subids[1] += (shift(@subids) * 40);

   # Encode each value as seven bits with the most significant bit
   # indicating the end of a subidentifier.

   my ($mask, $bits, $tmask, $tbits);
   my $value = '';

   foreach my $subid (@subids) {
      if (($subid <= 0x7f) && ($subid >= 0)) {
         $value .= pack('C', $subid);
      } else {
         $mask = 0x7f;
         $bits = 0;
         # Determine the number of bits need to encode the subidentifier
         for ($tmask = 0x7f, $tbits = 0;
              $tmask != 0x00;
              $tmask <<= 7, $tbits += 7)
         {
            if ($subid & $tmask) {
               $mask = $tmask;
               $bits = $tbits;
            }
         }
         # Now encode it, using the number of bits from above
         for ( ; $mask != 0x7f; $mask >>= 7, $bits -= 7) {
            # Handle a mask that was truncated above because
            # the subidentifier was four bytes long.
            if ((($mask & 0xffffffff) == 0xffe00000) ||
                 ($mask == 0x1e00000))
            {
               $mask = 0xfe00000;
            }
            $value .= pack('C', ((($subid & $mask) >> $bits) | 0x80));
         }
         $value .= pack('C', ($subid & $mask));
      }
   }

   # Encode the ASN.1 header
   $this->_prepare_type_length(OBJECT_IDENTIFIER, $value);
}

sub _prepare_sequence
{
   $_[0]->_prepare_type_length(SEQUENCE, $_[1]);
}

sub _prepare_ipaddress
{
   return $_[0]->_error('IpAddress not defined') unless defined($_[1]);

   if ($_[1] !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
      return $_[0]->_error('Expected IpAddress in dotted notation');
   }

   $_[0]->_prepare_type_length(IPADDRESS, pack('C4', split(/\./, $_[1])));
}

sub _prepare_counter
{
   $_[0]->_prepare_unsigned32(COUNTER, $_[1]);
}

sub _prepare_gauge
{
   $_[0]->_prepare_unsigned32(GAUGE, $_[1]);
}

sub _prepare_timeticks
{
   $_[0]->_prepare_unsigned32(TIMETICKS, $_[1]);
}

sub _prepare_opaque
{
   return $_[0]->_error('Opaque value not defined') unless defined($_[1]);

   $_[0]->_prepare_type_length(OPAQUE, $_[1]);
}

sub _prepare_counter64
{
   my ($this, $u_int64) = @_;

   # Validate the SNMP version
   if ($this->{_version} == SNMP_VERSION_1) {
      return $this->_error('Counter64 not supported in SNMPv1');
   }

   # Validate the passed value
   if (!defined($u_int64)) {
      return $this->_error('Counter64 value not defined');
   }

   if ($u_int64 !~ /^\+?\d+$/) {
      return $this->_error('Expected positive numeric Counter64 value');
   }

   $u_int64 = Math::BigInt->new($u_int64);

   if ($u_int64 eq 'NaN') {
      return $this->_error('Invalid Counter64 value');
   }

   # Make sure the value is no more than 8 bytes long
   if ($u_int64->bcmp('18446744073709551615') > 0) {
      return $this->_error('Counter64 value too high');
   }

   my ($quotient, $remainder, @bytes);

   # Handle a value of zero
   if ($u_int64 == 0) {
      unshift(@bytes, 0x00);
   }

   while ($u_int64 > 0) {
      ($quotient, $remainder) = $u_int64->bdiv(256);
      $u_int64 = Math::BigInt->new($quotient);
      unshift(@bytes, $remainder);
   }

   # Make sure that the value is encoded as a positive value
   if ($bytes[0] & 0x80) { unshift(@bytes, 0x00); }

   $this->_prepare_type_length(COUNTER64, pack('C*', @bytes));
}

sub _prepare_nosuchobject
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('noSuchObject not supported in SNMPv1');
   }

   $_[0]->_prepare_type_length(NOSUCHOBJECT, '');
}

sub _prepare_nosuchinstance
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('noSuchInstance not supported in SNMPv1');
   }

   $_[0]->_prepare_type_length(NOSUCHINSTANCE, '');
}

sub _prepare_endofmibview
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('endOfMibView not supported in SNMPv1');
   }

   $_[0]->_prepare_type_length(ENDOFMIBVIEW, '');
}

sub _prepare_get_request
{
   $_[0]->_prepare_type_length(GET_REQUEST, $_[1]);
}

sub _prepare_get_next_request
{
   $_[0]->_prepare_type_length(GET_NEXT_REQUEST, $_[1]);
}

sub _prepare_get_response
{
   $_[0]->_prepare_type_length(GET_RESPONSE, $_[1]);
}

sub _prepare_set_request
{
   $_[0]->_prepare_type_length(SET_REQUEST, $_[1]);
}

sub _prepare_trap
{
   if ($_[0]->{_version} != SNMP_VERSION_1) {
      return $_[0]->_error('Trap-PDU only supported in SNMPv1');
   }

   $_[0]->_prepare_type_length(TRAP, $_[1]);
}

sub _prepare_get_bulk_request
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('GetBulkRequest-PDU not supported in SNMPv1');
   }

   $_[0]->_prepare_type_length(GET_BULK_REQUEST, $_[1]);
}

sub _prepare_inform_request
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('InformRequest-PDU not supported in SNMPv1');
   }

   $_[0]->_prepare_type_length(INFORM_REQUEST, $_[1]);
}

sub _prepare_v2_trap
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('SNMPv2-Trap-PDU not supported in SNMPv1');
   }

   $_[0]->_prepare_type_length(SNMPV2_TRAP, $_[1]);
}

sub _prepare_report
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('Report-PDU not supported in SNMPv1');
   }

   $_[0]->_prepare_type_length(SNMPV2_TRAP, $_[1]);
}

#
# Basic Encoding Rules (BER) process methods
#

sub _process_length
{
#  my ($this) = @_;

   return $_[0]->_error if defined($_[0]->{_error});

   return $_[0]->_error unless defined(my $length = $_[0]->_buffer_get(1));

   $length = unpack('C', $length);

   if ($length & 0x80) {
      my $byte_cnt = ($length & 0x7f);
      if ($byte_cnt == 0) {
         return $_[0]->_error('Indefinite ASN.1 lengths not supported');
      } elsif ($byte_cnt <= 4) {
         if (!defined($length = $_[0]->_buffer_get($byte_cnt))) {
            return $_[0]->_error;
         }
         $length = unpack('N', ("\000" x (4 - $byte_cnt) . $length));
      } else {
         return $_[0]->_error('ASN.1 length too long (%d bytes)', $byte_cnt);
      }
   }

   $length;
}

sub _process_integer32
{
   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   # Return an error if the object length is zero
   if ($length < 1) {
      return $_[0]->_error("%s length equal to zero", asn1_itoa($_[1]));
   }

   # Get the first byte
   return $_[0]->_error unless defined(my $byte = $_[0]->_buffer_get(1));
   $length--;

   my $negative = FALSE;
   my $int32 = 0;

   # If the first bit is set, the integer is negative
   if (($byte = unpack('C', $byte)) & 0x80) {
      if (($_[1] == INTEGER) || (!($_[0]->{_translate} & TRANSLATE_UNSIGNED))) {
         $int32 = -1;
         $negative = TRUE;
      } else {
         DEBUG_INFO("translating sign bit for %s", asn1_itoa($_[1]));
      }
   }

   if (($length > 4) || (($length > 3) && ($byte != 0x00))) {
      return $_[0]->_error(
         '%s length too long (%d bytes)', asn1_itoa($_[1]), ($length + 1)
      );
   }

   $int32 = (($int32 << 8) | $byte);

   while ($length--) {
      if (!defined($byte = $_[0]->_buffer_get(1))) {
         return $_[0]->_error;
      }
      $int32 = (($int32 << 8) | unpack('C', $byte));
   }

   if ($negative) {
      sprintf('%d', $int32);
   } else {
      sprintf('%u', $int32);
   }
}

sub _process_octet_string
{
   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   # Get the string
   return $_[0]->_error unless defined(my $s = $_[0]->_buffer_get($length));

   # Set the translation mask
   my $mask = ($_[1] == OPAQUE) ? TRANSLATE_OPAQUE : TRANSLATE_OCTET_STRING;

   if (($s =~ /[\x01-\x08\x0b\x0e-\x1f\x7f-\xff]/g) &&
       ($_[0]->{_translate} & $mask))
   {
      DEBUG_INFO("translating %s to printable hex string", asn1_itoa($_[1]));
      sprintf('0x%s', unpack('H*', $s));
   } else {
      $s;
   }
}

sub _process_null
{
   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   if ($length != 0) {
      return $_[0]->_error('NULL length not equal to zero');
   }

   if ($_[0]->{_translate} & TRANSLATE_NULL) {
      DEBUG_INFO("translating NULL to 'NULL' string");
      'NULL';
   } else {
      '';
   }
}

sub _process_object_identifier
{
   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   if ($length < 1) {
      return $_[0]->_error('OBJECT IDENTIFIER length equal to zero');
   }

   my ($subid_cnt, $subid) = (1, 0);
   my ($byte, @oid);

   while ($length > 0) {
      $subid = 0;
      do {
         if (!defined($byte = $_[0]->_buffer_get(1))) {
            return $_[0]->_error;
         }
         $byte = unpack('C', $byte);
         if ($subid >= ~0) {
            return $_[0]->_error('OBJECT IDENTIFIER subidentifier too large');
         }
         $subid = (($subid << 7) + ($byte & 0x7f));
         $length--;
      } while ($byte & 0x80);
      $oid[$subid_cnt++] = $subid;
   }

   # The first two subidentifiers are encoded into the first identifier
   # using the the equation: subid = ((first * 40) + second).

   if ($oid[1] == 0x2b) {   # Handle the most common case
      $oid[0] = 1;          # first [iso(1).org(3)] 
      $oid[1] = 3;
   } elsif ($oid[1] < 40) {
      $oid[0] = 0;
   } elsif ($oid[1] < 80) {
      $oid[0] = 1;
      $oid[1] -= 40;
   } else {
      $oid[0] = 2;
      $oid[1] -= 80;
   }

   # Return the OID in dotted notation (optionally with a leading dot
   # if one was passed to the prepare routine).

   if ($_[0]->{_leading_dot}) {
      DEBUG_INFO('adding leading dot');
      '.' . join('.', @oid);
   } else {
      join('.', @oid);
   }
}

sub _process_sequence
{
   # Return the length, instead of the value
   $_[0]->_process_length;
}

sub _process_ipaddress
{
   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   if ($length != 4) {
      return $_[0]->_error(
         'Invalid IpAddress length (%d byte%s)',
         $length, ($length != 1 ? 's' : '')
      );
   }

   if (defined(my $ip = $_[0]->_buffer_get(4))) {
      sprintf('%vd', $ip);
   } else {
      $_[0]->_error;
   }
}

sub _process_counter
{
   $_[0]->_process_integer32(COUNTER);
}

sub _process_gauge
{
   $_[0]->_process_integer32(GAUGE);
}

sub _process_timeticks
{
   if (defined(my $ticks = $_[0]->_process_integer32(TIMETICKS))) {
      if ($_[0]->{_translate} & TRANSLATE_TIMETICKS) {
         DEBUG_INFO('translating %u TimeTicks to time', $ticks);
         asn1_ticks_to_time($ticks);
      } else {
         $ticks;
      }
   } else {
      $_[0]->_error;
   }
}

sub _process_opaque
{
   $_[0]->_process_octet_string(OPAQUE);
}

sub _process_counter64
{
   # Verify the SNMP version
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('Counter64 not supported in SNMPv1');
   }

   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   if ($length < 1) {
      return $_[0]->_error('Counter64 length equal to zero');
   }

   # Get the first byte
   return $_[0]->_error unless defined(my $byte = $_[0]->_buffer_get(1));
   $length--;
   $byte = unpack('C', $byte);

   if (($length > 8) || (($length > 7) && ($byte != 0x00))) {
      return $_[0]->_error(
         'Counter64 length too long (%d bytes)', ($length + 1)
      );
   }

   my $negative = FALSE;

   if ($byte & 0x80) {
      if (!($_[0]->{_translate} & TRANSLATE_UNSIGNED)) {
         $negative = TRUE;
         $byte = $byte ^ 0xff;
      } else {
         DEBUG_INFO('translating sign bit for Counter64');
      }
   }

   my $u_int64 = Math::BigInt->new($byte);

   while ($length-- > 0) {
      if (!defined($byte = $_[0]->_buffer_get(1))) {
         return $_[0]->_error;
      }
      $byte = unpack('C', $byte);
      $byte = $byte ^ 0xff if ($negative);
      $u_int64 = $u_int64->bmul(256);
      $u_int64 = Math::BigInt->new($u_int64);
      $u_int64 = $u_int64->badd($byte);
      $u_int64 = Math::BigInt->new($u_int64);
   };

   # If the value is negative the other end incorrectly encoded
   # the Counter64 since it should always be a positive value.

   if ($negative) {
      $byte = Math::BigInt->new('-1');
      $u_int64 = $byte->bsub($u_int64);
   }

   # Perl 5.6.0 (force to string or substitution does not work).
   $u_int64 .= ''; 

   # Remove the plus sign (or should we leave it to imply Math::BigInt?)
   $u_int64 =~ s/^\+//;

   $u_int64;
}

sub _process_nosuchobject
{
   # Verify the SNMP version
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('noSuchObject not supported in SNMPv1');
   }

   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   if ($length != 0) {
      return $_[0]->_error('noSuchObject length not equal to zero');
   }

   if ($_[0]->{_translate} & TRANSLATE_NOSUCHOBJECT) {
      DEBUG_INFO("translating noSuchObject to 'noSuchObject' string");
      'noSuchObject';
   } else {
      $_[0]->{_error_status} = NOSUCHOBJECT;
      '';
   }
}

sub _process_nosuchinstance
{
   # Verify the SNMP version
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('noSuchInstance not supported in SNMPv1');
   }

   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   if ($length != 0) {
      return $_[0]->_error('noSuchInstance length not equal to zero');
   }

   if ($_[0]->{_translate} & TRANSLATE_NOSUCHINSTANCE) {
      DEBUG_INFO("translating noSuchInstance to 'noSuchInstance' string");
      'noSuchInstance';
   } else {
      $_[0]->{_error_status} = NOSUCHINSTANCE;
      '';
   }
}

sub _process_endofmibview
{
   # Verify the SNMP version
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('endOfMibView not supported in SNMPv1');
   }

   # Decode the length
   return $_[0]->_error unless defined(my $length = $_[0]->_process_length);

   if ($length != 0) {
      return $_[0]->_error('endOfMibView length not equal to zero');
   }

   if ($_[0]->{_translate} & TRANSLATE_ENDOFMIBVIEW) {
      DEBUG_INFO("translating endOfMibView to 'endOfMibView' string");
      'endOfMibView';
   } else {
      $_[0]->{_error_status} = ENDOFMIBVIEW;
      '';
   }
}

sub _process_pdu_type
{
   # Generic methods used to process the PDU type.  The ASN.1 type is
   # returned by the method as passed by the generic process routine.

   defined($_[0]->_process_length) ? $_[1] : $_[0]->_error;
}

sub _process_get_request
{
   $_[0]->_process_pdu_type(GET_REQUEST);
}

sub _process_get_next_request
{
   $_[0]->_process_pdu_type(GET_NEXT_REQUEST);
}

sub _process_get_response
{
   $_[0]->_process_pdu_type(GET_RESPONSE);
}

sub _process_set_request
{
   $_[0]->_process_pdu_type(SET_REQUEST);
}

sub _process_trap
{
   if ($_[0]->{_version} != SNMP_VERSION_1) {
      return $_[0]->_error('Trap-PDU only supported in SNMPv1');
   }

   $_[0]->_process_pdu_type(TRAP);
}

sub _process_get_bulk_request
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('GetBulkRequest-PDU not supported in SNMPv1');
   }

   $_[0]->_process_pdu_type(GET_BULK_REQUEST);
}

sub _process_inform_request
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('InformRequest-PDU not supported in SNMPv1');
   }

   $_[0]->_process_pdu_type(INFORM_REQUEST);
}

sub _process_v2_trap
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('SNMPv2-Trap-PDU not supported in SNMPv1');
   }

   $_[0]->_process_pdu_type(SNMPV2_TRAP);
}

sub _process_report
{
   if ($_[0]->{_version} == SNMP_VERSION_1) {
      return $_[0]->_error('Report-PDU not supported in SNMPv1');
   }

   $_[0]->_process_pdu_type(REPORT);
}

#
# Abstract Syntax Notation One (ASN.1) utility functions
#

{
   my $types = {
      INTEGER,            'INTEGER',
      OCTET_STRING,       'OCTET STRING',
      NULL,               'NULL',
      OBJECT_IDENTIFIER,  'OBJECT IDENTIFER',
      SEQUENCE,           'SEQUENCE',
      IPADDRESS,          'IpAddress',
      COUNTER,            'Counter',
      GAUGE,              'Gauge',
      TIMETICKS,          'TimeTicks',
      OPAQUE,             'Opaque',
      COUNTER64,          'Counter64',
      NOSUCHOBJECT,       'noSuchObject',
      NOSUCHINSTANCE,     'noSuchInstance',
      ENDOFMIBVIEW,       'endOfMibView',
      GET_REQUEST,        'GetRequest-PDU',
      GET_NEXT_REQUEST,   'GetNextRequest-PDU',
      GET_RESPONSE,       'GetResponse-PDU',
      SET_REQUEST,        'SetRequest-PDU',
      TRAP,               'Trap-PDU',
      GET_BULK_REQUEST,   'GetBulkRequest-PDU',
      INFORM_REQUEST,     'InformRequest-PDU',
      SNMPV2_TRAP,        'SNMPv2-Trap-PDU',
      REPORT,             'Report-PDU'
   };

   sub asn1_itoa
   {
      return '??' unless (@_ == 1);

      if (exists($types->{$_[0]})) {
         $types->{$_[0]};
      } else {
         sprintf("?? [0x%02x]", $_[0]);
      }
   }
}

sub asn1_ticks_to_time
{
   my $ticks = shift;

   if (!defined($ticks)) { $ticks = 0; }

   my $days = int($ticks / (24 * 60 * 60 * 100));
   $ticks %= (24 * 60 * 60 * 100);

   my $hours = int($ticks / (60 * 60 * 100));
   $ticks %= (60 * 60 * 100);

   my $minutes = int($ticks / (60 * 100));
   $ticks %= (60 * 100);

   my $seconds = ($ticks / 100);

   if ($days != 0){
      sprintf("%d day%s, %02d:%02d:%05.02f", $days,
         ($days == 1 ? '' : 's'), $hours, $minutes, $seconds);
   } elsif ($hours != 0) {
      sprintf("%d hour%s, %02d:%05.02f", $hours,
         ($hours == 1 ? '' : 's'), $minutes, $seconds);
   } elsif ($minutes != 0) {
      sprintf("%d minute%s, %05.02f", $minutes,
         ($minutes == 1 ? '' : 's'), $seconds);
   } else {
      sprintf("%04.02f second%s", $seconds, ($seconds == 1 ? '' : 's'));
   }
}

#
# Error handlers
#

sub _error
{
   my $this = shift;

   if (!defined($this->{_error})) {
      $this->{_error} = sprintf(shift(@_), @_);
      if ($this->debug) {
         printf("error: [%d] %s(): %s\n",
            (caller(0))[2], (caller(1))[3], $this->{_error}
         );
      }
   }

   return;
}

sub _error_clear
{
   $_[0]->{_error} = undef;
}

#
# Buffer manipulation methods
#

sub _buffer_append
{
   return $_[0]->_error if defined($_[0]->{_error});

   # Always reset the index when the buffer is modified
   $_[0]->{_index} = 0;

   # Update our length
   $_[0]->{_length} += CORE::length($_[1]);

   # Append to the current buffer
   $_[0]->{_buffer} .= $_[1];
}

sub _buffer_get
{
   return $_[0]->_error if defined($_[0]->{_error});

   # Return the number of bytes requested at the current 
   # index or clear and return the whole buffer if no arguments  
   # are passed.

   if (@_ == 2) {

      if (($_[0]->{_index} += $_[1]) > $_[0]->{_length}) {
         $_[0]->{_index} -= $_[1];
         if ($_[0]->{_length} >= $_[0]->max_msg_size) {
            return $_[0]->_error('Message size exceeded maxMsgSize'); 
         }
         return $_[0]->_error('Unexpected end of message');
      }
      substr($_[0]->{_buffer}, $_[0]->{_index} - $_[1], $_[1]);

   } else {

      $_[0]->{_index}  = 0; # Index is reset on modifies 
      $_[0]->{_length} = 0; 
      substr($_[0]->{_buffer}, 0, CORE::length($_[0]->{_buffer}), '');

   }
}

sub _buffer_put
{
   return $_[0]->_error if defined($_[0]->{_error});

   # Always reset the index when the buffer is modified
   $_[0]->{_index} = 0;

   # Update our length
   $_[0]->{_length} += CORE::length($_[1]);

   # Add the prefix to the current buffer
   substr($_[0]->{_buffer}, 0, 0) = $_[1];
}

sub _buffer_dump
{
   return unless $DEBUG;

   DEBUG_INFO("%d byte%s", $_[0]->{_length}, $_[0]->{_length} != 1 ? 's' : '');

   my ($offset, $hex) = (0, '');

   while ($_[0]->{_buffer} =~ /(.{1,16})/gs) {
      $hex  = unpack('H*', ($_ = $1));
      $hex .= ' ' x (32 - CORE::length($hex));
      $hex  = sprintf("%s %s %s %s  " x 4, unpack('a2' x 16, $hex));
      s/[\x00-\x1f\x7f-\xff]/./g;
      printf("[%04d]  %s %s\n", $offset, uc($hex), $_);
      $offset += 16;
   }

   $_[0]->{_buffer};
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
