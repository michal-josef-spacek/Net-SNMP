# -*- mode: perl -*-
# ============================================================================

package Net::SNMP;

# $Id: SNMP.pm,v 2.0 1999/05/06 16:09:22 dtown Exp $
# $Source: /home/dtown/Projects/Net-SNMP/SNMP.pm,v $

# The module Net::SNMP implements an object oriented interface to the Simple
# Network Management Protocol.  Perl applications can use the module to 
# retrieve or update information on a remote host using the SNMP protocol.
# Both SNMPv1 and SNMPv2c (Community-Based SNMPv2) are supported by the 
# module.  The Net::SNMP module assumes that the user has a basic 
# understanding of the Simple Network Management Protocol and related 
# network management concepts.

# Copyright (c) 1998-1999 David M. Town <dtown@fore.com>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself. 

# ============================================================================

## Version of Net::SNMP module

$Net::SNMP::VERSION = 2.00;

## Required version of Perl

require 5.003;

## Handle exporting of symbols

use Exporter();

use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

@ISA         = qw(Exporter);
@EXPORT      = qw(
                  INTEGER INTEGER32 OCTET_STRING NULL OBJECT_IDENTIFIER 
                  IPADDRESS COUNTER COUNTER32 GAUGE GAUGE32 UNSIGNED32
                  TIMETICKS OPAQUE COUNTER64 NOSUCHOBJECT NOSUCHINSTANCE
                  ENDOFMIBVIEW
               );
@EXPORT_OK   = qw(
                  COLD_START WARM_START LINK_DOWN LINK_UP 
                  AUTHENTICATION_FAILURE EGP_NEIGHBOR_LOSS 
                  ENTERPRISE_SPECIFIC
               );

%EXPORT_TAGS = (
                  asn1        => [@EXPORT],
                  generictrap => [@EXPORT_OK], 
                  ALL         => [@EXPORT, @EXPORT_OK]
               );

## Import socket() defines and structure manipulators

use Socket qw(PF_INET SOCK_DGRAM inet_aton inet_ntoa sockaddr_in);

sub IPPROTO_UDP         {   17 }

## Import symbol generating function

use Symbol qw(gensym);

## ASN.1 Basic Encoding Rules type definitions

sub INTEGER             { 0x02 }  # INTEGER      
sub INTEGER32           { 0x02 }  # Integer32           - SNMPv2c
sub OCTET_STRING        { 0x04 }  # OCTET STRING
sub NULL                { 0x05 }  # NULL       
sub OBJECT_IDENTIFIER   { 0x06 }  # OBJECT IDENTIFIER  
sub SEQUENCE            { 0x30 }  # SEQUENCE       

sub IPADDRESS           { 0x40 }  # IpAddress     
sub COUNTER             { 0x41 }  # Counter  
sub COUNTER32           { 0x41 }  # Counter32           - SNMPv2c 
sub GAUGE               { 0x42 }  # Gauge     
sub GAUGE32             { 0x42 }  # Gauge32             - SNMPv2c
sub UNSIGNED32          { 0x42 }  # Unsigned32          - SNMPv2c 
sub TIMETICKS           { 0x43 }  # TimeTicks  
sub OPAQUE              { 0x44 }  # Opaque   
sub COUNTER64           { 0x46 }  # Counter64           - SNMPv2c 

sub NOSUCHOBJECT        { 0x80 }  # noSuchObject        - SNMPv2c 
sub NOSUCHINSTANCE      { 0x81 }  # noSuchInstance      - SNMPv2c 
sub ENDOFMIBVIEW        { 0x82 }  # endOfMibView        - SNMPv2c 
 
sub GET_REQUEST         { 0xa0 }  # GetRequest-PDU    
sub GET_NEXT_REQUEST    { 0xa1 }  # GetNextRequest-PDU 
sub GET_RESPONSE        { 0xa2 }  # GetResponse-PDU
sub SET_REQUEST         { 0xa3 }  # SetRequest-PDU
sub TRAP                { 0xa4 }  # Trap-PDU
sub GET_BULK_REQUEST    { 0xa5 }  # GetBulkRequest-PDU  - SNMPv2c 
sub INFORM_REQUEST      { 0xa6 }  # InformRequest-PDU   - SNMPv2c 
sub SNMPV2_TRAP         { 0xa7 }  # SNMPv2-Trap-PDU     - SNMPv2c 

## SNMP generic definitions 

sub SNMP_VERSION_1      { 0x00 }  # RFC 1157 SNMP
sub SNMP_VERSION_2C     { 0x01 }  # RFCs 1901, 1905, and 1906 SNMPv2c
sub SNMP_PORT           {  161 }  # RFC 1157 standard UDP port for PDUs
sub SNMP_TRAP_PORT      {  162 }  # RFC 1157 standard UDP port for Trap-PDUs

## RFC 1157 generic-trap definitions

sub COLD_START             { 0 }  # coldStart(0)
sub WARM_START             { 1 }  # warmStart(1)
sub LINK_DOWN              { 2 }  # linkDown(2)
sub LINK_UP                { 3 }  # linkUp(3)
sub AUTHENTICATION_FAILURE { 4 }  # authenticationFailure(4)
sub EGP_NEIGHBOR_LOSS      { 5 }  # egpNeighborLoss(5)
sub ENTERPRISE_SPECIFIC    { 6 }  # enterpriseSpecific(6)

## Default, minimum, and maximum values 

sub DEFAULT_HOSTNAME    { 'localhost' }
sub DEFAULT_COMMUNITY   {    'public' }

sub DEFAULT_MTU         {   484 } # RFC 1157 maximum size in octets
sub DEFAULT_TIMEOUT	{   2.0 } # Timeout period for UDP in seconds
sub DEFAULT_RETRIES	{     5 } # Number of retransmissions 

sub MINIMUM_MTU         {    30 }    
sub MINIMUM_TIMEOUT     {   1.0 }   
sub MINIMUM_RETRIES     {     0 }     

sub MAXIMUM_MTU         { 65535 }
sub MAXIMUM_TIMEOUT     {  60.0 }   
sub MAXIMUM_RETRIES     {    20 }

sub TRUE                  { 0x1 }
sub FALSE                 { 0x0 }

# [public methods] -----------------------------------------------------------

sub session
{
   my ($class, %argv) = @_;
   my ($port, $host_addr, $proto) = (SNMP_PORT, undef, undef);
   
   # Create a new data structure for the object
   my $this = bless {
        '_buffer',        =>  "\0" x DEFAULT_MTU,
        '_community'      =>  DEFAULT_COMMUNITY,
        '_debug'          =>  FALSE,
        '_error'          =>  undef,
        '_error_index'    =>  0,
        '_error_status'   =>  0,
        '_hostname'       =>  DEFAULT_HOSTNAME,
        '_leading_dot'    =>  FALSE,
        '_mtu'            =>  DEFAULT_MTU,
        '_request_id'     =>  (int(rand 0xff) + 1),
        '_retries'        =>  DEFAULT_RETRIES,
        '_sockaddr'       =>  undef,
        '_socket'         =>  gensym(),
        '_timeout'        =>  DEFAULT_TIMEOUT,
        '_translate'      =>  TRUE,
        '_var_bind_list'  =>  undef,
        '_verify_ip'      =>  TRUE,
        '_version'        =>  SNMP_VERSION_1
   }, $class;

   # Validate the passed arguments 
   foreach (keys %argv) {
      if (/^-?community$/i) {
         if ($argv{$_} eq '') {
            $this->{'_error'} = 'Empty community specified';
         } else {
            $this->{'_community'} = $argv{$_};
         }
      } elsif (/^-?debug$/i) {
         $this->debug($argv{$_});
      } elsif (/^-?hostname$/i) {
         if ($argv{$_} eq '') {
            $this->{'_error'} = 'Empty hostname specified';
         } else { 
            $this->{'_hostname'} = $argv{$_}; 
         }
      } elsif (/^-?mtu$/i) {
         $this->mtu($argv{$_});
      } elsif (/^-?port$/i) {
         if ($argv{$_} !~ /^\d+$/) {
            $this->{'_error'} = 'Expected numeric port number'; 
         } else { 
            $port = $argv{$_}; 
         }
      } elsif (/^-?retries$/i) {
         $this->retries($argv{$_});
      } elsif (/^-?timeout$/i) {
         $this->timeout($argv{$_});
      } elsif (/^-?translate$/i) {
         $this->translate($argv{$_});
      } elsif (/^-?verifyip$/i) {
         $this->verify_ip($argv{$_});
      } elsif (/^-?version$/i) {
         $this->version($argv{$_});
      } else {
         $this->{'_error'} = sprintf("Invalid argument '%s'", $_);  
      }
      if (defined($this->{'_error'})) {
         if (wantarray) {
            return (undef, $this->{'_error'});
         } else {
            return undef;
         }
      }
   }    
  
   # Resolve the hostname to an IP address
   if (!defined($host_addr = inet_aton($this->{'_hostname'}))) {
      $this->{'_error'} = sprintf(
         "Unable to resolve hostname '%s'", $this->{'_hostname'}
      );
      if (wantarray) {
         return (undef, $this->{'_error'});
      } else {
         return undef;
      }
   }

   # Pack the address and port information
   $this->{'_sockaddr'} = sockaddr_in($port, $host_addr);

   # Get the protocol number for UDP
   if (!defined($proto = scalar(getprotobyname('udp')))) { 
      $proto = IPPROTO_UDP;
   } 

   # Open an UDP socket for the object
   if (!socket($this->{'_socket'}, PF_INET, SOCK_DGRAM, $proto)) {
      $this->{'_error'} = sprintf("socket(): %s", $!);
      if (wantarray) {
         return (undef, $this->{'_error'});
      } else {
         return undef;
      }
   }

   # Return the object and empty error message (in list context) 
   if (wantarray) {
      return ($this, '');
   } else {
      return $this;
   }
}

sub close
{
   my ($this) = @_;
   
   # Clear all of the buffers and errors
   $this->_object_clear_buffer;
   $this->_object_clear_var_bind_list;
   $this->_object_clear_error;

   # Close the UDP socket and clear the variable name so that
   # we can tell that the socket has been closed elsewhere.

   if (defined($this->{'_socket'})) { 
      if (fileno($this->{'_socket'})) { close($this->{'_socket'}); }
   }

   $this->{'_socket'} = undef;
}

sub get_request
{
   my ($this, @oids) = @_;

   if (!defined($this->_snmp_encode_get_request(@oids))) { 
      return $this->_object_encode_error; 
   }

   if (!defined($this->_udp_send_message)) { 
      return $this->_object_decode_error; 
   }
  
   $this->_snmp_decode_get_reponse;
}

sub get_next_request
{
   my ($this, @oids) = @_;

   if (!defined($this->_snmp_encode_get_next_request(@oids))) {
      return $this->_object_encode_error;
   }

   if (!defined($this->_udp_send_message)) {
      return $this->_object_decode_error;
   }

   $this->_snmp_decode_get_reponse;
}

sub set_request
{
   my ($this, @pairs) = @_;

   if (!defined($this->_snmp_encode_set_request(@pairs))) {
      return $this->_object_encode_error;
   }

   if (!defined($this->_udp_send_message)) {
      return $this->_object_decode_error;
   }

   $this->_snmp_decode_get_reponse;
}

sub trap
{
   my ($this, %argv) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   # Use Sys:Hostname to determine the IP address of the client sending
   # the trap.  Only require the module for Trap-PDUs.

   use Sys::Hostname;

   # Setup default values for the Trap-PDU by creating new entries in 
   # the Net::SNMP object.

   # Use iso.org.dod.internet.private.enterprises for the default enterprise. 
   $this->{'_enterprise'} = '1.3.6.1.4.1';  

   # Get the address of the client sending the trap. 
   $this->{'_agent_addr'} = inet_ntoa(scalar(gethostbyname(hostname())));

   # Use enterpriseSpecific(6) for the generic-trap type.
   $this->{'_generic_trap'} = ENTERPRISE_SPECIFIC;

   # Set the specific-trap type to 0.
   $this->{'_specific_trap'} = 0;

   # Use the "uptime" of the script for the time-stamp.
   $this->{'_time_stamp'} = ((time() - $^T) * 100);

   # Create a local copy of the VarBindList.
   my @var_bind_list = ();


   # Validate the passed arguments
   foreach (keys %argv) {
      if (/^-?enterprise$/i) {
         if ($argv{$_} !~ /^\.?\d+\.\d+(\.\d+)*/) {
            return $this->_snmp_encode_error(
               'Expected enterprise as OBJECT IDENTIFIER in dotted notation' 
            );
         } else {
            $this->{'_enterprise'} = $argv{$_};
         }
      } elsif (/^-?agentaddr$/i) {
         if ($argv{$_} !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
            return $this->_snmp_encode_error(
               'Expected agent-addr in dotted notation'     
            );
         } else {
            $this->{'_agent_addr'} = $argv{$_};
         }
      } elsif (/^-?generictrap$/i) {
         if ($argv{$_} !~ /^\d+$/) {
            return $this->_snmp_encode_error(
               'Expected numeric generic-trap type'
            );
         } else {
            $this->{'_generic_trap'} = $argv{$_};
         }
      } elsif (/^-?specifictrap$/i) {
         if ($argv{$_} !~ /^\d+$/) {
            return $this->_snmp_encode_error(
               'Expected numeric specific-trap type'
            );
         } else {
            $this->{'_specific_trap'} = $argv{$_};
         }
      } elsif (/^-?timestamp$/i) {
         if ($argv{$_} !~ /^\d+$/) {
            return $this->_snmp_encode_error('Expected numeric time-stamp');
         } else {
            $this->{'_time_stamp'} = $argv{$_};
         }
      } elsif (/^-?varbindlist$/i) {
         if (ref($argv{$_}) ne 'ARRAY') {
            return $this->_snmp_encode_error(
               'Expected array reference for variable-bindings'
            );
         } else {
            @var_bind_list = @{$argv{$_}}; 
         }   
      } else {
         return $this->_snmp_encode_error("Invalid argument '%s'", $_);
      }
   }

   if (!defined($this->_snmp_encode_trap(@var_bind_list))) {
      return $this->_object_encode_error;
   }

   $this->_udp_send_buffer;
}

sub get_bulk_request
{
   my ($this, %argv) = @_;

   # Clear any previous error message which also clears the 
   # '_error_status' and '_error_index' so that we can use them 
   # to hold non-repeaters and max-repetitions.  
  
   $this->_object_clear_error;

   # Validate the SNMP version
   if ($this->version != SNMP_VERSION_2C) {
      return $this->_asn1_encode_error(
         'get_bulk_request() only supported with SNMPv2c'
      );
   }

   # Create a local copy of the VarBindList.
   my @var_bind_list = ();

   # Validate the passed arguments
   foreach (keys %argv) {
      if (/^-?nonrepeaters$/i) {
         if ($argv{$_} !~ /^\d+$/) {
            return $this->_snmp_encode_error(
               'Expected numeric non-repeaters value'
            );
         } elsif ($argv{$_} > 2147483647) {
            return $this->_snmp_encode_error(
               'Exceeded maximum non-repeaters value [2147483647]'
            );
         } else {
            # We cheat a little here...
            $this->{'_error_status'} = $argv{$_};
         }
      } elsif (/^-?maxrepetitions$/i) {
         if ($argv{$_} !~ /^\d+$/) {
            return $this->_snmp_encode_error(
               'Expected numeric max-repetitions value'
            );
         } elsif ($argv{$_} > 2147483647) {
            return $this->_snmp_encode_error(
               'Exceeded maximum max-repetitions value [2147483647]'
            );
         } else {
            # We cheat a little here...
            $this->{'_error_index'} = $argv{$_};
         }
      } elsif (/^-?varbindlist$/i) {
         if (ref($argv{$_}) ne 'ARRAY') {
            return $this->_snmp_encode_error(
               'Expected array reference for variable-bindings'
            );
         } else {
            @var_bind_list = @{$argv{$_}};
         }
      } else {
         return $this->_snmp_encode_error("Invalid argument '%s'", $_);
      }
   }

   if ($this->{'_error_status'} > scalar(@var_bind_list)) {
      return $this->_snmp_encode_error(
         'Non-repeaters greater than the number of variable-bindings'
      );
   }

   if (($this->{'_error_status'} == scalar(@var_bind_list)) &&
       ($this->{'_error_index'} != 0))
   {
      return $this->_snmp_encode_error(
         'Non-repeaters equals the number of variable-bindings and ' .
         'max-repetitions is not equal to zero'
      );
   }

   if (!defined($this->_snmp_encode_get_bulk_request(@var_bind_list))) {
      return $this->_object_encode_error;
   }

   if (!defined($this->_udp_send_message)) {
      return $this->_object_decode_error;
   }

   $this->_snmp_decode_get_reponse; 
}

sub inform_request
{
   my ($this, @pairs) = @_;
  
   # Clear any previous error message
   $this->_object_clear_error;

   # Validate the SNMP version
   if ($this->version != SNMP_VERSION_2C) {
      return $this->_asn1_encode_error(
         'inform_request() only supported with SNMPv2c'
      );
   }
 
   if (!defined($this->_snmp_encode_inform_request(@pairs))) {
      return $this->_object_encode_error;
   }

   if (!defined($this->_udp_send_message)) {
      return $this->_object_decode_error;
   }

   $this->_snmp_decode_get_reponse;
}

sub snmpv2_trap 
{
   my ($this, @pairs) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   # Validate the SNMP version
   if ($this->version != SNMP_VERSION_2C) {
      return $this->_asn1_encode_error(
         'snmpv2_trap() only supported with SNMPv2c'
      );
   }

   if (!defined($this->_snmp_encode_v2_trap(@pairs))) {
      return $this->_object_encode_error;
   }

   $this->_udp_send_buffer;
}

sub get_table
{
   my ($this, $base_oid) = @_;
   my ($repeat_cnt, $table, $result, $next_oid) = (0, undef, undef, undef);

   $next_oid = $base_oid;

   # Use get-next-requests until the response is not a subtree of the
   # base OBJECT IDENTIFIER.  Return the table only if there are no
   # errors other than a noSuchName(2) error since the table could
   # be at the end of the tree.  Also return the table when the value
   # of the OID equals endOfMibView(2) when using SNMPv2c.

   do {
      if (defined($result)) {
         if (!exists($table->{$next_oid})) {
            $table->{$next_oid} = $result->{$next_oid};
         } elsif ((($result->{$next_oid} eq 'endOfMibView') ||   # translate
                  ($this->{'_error_status'} == ENDOFMIBVIEW)) && # !translate 
                  ($this->version == SNMP_VERSION_2C))
         {
            return ($this->{'_var_bind_list'} = $table);
         } else {
            $repeat_cnt++;
         }
      }
      # Check to make sure that the remote host does not respond
      # incorrectly causing the get-next-requests to loop forever.
      if ($repeat_cnt > 5) {
         return $this->_object_decode_error(
            'Loop detected with table on remote host'
         );
      }
      if (!defined($this->_snmp_encode_get_next_request($next_oid))) {
         return $this->_object_encode_error;
      }
      if (!defined($this->_udp_send_message)) {
         return $this->_object_decode_error;
      }
      if (!defined($result = $this->_snmp_decode_get_reponse)) {
         # Check for noSuchName(2) error 
         if ($this->{'_error_status'} == 2) { 
            return ($this->{'_var_bind_list'} = $table);
         } else {
            return $this->_object_decode_error;
         }
      }
      ($next_oid) = keys(%{$result});
   } while (_asn1_oid_subtree($base_oid, $next_oid));

   if (!defined($table)) {
      $this->_object_decode_error('Requested table is empty');
   }

   $this->{'_var_bind_list'} = $table;
}

sub error
{
   my ($this) = @_;

   if (!defined($this->{'_error'})) { return ''; }
  
   $this->{'_error'};
}

sub error_status  { $_[0]->{'_error_status'};  }

sub error_index   { $_[0]->{'_error_index'};   }

sub var_bind_list { $_[0]->{'_var_bind_list'}; }

sub timeout
{
   my ($this, $timeout) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   if (@_ == 2) {
      if (($timeout >= MINIMUM_TIMEOUT) && ($timeout <= MAXIMUM_TIMEOUT)) { 
         $this->{'_timeout'} = $timeout; 
      } else {
         return $this->_object_encode_error(
            "Timeout out of range [%03.01f - %03.01f seconds]",
            MINIMUM_TIMEOUT, MAXIMUM_TIMEOUT
         );
      } 
   }

   $this->{'_timeout'};
}

sub version
{
   my ($this, $version) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   # Allow the user some flexability 
   my $supported = {
      '1'       => SNMP_VERSION_1,
      'v1'      => SNMP_VERSION_1,
      'snmpv1'  => SNMP_VERSION_1,
      '2'       => SNMP_VERSION_2C,
      '2c'      => SNMP_VERSION_2C,
      'v2'      => SNMP_VERSION_2C,
      'v2c'     => SNMP_VERSION_2C,
      'snmpv2'  => SNMP_VERSION_2C,
      'snmpv2c' => SNMP_VERSION_2C
   };

   if (@_ == 2) {
      if (exists($supported->{lc($version)})) {
         $this->{'_version'} = $supported->{lc($version)};
      } else {
         return $this->_object_encode_error(
            "Unknown or invalid SNMP version [%s]", $version
         );
      }
   }

   $this->{'_version'};
}

sub retries 
{
   my ($this, $retries) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   if (@_ == 2) {
      if (($retries >= MINIMUM_RETRIES) && ($retries <= MAXIMUM_RETRIES)) { 
         $this->{'_retries'} = $retries; 
      } else {
         return $this->_object_encode_error(
            "Retries out of range [%d - %d]", MINIMUM_RETRIES, MAXIMUM_RETRIES
         );
      }
   }

   $this->{'_retries'};
}

sub mtu 
{
   my ($this, $mtu) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   if (@_ == 2) {
      if (($mtu >= MINIMUM_MTU) && ($mtu <= MAXIMUM_MTU )) { 
         $this->{'_mtu'} = $mtu; 
      } else {
         return $this->_object_encode_error(
            "MTU out of range [%d - %d octets]", MINIMUM_MTU, MAXIMUM_MTU
         );
      }
   }

   $this->{'_mtu'};
}

sub translate
{
   my ($this, $flag) = @_;
 
   if (@_ == 2) {
      if ($flag) {
         $this->{'_translate'} = TRUE;
      } else {
         $this->{'_translate'} = FALSE;
      }
   }

   $this->{'_translate'};
}

sub verify_ip
{
   my ($this, $flag) = @_;

   if (@_ == 2) {
      if ($flag) {
         $this->{'_verify_ip'} = TRUE;
      } else {
         $this->{'_verify_ip'} = FALSE;
      }
   }
 
   $this->{'_verify_ip'};
}

sub debug
{
   my ($this, $flag) = @_;

   if (@_ == 2) {
      if ($flag) {
         $this->{'_debug'} = TRUE;
      } else {
         $this->{'_debug'} = FALSE;
      }
   }

   $this->{'_debug'};  
}

sub DESTROY { $_[0]->close; } 

# [private methods] ----------------------------------------------------------


###
## Simple Network Managment Protocol (SNMP) encode methods
###

sub _snmp_encode_get_request
{
   my ($this, @oids) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   $this->_snmp_encode_message(
      GET_REQUEST, $this->_snmp_create_oid_null_pairs(@oids)
   ); 
}

sub _snmp_encode_get_next_request
{
   my ($this, @oids) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   $this->_snmp_encode_message(
      GET_NEXT_REQUEST, $this->_snmp_create_oid_null_pairs(@oids)
   );
}

sub _snmp_encode_get_response
{
   my ($this) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   $this->_snmp_encode_error('GetResponse-PDU not supported');
}


sub _snmp_encode_set_request
{
   my ($this, @oid_values) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   $this->_snmp_encode_message(
      SET_REQUEST, $this->_snmp_create_oid_value_pairs(@oid_values)
   );
}

sub _snmp_encode_trap
{
   my ($this, @oid_values) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   $this->_snmp_encode_message(
      TRAP, $this->_snmp_create_oid_value_pairs(@oid_values)
   );
}

sub _snmp_encode_get_bulk_request
{
   my ($this, @oids) = @_;

   # DO NOT clear any previous error message or the non-repeaters
   # and the max-repetitions will be reset! 

   $this->_snmp_encode_message(
      GET_BULK_REQUEST, $this->_snmp_create_oid_null_pairs(@oids)
   );
}

sub _snmp_encode_inform_request
{
   my ($this, @oid_values) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   $this->_snmp_encode_message(
      INFORM_REQUEST, $this->_snmp_create_oid_value_pairs(@oid_values)
   );
}

sub _snmp_encode_v2_trap
{
   my ($this, @oid_values) = @_;

   # Clear any previous error message
   $this->_object_clear_error;

   $this->_snmp_encode_message(
      SNMPV2_TRAP, $this->_snmp_create_oid_value_pairs(@oid_values)
   );
} 

sub _snmp_encode_message
{
   my ($this, $type, @var_bind) = @_;

   # Do not do anything if there has already been an error
   if (defined($this->{'_error'})) { return $this->_snmp_encode_error; }

   if (!defined($type)) { 
      return $this->_snmp_encode_error('No SNMP PDU type defined');
   }

   # We need to reset the buffer that might have been defined 
   # from a previous message and clear the var_bind_list. 

   $this->_object_clear_buffer;
   $this->_object_clear_var_bind_list;
   $this->_object_clear_leading_dot;

   # We need to encode the message in reverse order so everything
   # ends up in the correct place.
  
   # Encode the PDU or Trap-PDU
   if ($type == TRAP) { 
      if (!defined($this->_snmp_encode_trap_pdu(@var_bind))) {
         return $this->_snmp_encode_error;
      }
   } else {
      if (!defined($this->_snmp_encode_pdu(@var_bind))) {
         return $this->_snmp_encode_error;
      }
   }

   # Encode the PDU type
   if (!defined($this->_asn1_encode($type))) { 
      return $this->_snmp_encode_error; 
   }

   # Encode the community name
   if (!defined($this->_asn1_encode(OCTET_STRING, $this->{'_community'}))) {
      return $this->_snmp_encode_error;
   }

   # Encode the SNMP version
   if (!defined($this->_asn1_encode(INTEGER, $this->{'_version'}))) {
      return $this->_snmp_encode_error;
   } 

   # Encode the SNMP message SEQUENCE 
   if (!defined($this->_asn1_encode(SEQUENCE))) {
      return $this->_snmp_encode_error;
   } 

   # Return the buffer
   $this->{'_buffer'};
}
 
sub _snmp_encode_pdu
{
   my ($this, @var_bind) = @_;

   # We need to encode eveything in reverse order so the 
   # objects end up in the correct place.

   # Encode the variable-bindings 
   if (!defined($this->_snmp_encode_var_bind_list(@var_bind))) {
      return $this->_snmp_encode_error;
   } 

   # Encode the error-index or max-repetitions (GetBulkRequest-PDU)  
   if (!defined($this->_asn1_encode(INTEGER, $this->{'_error_index'}))) {
      return $this->_snmp_encode_error;
   } 
   
   # Encode the error-status or non-repeaters (GetBulkRequest-PDU) 
   if (!defined($this->_asn1_encode(INTEGER, $this->{'_error_status'}))) {
      return $this->_snmp_encode_error;
   }

   # Encode the request-id, after incrementing by one
   if (!defined($this->_asn1_encode(INTEGER, ++$this->{'_request_id'}))) {
      return $this->_snmp_encode_error;
   }
 
   # Return the buffer 
   $this->{'_buffer'}; 
}

sub _snmp_encode_trap_pdu
{
   my ($this, @var_bind) = @_;

   # We need to encode eveything in reverse order so the
   # objects end up in the correct place.

   # Encode the variable-bindings
   if (!defined($this->_snmp_encode_var_bind_list(@var_bind))) {
      return $this->_snmp_encode_error;
   }

   # Encode the time-stamp
   if (!defined($this->_asn1_encode(TIMETICKS, $this->{'_time_stamp'}))) {
      return $this->_snmp_encode_error;
   }

   # Encode the specific-trap type
   if (!defined($this->_asn1_encode(INTEGER, $this->{'_specific_trap'}))) {
      return $this->_snmp_encode_error;
   }

   # Encode the generic-trap type
   if (!defined($this->_asn1_encode(INTEGER, $this->{'_generic_trap'}))) {
      return $this->_snmp_encode_error;
   }

   # Encode the agent-addr
   if (!defined($this->_asn1_encode(IPADDRESS, $this->{'_agent_addr'}))) {
      return $this->_snmp_encode_error;
   }

   # Encode the enterprise
   if (!defined(
         $this->_asn1_encode(OBJECT_IDENTIFIER, $this->{'_enterprise'}))
      ) 
   { 
      return $this->_snmp_encode_error;
   }

   # Return the buffer
   $this->{'_buffer'};
}

sub _snmp_encode_var_bind_list
{
   my ($this, @var_bind) = @_;
   my ($type, $value) = (undef, '');

   # The passed array is expected to consist of groups of four values
   # consisting of two sets of ASN.1 types and their values.

   if ((scalar(@var_bind) % 4)) {
      return $this->_snmp_encode_error(
         "Invalid number of VarBind parameters [%d]", scalar(@var_bind) 
      );
   }
 
   # Encode the objects from the end of the list, so they are wrapped 
   # into the packet as expected.  Also, check to make sure that the 
   # OBJECT IDENTIFIER is in the correct place.

   while (@var_bind) {
      # Encode the ObjectSyntax
      $value = pop(@var_bind);
      $type  = pop(@var_bind);
      if (!defined($this->_asn1_encode($type, $value))) { 
         return $this->_snmp_encode_error; 
      }
      # Encode the ObjectName 
      $value = pop(@var_bind);
      $type  = pop(@var_bind);
      if ($type != OBJECT_IDENTIFIER) {
         return $this->_snmp_encode_error(
            'Expected OBJECT IDENTIFIER in VarBindList'
         );
      }
      if (!defined($this->_asn1_encode($type, $value))) {
         return $this->_snmp_encode_error;
      }
      # Encode the VarBind SEQUENCE 
      if (!defined($this->_asn1_encode(SEQUENCE))) {
         return $this->_snmp_encode_error;
      } 
   } 

   # Encode the VarBindList SEQUENCE 
   if (!defined($this->_asn1_encode(SEQUENCE))) { 
      return $this->_snmp_encode_error; 
   }

   # Return the buffer
   $this->{'_buffer'};
}

sub _snmp_create_oid_null_pairs
{
   my ($this, @oids) = @_;
   my ($oid) = (undef);
   my @pairs = ();

   while (@oids) {
      $oid = shift(@oids);
      if ($oid !~ /^\.?\d+\.\d+(\.\d+)*/) {
         return $this->_snmp_encode_error(
            'Expected OBJECT IDENTIFIER in dotted notation'
         );
      }
      push(@pairs, OBJECT_IDENTIFIER, $oid, NULL, '');
   }

   @pairs;
}

sub _snmp_create_oid_value_pairs
{
   my ($this, @oid_values) = @_;
   my ($oid) = (undef);
   my @pairs = ();

   if ((scalar(@oid_values) % 3)) {
      return $this->_snmp_encode_error(
         'Expected [OBJECT IDENTIFIER, ASN.1 type, object value] combination'
      );
   }

   while (@oid_values) {
      $oid = shift(@oid_values);
      if ($oid !~ /^\.?\d+\.\d+(\.\d+)*/) {
         return $this->_snmp_encode_error(
            'Expected OBJECT IDENTIFIER in dotted notation'
         );
      }
      push(@pairs, OBJECT_IDENTIFIER, $oid);
      push(@pairs, shift(@oid_values), shift(@oid_values));
   }

   @pairs;
}

sub _snmp_encode_error
{
   my ($this, @error) = @_;

   # Clear the buffer
   $this->_object_clear_buffer;

   $this->_object_error(@error);
}


###
## Simple Network Managment Protocol (SNMP) decode methods
###

sub _snmp_decode_get_request
{
   $_[0]->_snmp_decode_error('GetRequest-PDU not supported');
}

sub _snmp_decode_get_next_request
{
   $_[0]->_snmp_decode_error('GetNextRequest-PDU not supported');
}

sub _snmp_decode_get_reponse
{
   $_[0]->_snmp_decode_message(GET_RESPONSE);
}

sub _snmp_decode_set_request
{
   $_[0]->_snmp_decode_error('SetRequest-PDU not supported');
}

sub _snmp_decode_trap
{
   $_[0]->_snmp_decode_error('Trap-PDU not supported');
}

sub _snmp_decode_get_bulk_request
{
   $_[0]->_snmp_decode_error('GetBulkRequest-PDU not supported');
}

sub _snmp_decode_inform_request
{
   $_[0]->_snmp_decode_error('InformRequest-PDU not supported');
}

sub _snmp_decode_v2_trap
{
   $_[0]->_snmp_decode_error('SNMPv2-Trap-PDU not supported');
}

sub _snmp_decode_message
{
   my ($this, $type) = @_;
   my $value = undef;

   # First we need to reset the var_bind_list and errors that
   # might have been set from a previous message.

   $this->_object_clear_var_bind_list;
   $this->_object_clear_error;

   if (!defined($type)) {
      return $this->_snmp_decode_error('SNMP PDU type not defined');
   }

   # Decode the message SEQUENCE
   if (!defined($value = $this->_asn1_decode(SEQUENCE))) {
      return $this->_snmp_decode_error;
   } 
   if ($value != $this->_object_buffer_length) {
      return $this->_snmp_decode_error(
         'Encoded message length not equal to remaining data length' 
      );
   }

   # Decode the version
   if (!defined($value = $this->_asn1_decode(INTEGER))) {
      return $this->_snmp_decode_error;
   } 
   if ($value != $this->{'_version'}) {
      return $this->_snmp_decode_error(
         "Received version [0x%02x] is not equal to transmitted version " .
         "[0x%02x]", $value, $this->{'_version'}
      );
   }

   # Decode the community
   if (!defined($value = $this->_asn1_decode(OCTET_STRING))) {
      return $this->_snmp_decode_error;
   }
   if ($value ne $this->{'_community'}) {
      return $this->_snmp_decode_error(
         "Received community [%s] is not equal to transmitted community [%s]",  
         $value, $this->{'_community'}
      );
   } 

   # Decode the PDU type
   if (!defined($value = $this->_asn1_decode($type))) {
      return $this->_snmp_decode_error;
   }

   # Decode the PDU
   $this->_snmp_decode_pdu;
}

sub _snmp_decode_pdu
{
   my ($this) = @_;
   my $value = undef;

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

   # Decode the request-id
   if (!defined($value = $this->_asn1_decode(INTEGER))) {
      return $this->_snmp_decode_error;
   }
   if ($value != $this->{'_request_id'}) {
      return $this->_snmp_decode_error(
         "Received request-id [%s] is not equal to transmitted request-id [%s]",
         $value, $this->{'_request_id'} 
      );
   }   

   # Decode the error-status and error-index 
   if (!defined($this->{'_error_status'} = $this->_asn1_decode(INTEGER))) {
      $this->{'_error_status'} = 0;
      return $this->_snmp_decode_error;
   }
   if (!defined($this->{'_error_index'} = $this->_asn1_decode(INTEGER))) {
      $this->{'_error_index'} = 0;
      return $this->_snmp_decode_error;
   }
   if (($this->{'_error_status'} != 0) || ($this->{'_error_index'} != 0)) {
      return $this->_snmp_decode_error(
         "Received SNMP %s(%s) error-status at error-index %s",
         $error_status[$this->{'_error_status'}], $this->{'_error_status'}, 
         $this->{'_error_index'}
      );
   } 

   # Decode the VarBindList
   $this->_snmp_decode_var_bind_list;
}

sub _snmp_decode_var_bind_list
{
   my ($this) = @_;
   my ($value, $oid) = (undef, undef);

   # Decode the VarBindList SEQUENCE
   if (!defined($value = $this->_asn1_decode(SEQUENCE))) {
      return $this->_snmp_decode_error;
   }
   if ($value != $this->_object_buffer_length) {
      return $this->_snmp_decode_error(
         'Encoded VarBindList length not equal to remaining data length' 
      );
   }

   $this->{'_var_bind_list'} = {};

   while ($this->_object_buffer_length) {
      # Decode the VarBind SEQUENCE
      if (!defined($this->_asn1_decode(SEQUENCE))) {
         return $this->_snmp_decode_error;
      }
      # Decode the ObjectName
      if (!defined($oid = $this->_asn1_decode(OBJECT_IDENTIFIER))) {
         return $this->_snmp_decode_error;
      }
      # Decode the ObjectSyntax
      if (!defined($value = $this->_asn1_decode)) {
         return $this->_snmp_decode_error;
      }
      # Create a hash consisting of the OBJECT IDENTIFIER as a
      # key and the ObjectSyntax as the value.
      $this->_debug_message("{ %s => %s }\n", $oid, $value);
      $this->{'_var_bind_list'}->{$oid} = $value;
   }

   # Return the var_bind_list hash
   $this->{'_var_bind_list'};
}

sub _snmp_decode_error
{
   my ($this, @error) = @_;

   # Clear var_bind_list
   $this->_object_clear_var_bind_list;

   $this->_object_error(@error);
}


###
## Abstract Syntax Notation One (ASN.1) encode methods
### 

sub _asn1_encode
{ 
   my ($this, $type, $value) = @_;
   my ($method) = (undef);

   my $encode = {
        INTEGER,            '_asn1_encode_integer',
        OCTET_STRING,       '_asn1_encode_octet_string',
        NULL,               '_asn1_encode_null',
        OBJECT_IDENTIFIER,  '_asn1_encode_object_identifier',
        SEQUENCE,           '_asn1_encode_sequence',
        IPADDRESS,          '_asn1_encode_ipaddress',
        COUNTER,            '_asn1_encode_counter',
        GAUGE,              '_asn1_encode_gauge',
        TIMETICKS,          '_asn1_encode_timeticks',
        OPAQUE,             '_asn1_encode_opaque',
        COUNTER64,          '_asn1_encode_counter64',
        NOSUCHOBJECT,       '_asn1_encode_nosuchobject',
        NOSUCHINSTANCE,     '_asn1_encode_nosuchinstance',
        ENDOFMIBVIEW,       '_asn1_encode_endofmibview',
        GET_REQUEST,        '_asn1_encode_get_request',
        GET_NEXT_REQUEST,   '_asn1_encode_get_next_request',
        GET_RESPONSE,       '_asn1_encode_get_response',
        SET_REQUEST,        '_asn1_encode_set_request',
        TRAP,               '_asn1_encode_trap',
        GET_BULK_REQUEST,   '_asn1_encode_get_bulk_request',
        INFORM_REQUEST,     '_asn1_encode_inform_request',
        SNMPV2_TRAP,        '_asn1_encode_v2_trap'
   };

   if (!defined($type)) {
      return $this->_asn1_encode_error('ASN.1 type not defined');
   }

   if (exists($encode->{$type})) {
      $method = $encode->{$type};
      $this->$method($value);
   } else {
      $this->_asn1_encode_error("Unknown ASN.1 type [%s]", $type);
   }
}

sub _asn1_encode_type_length
{
   my ($this, $type, $value) = @_;
   my $length = 0;

   if (defined($this->{'_error'})) { return $this->_asn1_encode_error; }

   if (!defined($type)) {
      return $this->_asn1_Error('ASN.1 type not defined');
   }

   if (!defined($value)) { $value = ''; }

   $length = length($value);

   if ($length < 0x80) {
      return $this->_object_put_buffer(
         join('', pack('C2', $type, $length), $value)
      );
   } elsif ($length <= 0xff) {
      return $this->_object_put_buffer(
         join('', pack('C3', $type, (0x80 | 1), $length), $value)
      );
   } elsif ($length <= 0xffff) {
      return $this->_object_put_buffer(
         join('', pack('CCn', $type, (0x80 | 2), $length), $value)
      );
   } 
      
   $this->_asn1_encode_error('Unable to encode ASN.1 length');
}

sub _asn1_encode_integer
{
   my ($this, $integer) = @_;

   if (!defined($integer)) {
      return $this->_asn1_encode_error('INTEGER value not defined');
   }

   if ($integer !~ /^-?\d+$/) {
      return $this->_asn1_encode_error('Expected numeric INTEGER value');
   }

   $this->_asn1_encode_integer32(INTEGER, $integer);
}

sub _asn1_encode_unsigned32
{
   my ($this, $type, $u32) = @_;

   if (!defined($type)) { $type = INTEGER; }

   if (!defined($u32)) { 
      return $this->_asn1_encode_error(
         "%s value not defined", _asn1_itoa($type) 
      );
   }

   if ($u32 !~ /^\d+$/) {
      return $this->_asn1_encode_error(
         "Expected positive numeric %s value", _asn1_itoa($type)
      );
   }

   $this->_asn1_encode_integer32($type, $u32);
}

sub _asn1_encode_integer32
{
   my ($this, $type, $integer) = @_;
   my ($size, $value, $negative, $prefix) = (4, '', FALSE, FALSE);

   if (!defined($type)) { $type = INTEGER; }

   if (!defined($integer)) {
      return $this->_asn1_encode_error(
         "%s value not defined", _asn1_itoa($type)
      );
   }

   # Determine if the value is positive or negative
   if ($integer =~ /^-/) { $negative = TRUE; } 

   # Check to see if the most significant bit is set, if it is we
   # need to prefix the encoding with a zero byte.

   if (((($integer & 0xff000000) >> 24) & 0x80) && (!$negative)) { 
      $size++; 
      $prefix = TRUE;
   }

   # Remove occurances of nine consecutive ones (if negative) or zeros 
   # from the most significant end of the two's complement integer.

   while ((((!($integer & 0xff800000))) || 
           ((($integer & 0xff800000) == 0xff800000) && ($negative))) && 
           ($size > 1)) 
   {
      $size--;
      $integer <<= 8;
   }

   # Add a zero byte so the integer is decoded as a positive value
   if ($prefix) {
      $value .= pack('x');
      $size--;
   }

   # Build the integer
   while ($size-- > 0) {
      $value .= pack('C', (($integer & 0xff000000) >> 24));
      $integer <<= 8;
   }

   # Encode ASN.1 header
   $this->_asn1_encode_type_length($type, $value);
}

sub _asn1_encode_octet_string
{
   if (!defined($_[1])) {
      return $_[0]->_asn1_encode_error('OCTET STRING value not defined');
   }

   $_[0]->_asn1_encode_type_length(OCTET_STRING, $_[1]);
}

sub _asn1_encode_null
{
   $_[0]->_asn1_encode_type_length(NULL, '');
}

sub _asn1_encode_object_identifier
{
   my ($this, $oid) = @_;
   my ($value, $subid, $mask, $bits, $tmask, $tbits) = ('', 0, 0, 0, 0, 0);

   if (!defined($oid)) {
      return $this->_asn1_Error('OBJECT IDENTIFIER value not defined');
   }

   # Input is expected in dotted notation, so break it up into subids
   my @subids = split(/\./, $oid);

   # If there was a leading dot on _any_ OBJECT IDENTIFIER passed to 
   # an encode method, return a leading dot on _all_ of the OBJECT
   # IDENTIFIERs in the decode methods.

   if ($subids[0] eq '') { 
      $this->_debug_message("leading dot present\n");
      $this->{'_leading_dot'} = TRUE;
      shift(@subids);
   }

   # The first two subidentifiers are encoded into the first identifier
   # using the the equation: subid = ((first * 40) + second).  We just
   # return an error if there are not at least two subidentifiers.

   if (scalar(@subids) < 2) { 
      return $this->_asn1_encode_error('Invalid OBJECT IDENTIFIER length'); 
   }

   $value = 40 * shift(@subids);
   $value = pack('C', ($value + shift(@subids)));

   # Encode each value as seven bits with the most significant bit
   # indicating the end of a subidentifier.

   foreach $subid (@subids) {
      if (($subid < 0x7f) && ($subid >= 0)) {
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
   $this->_asn1_encode_type_length(OBJECT_IDENTIFIER, $value);
}

sub _asn1_encode_sequence
{
   $_[0]->_asn1_encode_type_length(SEQUENCE, $_[0]->_object_get_buffer);
}

sub _asn1_encode_ipaddress
{
   my ($this, $address) = @_;

   if (!defined($address)) {
      return $this->_asn1_encode_error('IpAddress not defined');
   }

   if ($address  !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {
      return $this->_asn1_encode_error('Expected IpAddress in dotted notation');
   } 

   $this->_asn1_encode_type_length(
      IPADDRESS, pack('C4', split(/\./, $address))
   );
}

sub _asn1_encode_counter
{
   $_[0]->_asn1_encode_unsigned32(COUNTER, $_[1]);
}

sub _asn1_encode_gauge
{
   $_[0]->_asn1_encode_unsigned32(GAUGE, $_[1]);
}

sub _asn1_encode_timeticks
{
   $_[0]->_asn1_encode_unsigned32(TIMETICKS, $_[1]);
}

sub _asn1_encode_opaque
{
   if (!defined($_[1])) {
      return $_[0]->_asn1_encode_error('Opaque value not defined');
   }

   $_[0]->_asn1_encode_type_length(OPAQUE, $_[1]);
}

sub _asn1_encode_counter64
{
   my ($this, $c64) = @_;
   my ($quotient, $remainder) = (0, 0);
   my @bytes = ();

   # Validate the SNMP version
   if ($this->version != SNMP_VERSION_2C) {
      return $this->_asn1_encode_error(
         'Counter64 only supported with SNMPv2c'
      );
   }

   # Validate the passed value
   if (!defined($c64)) {
      return $this->_asn1_encode_error('Counter64 value not defined');
   }

   if ($c64 !~ /^\+?\d+$/) {
      return $this->_asn1_encode_error(
         'Expected positive numeric Counter64 value'
      );
   }

   # Only load the Math::BigInt module when needed
   use Math::BigInt;

   $c64 = Math::BigInt->new($c64);

   if ($c64 eq 'NaN') {
      return $this->_asn1_encode_error('Invalid Counter64 value');
   }

   # Make sure the value is no more than 8 bytes long
   if ($c64->bcmp('18446744073709551615') > 0) {
      return $this->_asn1_encode_error('Counter64 value too high');
   }

   if ($c64 == 0) { unshift(@bytes, 0x00); }

   while ($c64 > 0) {
      ($quotient, $remainder) = $c64->bdiv(256);
      $c64 = Math::BigInt->new($quotient);
      unshift(@bytes, $remainder);
   }

   # Make sure that the value is encoded as a positive value
   if ($bytes[0] & 0x80) { unshift(@bytes, 0x00); }

   $this->_asn1_encode_type_length(COUNTER64, pack('C*', @bytes));
}

sub _asn1_encode_nosuchobject
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_encode_error(
         'noSuchObject only supported with SNMPv2c'
      );
   }

   $_[0]->_asn1_encode_type_length(NOSUCHOBJECT, '');
}

sub _asn1_encode_nosuchinstance
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_encode_error(
         'noSuchInstance only supported with SNMPv2c'
      );
   }

   $_[0]->_asn1_encode_type_length(NOSUCHINSTANCE, '');
}

sub _asn1_encode_endofmibview
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_encode_error(
         'endOfMibView only supported with SNMPv2c'
      );
   }

   $_[0]->_asn1_encode_type_length(ENDOFMIBVIEW, '');
}

sub _asn1_encode_get_request
{
   $_[0]->_asn1_encode_type_length(GET_REQUEST, $_[0]->_object_get_buffer);
}

sub _asn1_encode_get_next_request
{
   $_[0]->_asn1_encode_type_length(GET_NEXT_REQUEST, $_[0]->_object_get_buffer);
}

sub _asn1_encode_get_response
{
   $_[0]->_asn1_encode_type_length(GET_RESPONSE, $_[0]->_object_get_buffer);
}

sub _asn1_encode_set_request
{
   $_[0]->_asn1_encode_type_length(SET_REQUEST, $_[0]->_object_get_buffer);
}

sub _asn1_encode_trap
{
   $_[0]->_asn1_encode_type_length(TRAP, $_[0]->_object_get_buffer);
}

sub _asn1_encode_get_bulk_request
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_encode_error(
         'GetBulkRequest-PDU only supported with SNMPv2c'
      );
   }

   $_[0]->_asn1_encode_type_length(GET_BULK_REQUEST, $_[0]->_object_get_buffer);
}

sub _asn1_encode_inform_request
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_encode_error(
         'InformRequest-PDU only supported with SNMPv2c'
      );
   }

   $_[0]->_asn1_encode_type_length(INFORM_REQUEST, $_[0]->_object_get_buffer);
}

sub _asn1_encode_v2_trap
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_encode_error(
         'SNMPv2-Trap-PDU only supported with SNMPv2c'
      );
   }

   $_[0]->_asn1_encode_type_length(SNMPV2_TRAP, $_[0]->_object_get_buffer);
}

sub _asn1_encode_error
{
   my ($this, @error) = @_;

   # Clear the buffer
   $this->_object_clear_buffer;

   $this->_object_error(@error);
}


###
## Abstract Syntax Notation One (ASN.1) decode methods
###

sub _asn1_decode
{
   my ($this, $expected) = @_;
   my ($method) = (undef);

   my $decode = {
        INTEGER,            '_asn1_decode_integer32',
        OCTET_STRING,       '_asn1_decode_octet_string',
        NULL,               '_asn1_decode_null',
        OBJECT_IDENTIFIER,  '_asn1_decode_object_identifier',
        SEQUENCE,           '_asn1_decode_sequence',
        IPADDRESS,          '_asn1_decode_ipaddress',
        COUNTER,            '_asn1_decode_counter',
        GAUGE,              '_asn1_decode_gauge',
        TIMETICKS,          '_asn1_decode_timeticks',
        OPAQUE,             '_asn1_decode_opaque',
        COUNTER64,          '_asn1_decode_counter64',
        NOSUCHOBJECT,       '_asn1_decode_nosuchobject',
        NOSUCHINSTANCE,     '_asn1_decode_nosuchinstance',
        ENDOFMIBVIEW,       '_asn1_decode_endofmibview',
        GET_REQUEST,        '_asn1_decode_get_request',
        GET_NEXT_REQUEST,   '_asn1_decode_get_next_request',
        GET_RESPONSE,       '_asn1_decode_get_reponse',
        SET_REQUEST,        '_asn1_decode_set_request',
        TRAP,               '_asn1_decode_trap',
        GET_BULK_REQUEST,   '_asn1_decode_get_bulk_request',
        INFORM_REQUEST,     '_asn1_decode_inform_request',
        SNMPV2_TRAP,        '_asn1_decode_v2_trap'
   };

   if (defined($this->{'_error'})) { return $this->_asn1_decode_error; }

   my $type = $this->_object_get_buffer(1);

   if (defined($type)) {
      $type = unpack('C', $type);
      if (exists($decode->{$type})) {
         $method = $decode->{$type};
         if (defined($expected)) {
            if ($type != $expected) {
               return $this->_asn1_decode_error(
                  "Expected %s, but found %s", 
                  _asn1_itoa($expected), _asn1_itoa($type)
               );
            }
         }
         return $this->$method();
      } else {
         return $this->_asn1_decode_error("Unknown ASN.1 type [0x%02x]", $type);
      }
   }
 
   $this->_asn1_decode_error;
}

sub _asn1_decode_length
{
   my ($this) = @_;
   my ($length, $byte_cnt) = (0, 0);
  
   if (defined($this->{'_error'})) { return $this->_asn1_decode_error; }

   if (!defined($length = $this->_object_get_buffer(1))) {
      return $this->_asn1_decode_error;
   } 
   $length = unpack('C', $length);
 
   if ($length & 0x80) {
      $byte_cnt = ($length & 0x7f);
      if ($byte_cnt == 0) {
         return $this->_asn1_decode_error(
            'Indefinite ASN.1 lengths not supported'
         );  
      } elsif ($byte_cnt <= 4) {
         if (!defined($length = $this->_object_get_buffer($byte_cnt))) {
            return $this->_asn1_decode_error;
         }
         $length = unpack('N', ("\0" x (4 - $byte_cnt) . $length)); 
      } else {   
         return $this->_asn1_decode_error(
            "ASN.1 length too long (%d bytes)", $byte_cnt 
         );
      }
   }
 
   $length;
}

sub _asn1_decode_integer32
{
   my ($this) = @_;
   my ($length, $integer, $negative, $byte) = (undef, 0, FALSE, undef);

   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   # Just return zero if the object length is zero
   if ($length < 1) { return '0'; }
   
   if (!defined($byte = $this->_object_get_buffer(1))) { 
      return $this->_asn1_decode_error; 
   }
   $length--;

   # If the first bit is set, the integer is negative
   if (($byte = unpack('C', $byte)) & 0x80) {
      $integer = -1;
      $negative = TRUE; 
   }

   if (($length > 4) || (($length > 3) && ($byte != 0))) {
      return $this->_asn1_decode_error(
         "INTEGER length too long (%d bytes)", ($length + 1)
      );
   }

   $integer = (($integer << 8) | $byte);

   while ($length--) {
      if (!defined($byte = $this->_object_get_buffer(1))) {
         return $this->_asn1_decode_error;
      }
      $integer = (($integer << 8) | unpack('C', $byte));
   }
 
   if ($negative) { 
      sprintf("%d", $integer); 
   } else {
      $integer = abs($integer);
      sprintf("%u", $integer);
   }
}

sub _asn1_decode_octet_string
{
   my ($this) = @_;
   my ($length, $string) = (undef, undef);

   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   if (defined($string = $this->_object_get_buffer($length))) {
      if (($string =~ /[\x00-\x08\x0b\x0e-\x1f\x7f-\xff]/g) && 
          ($this->translate)) 
      {
         $this->_debug_message(
            "translating OCTET STRING to printable hex string\n"
         );
         return sprintf("0x%s", unpack('H*', $string));
      } else {
         return $string;
      }
   } else {
      return $this->_asn1_decode_error;
   }
}

sub _asn1_decode_null
{
   my ($this) = @_;
   my ($length) = (undef);

   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   if ($length != 0) {
      return $this->_asn1_decode_error('NULL length not equal to zero');
   }

   if ($this->translate) {
      $this->_debug_message("translating NULL to 'NULL' string\n");
      'NULL';
   } else {
      '';
   }
}

sub _asn1_decode_object_identifier
{
   my ($this) = @_;
   my ($length, $subid_cnt, $subid, $byte) = (undef, 1, 0, undef);
   my (@oid);

   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   if ($length < 1) { 
      return $this->_asn1_decode_error(
         'OBJECT IDENTIFIER length equal to zero'
      );
   }

   while ($length > 0) {
      $subid = 0;
      do {
         if (!defined($byte = $this->_object_get_buffer(1))) {
            return $this->_asn1_decode_error;
         }   
         $byte = unpack('C', $byte);
         if ($subid >= 0xffffffff) {
            return $this->_asn1_decode_error(
               'OBJECT IDENTIFIER subidentifier too large'
            );
         }
         $subid = (($subid << 7) + ($byte & 0x7f)); 
         $length--;
      } while ($byte & 0x80);
      $oid[$subid_cnt++] = $subid;
   }

   # The first two subidentifiers are encoded into the first identifier
   # using the the equation: subid = ((first * 40) + second).

   $subid  = $oid[1];
   $oid[1] = int($subid % 40);
   $oid[0] = int(($subid - $oid[1]) / 40);

   # Return the OID in dotted notation (optionally with a leading dot
   # if one was passed to the encode routine).

   if ($this->{'_leading_dot'}) {
      $this->_debug_message("adding leading dot\n");
      '.' . join('.', @oid);
   } else {
      join('.', @oid);
   }
}

sub _asn1_decode_sequence
{
   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_ipaddress
{
   my ($this) = @_;
   my ($length, $address) = (undef, undef);

   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   if ($length != 4) {
      return $this->_asn1_decode_error(
         "Invalid IpAddress length (% byte%s)", 
         $length, ($length == 1 ? '' : 's')
      );
   }

   if (defined($address = $this->_object_get_buffer(4))) {
      join('.', unpack('C4', $address));
   } else {
      $this->_asn1_decode_error;
   }
}

sub _asn1_decode_counter
{
   $_[0]->_asn1_decode_integer32;
}

sub _asn1_decode_gauge
{
   $_[0]->_asn1_decode_integer32;
}

sub _asn1_decode_timeticks
{
   my ($this) = @_;
   my ($ticks) = (undef);

   if (defined($ticks = $this->_asn1_decode_integer32)) {
      if ($this->translate) {
         $this->_debug_message("translating %u TimeTicks to time\n", $ticks);
         return _asn1_ticks_to_time($ticks);
      } else {
         return $ticks;
      }
   } else {
      return $this->_asn1_decode_error;
   }
}

sub _asn1_decode_opaque
{
   $_[0]->_asn1_decode_octet_string;
}

sub _asn1_decode_counter64
{
   my ($this) = @_;
   my ($length, $byte, $negative) = (undef, undef, FALSE);

   # Verify the SNMP version
   if ($this->version != SNMP_VERSION_2C) {
      return $this->_asn1_decode_error(
         'Counter64 only supported with SNMPv2c'
      );
   }

   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   # Just return zero if the object length is zero
   if ($length < 1) { return '0'; }

   if (!defined($byte = $this->_object_get_buffer(1))) {
      return $this->_asn1_decode_error;
   }
   $length--;
   $byte = unpack('C', $byte);

   if (($length > 8) || (($length > 7) && ($byte != 0x00))) {
      return $this->_asn1_decode_error(
         "Counter64 length too long (%d bytes)", ($length + 1)
      );
   }

   # Only load the Math::BigInt module when needed
   use Math::BigInt;

   if ($byte & 0x80) { $negative = TRUE; }
   if ($negative) { $byte = $byte ^ 0xff; }

   my $c64 = Math::BigInt->new($byte);

   while ($length-- > 0) {
      if (!defined($byte = $this->_object_get_buffer(1))) {
         return $this->_asn1_decode_error;
      }
      $byte = unpack('C', $byte);
      if ($negative) { $byte = $byte ^ 0xff; }
      $c64 = $c64->bmul(256);
      $c64 = Math::BigInt->new($c64);
      $c64 = $c64->badd($byte);
      $c64 = Math::BigInt->new($c64);
   };

   # If the value is negative the other end incorrectly encoded  
   # the Counter64 since it should always be a positive value. 

   if ($negative) {
      $byte = Math::BigInt->new('-1');
      $c64 = $byte->bsub($c64);
   }

   # Remove the plus sign (or should we leave it to imply Math::BigInt?)
   $c64 =~ s/^\+//;

   $c64;
}

sub _asn1_decode_nosuchobject
{
   my ($this) = @_;
   my ($length) = (undef);

   if ($this->version != SNMP_VERSION_2C) {
      return $this->_asn1_decode_error(
         'noSuchObject only supported with SNMPv2c'
      );
   }
 
   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   if ($length != 0) {
      return $this->_asn1_decode_error('noSuchObject length not equal to zero');
   }

   if ($this->translate) {
      $this->_debug_message(
         "translating noSuchObject to 'noSuchObject' string"
      );
      'noSuchObject';
   } else {
      $this->{'_error_status'} = NOSUCHOBJECT;
      '';
   }
}

sub _asn1_decode_nosuchinstance
{
   my ($this) = @_;
   my ($length) = (undef);

   if ($this->version != SNMP_VERSION_2C) {
      return $this->_asn1_decode_error(
         'noSuchInstance only supported with SNMPv2c'
      );
   }

   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   if ($length != 0) {
      return $this->_asn1_decode_error(
         'noSuchInstance length not equal to zero'
      );
   }

   if ($this->translate) {
      $this->_debug_message(
         "translating noSuchInstance to 'noSuchInstance' string"
      );
      'noSuchInstance';
   } else {
      $this->{'_error_status'} = NOSUCHINSTANCE;
      '';
   }
}

sub _asn1_decode_endofmibview
{
   my ($this) = @_;
   my ($length) = (undef);

   if ($this->version != SNMP_VERSION_2C) {
      return $this->_asn1_decode_error(
         'endOfMibView only supported with SNMPv2c'
      );
   }

   if (!defined($length = $this->_asn1_decode_length)) {
      return $this->_asn1_decode_error;
   }

   if ($length != 0) {
      return $this->_asn1_decode_error('endOfMibView length not equal to zero');
   }

   if ($this->translate) {
      $this->_debug_message(
         "translating endOfMibView to 'endOfMibView' string"
      );
      'endOfMibView';
   } else {
      $this->{'_error_status'} = ENDOFMIBVIEW;
      '';
   }
}


sub _asn1_decode_get_request
{
   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_get_next_request
{
   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_get_reponse
{
   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_set_request
{
   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_trap
{
   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_get_bulk_request
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_decode_error(
         'GetBulkRequest-PDU only supported with SNMPv2c'
      );
   }

   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_inform_request
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_decode_error(
         'InformRequest-PDU only supported with SNMPv2c'
      );
   }

   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_v2_trap
{
   if ($_[0]->version != SNMP_VERSION_2C) {
      return $_[0]->_asn1_decode_error(
         'SNMPv2-Trap-PDU only supported with SNMPv2c'
      );
   }

   # Return the length, instead of the value
   $_[0]->_asn1_decode_length;
}

sub _asn1_decode_error
{
   my ($this, @error) = @_;

   $this->_object_error(@error);
}


###
## Abstract Syntax Notation One (ASN.1) utility functions 
###

sub _asn1_itoa 
{
   my ($type) = @_;

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
        SNMPV2_TRAP,        'SNMPv2-Trap-PDU' 
   };

   if (!defined($type)) { return '??'; }

   if (exists($types->{$type})) {
      $types->{$type};
   } else {
      sprintf("?? [0x%02x]", $type);
   }
}

sub _asn1_oid_subtree 
{
   my ($oid_p, $oid_c) = @_;
   my ($parent, $child) = (undef, undef);

   # Compares the parent OID (oid_p) to the child OID (oid_c)
   # and returns true if the child is equal to or is a subtree 
   # of the parent OID.
    
   if (!defined($oid_p)) { return FALSE; }
   if (!defined($oid_c)) { return FALSE; }

   # Remove leading dots
   $oid_p =~ s/^\.//;
   $oid_c =~ s/^\.//;

   my @subid_p = split(/\./, $oid_p);
   my @subid_c = split(/\./, $oid_c);

   while (@subid_p) {
      if (!defined($parent = shift(@subid_p))) { return TRUE; }
      if (!defined($child  = shift(@subid_c))) { return FALSE; }
      if ($parent != $child) { return FALSE; }
   }

   TRUE;
}

sub _asn1_ticks_to_time 
{
   my ($ticks) = @_;

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

###
## User Datagram Protocol (UDP) methods
###

sub _udp_send_message
{
   my ($this) = @_;
   my ($retries, $rout, $rin) = (0, '', '');

   # Make sure the socket is still open
   if (!defined($this->{'_socket'})) {
      return $this->_udp_error('Session is closed');
   }

   # Get the number of retries
   $retries = $this->{'_retries'};

   # Send the message
   if (!defined($this->_udp_send_buffer)) { return $this->_udp_error; }

   # Setup a vector to indicate received data on the socket
   vec($rin, fileno($this->{'_socket'}), 1) = 1;

   while ($retries > 0) {
      if (select($rout=$rin, undef, undef, $this->{'_timeout'})) {
         return $this->_udp_recv_buffer;
      } else {
         $retries--;
         $this->_debug_message("request timed out\n");
         if (!defined($this->_udp_send_buffer)) { return $this->_udp_error; }
      }
   }

   # Exceeded the number of retries
   $this->_udp_error(
      "No response from agent on remote host '%s'", $this->{'_hostname'} 
   );
}

sub _udp_send_buffer
{
   my ($this) = @_;
   my ($length, $host_port, $host_addr) = (0, undef, undef);

   # Make sure the socket is still open
   if (!defined($this->{'_socket'})) {
      return $this->_udp_error('Session is closed');
   }

   ($host_port, $host_addr) = sockaddr_in($this->{'_sockaddr'});
   $this->_debug_message(
      "address %s, port %d\n", inet_ntoa($host_addr), $host_port 
   );
   $this->_debug_dump_buffer;

   # Transmit the contents of the buffer
   if (!defined($length = send($this->{'_socket'}, $this->{'_buffer'}, 0,
                             $this->{'_sockaddr'})))
   {
      return $this->_udp_error("send(): %s", $!);
   }

   # Return the number of bytes transmitted
   $length;
}

sub _udp_recv_buffer
{
   my ($this) = @_;
   my ($sockaddr, $host_port, $host_addr) = (undef, undef, undef);

   # Make sure the socket is still open
   if (!defined($this->{'_socket'})) {
      return $this->_udp_error('Session is closed');
   }

   # Clear the contents of the buffer
   $this->_object_clear_buffer;

   # Fill the buffer
   if (!defined($sockaddr = recv($this->{'_socket'}, $this->{'_buffer'},
                               $this->{'_mtu'}, 0)))
   {
      return $this->_udp_error("recv(): %s", $!);
   }

   ($host_port, $host_addr) = sockaddr_in($sockaddr);

   # Make sure that the address that we received the data from was the
   # one that we sent the request to.  We just compare the bytes 
   # containing the port and address information since Windows NT seems
   # to fill the last eight bytes with random data and AIX returns a 
   # different PF_INET value in the resulting sockaddr_in structure.

   if (substr($sockaddr, 2, 6) ne substr($this->{'_sockaddr'}, 2, 6)) {
      $this->_debug_message("rcv = 0x%s\n", unpack('H*', $sockaddr));
      $this->_debug_message("snd = 0x%s\n", unpack('H*', $this->{'_sockaddr'}));
      if ($this->verify_ip) {
         return $this->_udp_error(
            "Received unexpected datagram from '%s'", inet_ntoa($host_addr)
         );
      }
   }

   $this->_debug_message(
      "address %s, port %d\n", inet_ntoa($host_addr), $host_port
   );
   $this->_debug_dump_buffer;

   # Return the address structure
   $sockaddr;
}

sub _udp_error
{
   my ($this, @error) = @_;

   $this->_object_error(@error);
}


###
## Object specific methods
###

sub _object_put_buffer
{
   my ($this, $prefix) = @_;

   # Do not do anything if there has already been an error
   if (defined($this->{'_error'})) { return $this->_object_encode_error; }

   # Make sure we do not exceed our MTU
   if (($this->_object_buffer_length + length($prefix)) > $this->{'_mtu'}) {
      return $this->_object_encode_error('PDU size exceeded MTU');
   }
 
   # Add the prefix to the current buffer
   if ((defined($prefix)) && ($prefix ne '')) {
      $this->{'_buffer'} = join('', $prefix, $this->{'_buffer'});
   } 

   # Return what was just added in case someone wants it
   $prefix;
}

sub _object_get_buffer
{
   my ($this, $offset) = @_;
   my ($substr) = ('');

   # Do not do anything if there has already been an error
   if (defined($this->{'_error'})) { return $this->_object_decode_error; }
  
   # Either return the whole buffer or a sub-string from the 
   # beginning of the buffer and then set the buffer equal to
   # what is left in the buffer
 
   if (defined($offset)) {
      $offset = abs($offset);
      if ($offset > length($this->{'_buffer'})) {
         return $this->_object_decode_error('Unexpected end of buffer');
      } else {
         $substr = substr($this->{'_buffer'}, 0, $offset);
         $this->{'_buffer'} = substr($this->{'_buffer'}, $offset);
      }
   } else {
      $substr = $this->{'_buffer'}; 
      $this->_object_clear_buffer;
   }

   $substr;
}

sub _object_clear_buffer
{
   $_[0]->{'_buffer'} = '';
}

sub _object_clear_var_bind_list
{
   $_[0]->{'_var_bind_list'} = undef;
}

sub _object_clear_error
{
   $_[0]->{'_error_status'} = 0;
   $_[0]->{'_error_index'}  = 0;
   $_[0]->{'_error'} = undef;
}

sub _object_clear_leading_dot
{
   $_[0]->{'_leading_dot'} = FALSE;
}

sub _object_buffer_length
{
   length $_[0]->{'_buffer'};
}

sub _object_encode_error
{
   my ($this, @error) = @_;

   # Clear the buffer
   $this->_object_clear_buffer;

   $this->_object_error(@error);
}

sub _object_decode_error
{
   my ($this, @error) = @_;

   $this->_object_error(@error);
}

sub _object_error
{
   my ($this, $format, @message) = @_;

   if (!defined($this->{'_error'})) {
      $this->{'_error'} = sprintf $format, @message;
      if ($this->debug) {
         my @info_1 = caller(1);
         my @info_2 = caller(2);
         printf("debug: [%d] %s(): %s\n", $info_1[2], $info_2[3], 
            $this->{'_error'}
         );
      }
   }

   undef;
}


###
## Debug methods
###

sub _debug_message
{
   my ($this, @message) = @_;

   if (!$this->debug) { return 0x0; }

   my @info_0 = caller(0);
   my @info_1 = caller(1);
   my $format = sprintf("debug: [%d] %s(): ", $info_0[2], $info_1[3]);

   $format = join('', $format, shift(@message));

   printf $format, @message;

   0x1;
}

sub _debug_dump_buffer
{
   my ($this) = @_;
   my ($length, $offset, $line, $hex) = (0, 0, '', '');

   if (!$this->debug) { return undef; }

   $length = length($this->{'_buffer'});

   $this->_debug_message("%d byte%s\n", $length, ($length == 1 ? '' : 's'));
  
   while ($length > 0) {
      if ($length >= 16) { 
         $line = substr($this->{'_buffer'}, $offset, 16);
      } else {
         $line = substr($this->{'_buffer'}, $offset, $length);
      }
      $hex  = unpack('H*', $line);
      $hex .= ' ' x (32 - length($hex));
      $hex  = sprintf("%s %s %s %s  " x 4, unpack('a2' x 16, $hex));
      $line =~ s/[\x00-\x1f\x7f-\xff]/./g;
      printf("[%03d]  %s %s\n", $offset, uc($hex), $line);
      $offset += 16;
      $length -= 16;
   }
   print("\n");
   
   $this->{'_buffer'};
}

# ============================================================================
1; # [end Net::SNMP]

__DATA__

###
## POD formatted documentation for Perl module Net::SNMP.
##
## $Id: Net-SNMP.pod,v 2.0 1999/05/06 16:03:49 dtown Exp $
## $Source: /home/dtown/Projects/Net-SNMP/Net-SNMP.pod,v $
##
###

=head1 NAME

Net::SNMP - Simple Network Management Protocol

=head1 SYNOPSIS

use Net::SNMP;

=head1 DESCRIPTION

The module Net::SNMP implements an object oriented interface to the Simple 
Network Management Protocol.  Perl applications can use the module to 
retrieve or update information on a remote host using the SNMP protocol.
Net::SNMP is implemented completely in Perl, requires no compiling, and 
uses only standard Perl modules.  Both SNMPv1 and SNMPv2c (Community-Based
SNMPv2) are supported by the module.  The Net::SNMP module assumes that the 
user has a basic understanding of the Simple Network Management Protocol and
related network management concepts. 

=head1 METHODS

When named arguments are used with methods, two different styles are
supported.  All examples use the IO:: style:

   $object->method(Argument => $value);

However, the dashed-option style is also allowed:

   $object->method(-argument => $value);


=head2 session() - create a new Net::SNMP object

   ($session, $error) = Net::SNMP->session(
                                      [Hostname  => $hostname,]
                                      [Community => $community,]
                                      [Port      => $port,]
                                      [Version   => $version,]
                                      [Timeout   => $seconds,]
                                      [Retries   => $count,]
                                      [MTU       => $octets,]
                                      [Translate => $translate,]
                                      [VerifyIP  => $verifyip,]
                                      [Debug     => $debug]
                                   );

This is the constructor for Net::SNMP objects. In scalar context, a
reference to a new Net::SNMP object is returned if the creation of the object
is successful.  In list context, a reference to a new Net::SNMP object and an 
error message string is returned.  

If an error occurs, the object reference returns the undefined value.
The error string may be used when this method is used in list context to
determine the cause of the error.

The B<Hostname>, B<Community>, and B<Port> arguments are basic properties
of a Net::SNMP object and cannot be changed after the object is created.
All other arguments have methods that allow their values to be modified after
the Net::SNMP object has been created.  See the methods corresponding to  
these named arguments for their valid ranges and default values.

All arguments are optional and will take default values in the absence of a
corresponding named argument. 

=over  

=item *

The default value for the remote B<Hostname> is "localhost".  The hostname 
can either be a network hostname or the dotted IP address of the host. 

=item *

The default value for the SNMP B<Community> name is "public".

=item *

The default value for the destination UDP B<Port> number is 161.  This is 
the port on which hosts using default values expect to receive all SNMP 
messages except for traps.  Port number 162 is the default port used by hosts 
expecting to receive SNMP traps.

=back

=head2 close() - close the UDP socket and clear all buffers and errors 

   $session->close;

This method closes the UDP socket and clears the errors, hash pointers, and 
buffers associated with the object.

=head2 get_request() - send a SNMP get-request to the remote agent

   $response = $session->get_request(@oids);

This method performs a SNMP get-request query to gather data from the remote
agent on the host associated with the Net::SNMP object.  The method takes
a list of OBJECT IDENTIFIERs in dotted notation.  Each OBJECT IDENTIFER is
placed into a single SNMP GetRequest-PDU in the same order that it held in
the original list.

Upon success, a reference to a hash is returned which contains the results of
the query. The undefined value is returned when a failure has occurred.  The
C<error()> method can be used to determine the cause of the failure.

The returned reference points to a hash constructed from the VarBindList
contained in the SNMP GetResponse-PDU.  The hash is created using the
ObjectName and the ObjectSyntax pairs in the VarBindList.  The keys of the
hash consist of the OBJECT IDENTIFIERs in dotted notation corresponding to
each ObjectName in the list.  If any of the passed OBJECT IDENTIFIERs began
with a leading dot, all of the OBJECT IDENTIFIER hash keys will be prefixed
with a leading dot.  The value of each hash entry is set to be the value of
the associated ObjectSyntax.  The hash reference can also be retrieved using 
the C<var_bind_list()> method.

=head2 get_next_request() - send a SNMP get-next-request to the remote agent

   $response = $session->get_next_request(@oids);

This method performs a SNMP get-next-request query to gather data from the
remote agent on the host associated with the Net::SNMP object.  The method
takes a list of OBJECT IDENTIFIERs in dotted notation.  Each OBJECT IDENTIFER
is placed into a single SNMP GetNextRequest-PDU in the same order that it
held in the original list.

Upon success, a reference to a hash is returned which contains the results of
the query. The undefined value is returned when a failure has occurred.  The
C<error()> method can be used to determine the cause of the failure.

The returned reference points to a hash constructed from the VarBindList
contained in the SNMP GetResponse-PDU.  The hash is created using the
ObjectName and the ObjectSyntax pairs in the VarBindList.  The keys of the
hash consist of the OBJECT IDENTIFIERs in dotted notation corresponding to
each ObjectName in the list.  If any of the passed OBJECT IDENTIFIERs began
with a leading dot, all of the OBJECT IDENTIFIER hash keys will be prefixed
with a leading dot.  The value of each hash entry is set to be the value of
the associated ObjectSyntax.  The hash reference can also be retrieved using
the C<var_bind_list()> method.

=head2 set_request() - send a SNMP set-request to the remote agent

   $response = $session->set_request(
                            $oid, $type, $value 
                            [, $oid, $type, $value]
                         );

This method is used to modify data on the remote agent that is associated
with the Net::SNMP object using a SNMP set-request.  The method takes a
list of values consisting of groups of an OBJECT IDENTIFIER, an object type, 
and the actual value to be set.  The OBJECT IDENTIFIERs in each trio are to
be in dotted notation.  The object type is a byte corresponding to the ASN.1
type of value that is to be set.  Each of the supported types have been
defined and are exported by the package by default (see L<"EXPORTS">).

Upon success, a reference to a hash is returned which contains the results of
the query. The undefined value is returned when a failure has occurred.  The
C<error()> method can be used to determine the cause of the failure.

The returned reference points to a hash constructed from the VarBindList
contained in the SNMP GetResponse-PDU.  The hash is created using the
ObjectName and the ObjectSyntax pairs in the VarBindList.  The keys of the
hash consist of the OBJECT IDENTIFIERs in dotted notation corresponding to
each ObjectName in the list.  If any of the passed OBJECT IDENTIFIERs began
with a leading dot, all of the OBJECT IDENTIFIER hash keys will be prefixed
with a leading dot.  The value of each hash entry is set to be the value of
the associated ObjectSyntax.  The hash reference can also be retrieved using
the C<var_bind_list()> method.

=head2 trap() - send an SNMP trap to the remote manager

   $octets = $session->trap(
                          [Enterprise   => $oid,]
                          [AgentAddr    => $ipaddress,]
                          [GenericTrap  => $generic,]
                          [SpecificTrap => $specific,]
                          [TimeStamp    => $timeticks,]
                          [VarBindList  => \@oids,]
                       );

This method sends an SNMP trap to the remote manager associated with the
Net::SNMP object.  All arguments are optional and will be given the following 
defaults in the absence of a corresponding named argument: 

=over 

=item *

The default value for the trap B<Enterprise> is "1.3.6.1.4.1", which 
corresponds to "iso.org.dod.internet.private.enterprises".  The enterprise 
value is expected to be an OBJECT IDENTIFER in dotted notation. 

=item *

The default value for the trap B<AgentAddr> is the local IP address from
the host on which the script is running.  The agent-addr is expected to
be an IpAddress in dotted notation.

=item *

The default value for the B<GenericTrap> type is 6 which corresponds to 
"enterpriseSpecific".  The generic-trap types are defined and can be exported
upon request (see L<"EXPORTS">).

=item *

The default value for the B<SpecificTrap> type is 0.  No pre-defined values
are available for specific-trap types.

=item *

The default value for the trap B<TimeStamp> is the "uptime" of the script.  The
"uptime" of the script is the number of hundredths of seconds that have elapsed
since the script started running.  The time-stamp is expected to be a TimeTicks
number in hundredths of seconds.

=item *

The default value for the trap B<VarBindList> is an empty array reference.
The variable-bindings are expected to be in an array format consisting of 
groups of an OBJECT IDENTIFIER, an object type, and the actual value of the 
object.  This is identical to the list expected by the C<set_request()> method.
The OBJECT IDENTIFIERs in each trio are to be in dotted notation.  The object 
type is a byte corresponding to the ASN.1 type for the value. Each of the 
supported types have been defined and are exported by default (see 
L<"EXPORTS">).

=back

Upon success, the number of bytes transmitted is returned.  The undefined value
is returned when a failure has occurred.  The C<error()> method can be used to 
determine the cause of the failure.  Since there are no acknowledgements for
Trap-PDUs, there is no way to determine if the remote host actually received 
the trap.

=head2 get_bulk_request() - send a SNMPv2 get-bulk-request to the remote agent

   $response = $session->get_bulk_request(
                            [NonRepeaters   => $nonrepeaters,]
                            [MaxRepetitions => $maxrepetitions,]
                            [VarBindList    => \@oids,]
                         );

This method performs a SNMP get-bulk-request query to gather data from the
remote agent on the host associated with the Net::SNMP object.  All arguments 
are optional and will be given the following defaults in the absence of a 
corresponding named argument: 

=over 

=item *

The default value for the get-bulk-request B<NonRepeaters> is 0.  The 
non-repeaters value specifies the number of variables in the 
variable-bindings list for which a single successor is to be returned.

=item *

The default value for the get-bulk-request B<MaxRepetitions> is 0. The
max-repetitions value specifies the number of successors to be returned for
the remaining variables in the variable-bindings list.

=item *

The default value for the get-bulk-request B<VarBindList> is an empty array
reference.  The variable-bindings are expected to be in an array format 
consisting of groups of an OBJECT IDENTIFIER, an object type, and the actual
value of the object.  This is identical to the list expected by the 
C<set_request()> method.  The OBJECT IDENTIFIERs in each trio are to be in 
dotted notation.  The object type is a byte corresponding to the ASN.1 type 
for the value that is identified.  Each of the supported types have been 
defined and are exported by default (see L<"EXPORTS">).

=back

Upon success, a reference to a hash is returned which contains the results of
the query. The undefined value is returned when a failure has occurred.  The
C<error()> method can be used to determine the cause of the failure.

The returned reference points to a hash constructed from the VarBindList
contained in the SNMP GetResponse-PDU.  The hash is created using the
ObjectName and the ObjectSyntax pairs in the VarBindList.  The keys of the
hash consist of the OBJECT IDENTIFIERs in dotted notation corresponding to
each ObjectName in the list.  If any of the passed OBJECT IDENTIFIERs began
with a leading dot, all of the OBJECT IDENTIFIER hash keys will be prefixed
with a leading dot.  The value of each hash entry is set to be the value of
the associated ObjectSyntax.  The hash reference can also be retrieved using
the C<var_bind_list()> method.

B<NOTE:> This method can only be used when the version of the object is set to
SNMPv2c.

=head2 inform_request() - send a SNMPv2 inform-request to the remote manager

   $response = $session->inform_request(
                            $oid, $type, $value 
                            [, $oid, $type, $value]
                         );

This method is used to provide management information to the remote manager
associated with the Net::SNMP object using a SNMPv2 inform-request.  The 
method takes a list of values consisting of groups of an OBJECT IDENTIFIER,
an object type, and the actual value to be set.  The OBJECT IDENTIFIERs in 
each trio are to be in dotted notation.  The object type is a byte 
corresponding to the ASN.1 type of value that is identified. Each of the
supported types have been defined and are exported by the package by default
(see L<"EXPORTS">).

The first two variable-bindings fields in the inform-request are specified
by SNMPv2 and should be:

=over

=item *

sysUpTime.0 - ['1.3.6.1.2.1.1.3.0', TIMETICKS, $timeticks] 

=item *

snmpTrapOID.0 - ['1.3.6.1.6.3.1.1.4.1.0', OBJECT_IDENTIFIER, $oid]

=back

Upon success, a reference to a hash is returned which contains the results of
the query. The undefined value is returned when a failure has occurred.  The
C<error()> method can be used to determine the cause of the failure.

The returned reference points to a hash constructed from the VarBindList
contained in the SNMP GetResponse-PDU.  The hash is created using the
ObjectName and the ObjectSyntax pairs in the VarBindList.  The keys of the
hash consist of the OBJECT IDENTIFIERs in dotted notation corresponding to
each ObjectName in the list.  If any of the passed OBJECT IDENTIFIERs began
with a leading dot, all of the OBJECT IDENTIFIER hash keys will be prefixed
with a leading dot.  The value of each hash entry is set to be the value of
the associated ObjectSyntax.  The hash reference can also be retrieved using
the C<var_bind_list()> method.

B<NOTE:> This method can only be used when the version of the object is set to
SNMPv2c.

=head2 snmpv2_trap() - send a SNMPv2 snmpV2-trap to the remote manager

   $octets = $session->snmpv2_trap(
                          $oid, $type, $value 
                          [, $oid, $type, $value]
                       );

This method sends an SNMPv2 snmpV2-trap to the remote manager associated with 
the Net::SNMP object.  The method takes a list of values consisting of groups
of an OBJECT IDENTIFIER, an object type, and the actual value to be set. The
OBJECT IDENTIFIERs in each trio are to be in dotted notation.  The object type
is a byte corresponding to the ASN.1 type of value that is being identified. 
Each of the supported types have been defined and are exported by the package
by default (see L<"EXPORTS">).

The first two variable-bindings fields in the snmpV2-trap are specified by
SNMPv2 and should be:

=over

=item *

sysUpTime.0 - ['1.3.6.1.2.1.1.3.0', TIMETICKS, $timeticks]

=item *

snmpTrapOID.0 - ['1.3.6.1.6.3.1.1.4.1.0', OBJECT_IDENTIFIER, $oid]

=back

Upon success, the number of bytes transmitted is returned.  The undefined value
is returned when a failure has occurred.  The C<error()> method can be used to
determine the cause of the failure.  Since there are no acknowledgements for
SNMPv2-Trap-PDUs, there is no way to determine if the remote host actually 
received the snmpV2-trap.

B<NOTE:> This method can only be used when the version of the object is set to
SNMPv2c.

=head2 get_table() - retrieve a table from the remote agent

   $response = $session->get_table($oid);

This method performs repeated SNMP get-next-request queries to gather data 
from the remote agent on the host associated with the Net::SNMP object.
The method takes a single OBJECT IDENTIFIER.  This OBJECT IDENTIFIER is used
as the base object for the SNMP get-next-requests.  Repeated SNMP 
get-next-requests are issued until the OBJECT IDENTIFER in the response is no 
longer a subtree of the base OBJECT IDENTIFIER.

Upon success, a reference to a hash is returned which contains the results of
the query. The undefined value is returned when a failure has occurred.  The
C<error()> method can be used to determine the cause of the failure.

The returned reference points to a hash constructed from the VarBindList
contained in the SNMP GetResponse-PDU.  The hash is created using the
ObjectName and the ObjectSyntax pairs in the VarBindList.  The keys of the
hash consist of the OBJECT IDENTIFIERs in dotted notation corresponding to
each ObjectName in the list.  If any of the passed OBJECT IDENTIFIERs began
with a leading dot, all of the OBJECT IDENTIFIER hash keys will be prefixed
with a leading dot.  The value of each hash entry is set to be the value of
the associated ObjectSyntax.  The hash reference can also be retrieved using
the C<var_bind_list()> method.

B<WARNING:> Results from this method can become very large if the base
OBJECT IDENTIFIER is close the root of the SNMP MIB tree.

=head2 version() - set or get the SNMP version for the object

This method is used to set or get the current SNMP version associated with
the Net::SNMP object.  The module supports SNMP version-1 (SNMPv1) and SNMP 
version-2c (SNMPv2c).  The default version used by the module is SNMP 
version-1.

The method accepts the digit '1' or the string 'SNMPv1' for SNMP version-1 and
the digit '2', or the strings '2c', 'SNMPv2', or 'SNMPv2' for SNMP version-2c.
The undefined value is returned upon an error and the C<error()> method may 
be used to determine the cause.

The method returns the current value for the SNMP version.  The returned value
is the corresponding version number defined by the RFCs for the protocol 
version field (i.e. SNMPv1 == 0 and SNMPv2c == 1).

=head2 error() - get the current error message from the object

   $error_message = $session->error;

This method returns a text string explaining the reason for the last error.
A null string is returned if no error has occurred.

=head2 error_status() - get the current SNMP error-status from the object

   $error_status = $session->error_status;

This method returns the numeric value of the error-status contained in the 
last SNMP GetResponse-PDU.

=head2 error_index() - get the current SNMP error-index from the object

   $error_index = $session->error_index;

This method returns the numeric value of the error-index contained in the 
last SNMP GetResponse-PDU.

=head2 var_bind_list() - get the hash reference to the last SNMP response

   $response = $session->var_bind_list;

This method returns a reference to the hash returned from the query or set 
methods.  The undefined value is returned if this value is empty.

=head2 timeout() - set or get the current timeout period for the object 

   $seconds = $session->timeout([$seconds]);

This method returns the current value for the UDP timeout for the Net::SNMP
object.  This value is the number of seconds that the object will wait for a
response from the agent on the remote host.  The default timeout is 2.0
seconds.

If a parameter is specified, the timeout for the object is set to the provided
value if it falls within the range 1.0 to 60.0 seconds.  The undefined value
is returned upon an error and the C<error()> method may be used to determine
the cause.

=head2 retries() - set or get the current retry count for the object

   $count = $session->retries([$count]);

This method returns the current value for the number of times to retry
sending a SNMP message to the remote host.  The default number of retries
is 2.

If a parameter is specified, the number of retries for the object is set to
the provided value if it falls within the range 0 to 20. The undefined value
is returned upon an error and the C<error()> method may be used to determine 
the cause.

=head2 mtu() - set or get the current MTU for the object

   $octets = $session->mtu([$octets]);

This method returns the current value for the Maximum Transport Unit for the
Net::SNMP object.  This value is the largest value in octets for an SNMP
message that can be transmitted or received by the object.  The default
MTU is 484 octets.

If a parameter is specified, the Maximum Transport Unit is set to the provided
value if it falls within the range 30 to 65535 octets.  The undefined value
is returned upon an error and the C<error()> method may be used to determine
the cause.

=head2 translate() - enable or disable the translation mode for the object

   $mode = $session->translate([$mode]);

When the object decodes the GetResponse-PDU that is returned in response to
a SNMP message, certain values are translated into a more "human readable"
form.  By default the following translations occur: 

=over 

=item *

OCTET STRINGs containing non-printable characters are converted into a 
hexadecimal representation prefixed with "0x".

=item *

TimeTicks integer values are converted to a time format.

=item *

NULL values return the string "NULL" instead of an empty string.

=item *

noSuchObject exception values return the string "noSuchObject" instead of an
empty string.  If translation is not enabled, the SNMP error-status field
is set to 128 which is equal to the exported definition NOSUCHOBJECT (see 
L<"EXPORTS">).

=item *

noSuchInstance exception values return the string "noSuchInstance" instead of 
an empty string.  If translation is not enabled, the SNMP error-status field
is set to 129 which is equal to the exported definition NOSUCHINSTANCE (see 
L<"EXPORTS">).

=item *

endOfMibView exception values return the string "endOfMibView" instead of an
empty string.  If translation is not enabled, the SNMP error-status field
is set to 130 which is equal to the exported definition ENDOFMIBVIEW (see 
L<"EXPORTS">).

=back

If a parameter is specified, the translation mode is set to either enabled
or disabled depending on the value of the passed parameter.  Any value that
Perl would treat as a true value will set the mode to be enabled, while a
false value will disable translation.  The current state of the translation 
mode is returned by the method.

=head2 verify_ip() - enable or disable IP verification for the object

   $mode = $session->verify_ip([$mode]);

When the object receives an UDP packet, the IP address and UDP port with which
the object was created are compared to the values in the received packet.
By default, if these values do not match, the UDP packet is ignored and an 
error message is returned.  This check is to insure that the data the object 
has just received is from the host to which the message was sent. However this 
can cause problems with multi-homed hosts which respond from a different 
interface than the one to which the message was sent.

This method is used to enable or disable IP verification on a per object basis.
By default, IP address and port verification is enabled.  If a parameter is 
specified, the verification mode is set to either enabled or disabled depending
on the value of the passed parameter.  Any value that Perl would treat as a
true value will set the mode to be enabled, while a false value will disable IP
verification.  The current state of the IP verification mode is returned by the 
method.

=head2 debug() - set or get the debug mode for the object

   $mode = $session->debug([$mode]);

This method is used to enable or disable debugging on a per object basis.  By
default, debugging is off.  If a parameter is specified, the debug mode is set
to either enabled or disabled depending on the value of the passed parameter. 
Any value that Perl would treat as a true value will set the mode to be 
enabled, while a false value will disable debugging.  The current state of the 
debugging mode is returned by the method.

=head1 EXPORTS

=over

=item Default

INTEGER, INTEGER32, OCTET_STRING, NULL, OBJECT_IDENTIFIER, IPADDRESS, COUNTER,
COUNTER32, GAUGE, GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, COUNTER64, 
NOSUCHOBJECT, NOSUCHINSTANCE, ENDOFMIBVIEW

=item Exportable

INTEGER, INTEGER32, OCTET_STRING, NULL, OBJECT_IDENTIFIER, IPADDRESS, COUNTER, 
COUNTER32, GAUGE, GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, COUNTER64,
NOSUCHOBJECT, NOSUCHINSTANCE, ENDOFMIBVIEW, COLD_START, WARM_START, LINK_DOWN, 
LINK_UP, AUTHENTICATION_FAILURE, EGP_NEIGHBOR_LOSS, ENTERPRISE_SPECIFIC

=item Tags

=over 

=item :asn1

INTEGER, INTEGER32, OCTET_STRING, NULL, OBJECT_IDENTIFIER, IPADDRESS, COUNTER,
COUNTER32, GAUGE, GAUGE32, UNSIGNED32, TIMETICKS, OPAQUE, COUNTER64, 
NOSUCHOBJECT, NOSUCHINSTANCE, ENDOFMIBVIEW

=item :generictrap

COLD_START, WARM_START, LINK_DOWN, LINK_UP, AUTHENTICATION_FAILURE,
EGP_NEIGHBOR_LOSS, ENTERPRISE_SPECIFIC

=item :ALL

All of the above exportable items.

=back

=back

=head1 EXAMPLES

This example gets the system uptime from a remote host:


   #!/bin/env perl

   use Net::SNMP;

   $hostname  = shift || 'localhost';
   $community = shift || 'public';
   $port      = shift || 161;

   ($session, $error) = Net::SNMP->session(
                                      Hostname  => $hostname,
                                      Community => $community,
                                      Port      => $port
                                   );

   if (!defined($session)) {
      printf("ERROR: %s\n", $error);
      exit 1;
   }

   $sysUpTime = '1.3.6.1.2.1.1.3.0';

   if (!defined($response = $session->get_request($sysUpTime))) {
      printf("ERROR: %s\n", $session->error);
      $session->close;
      exit 1;
   }

   printf("sysUpTime for host '%s' is %s\n", $hostname, 
      $response->{$sysUpTime}
   );

   $session->close;

   exit 0;

This example sets the system contact information to "Help Desk":

   #!/bin/env perl

   use Net::SNMP;

   $hostname  = shift || 'localhost';
   $community = shift || 'private';
   $port      = shift || 161;

   ($session, $error) = Net::SNMP->session(
                                      Hostname  => $hostname,
                                      Community => $community,
                                      Port      => $port
                                   );

   if (!defined($session)) {
      printf("ERROR: %s\n", $error);
      exit 1;
   }

   $sysContact = '1.3.6.1.2.1.1.4.0';
   $contact    = 'Help Desk';

   $response = $session->set_request($sysContact, OCTET_STRING, $contact);
 
   if (!defined($response)) { 
      printf("ERROR: %s\n", $session->error);
      $session->close;
      exit 1;
   }


   printf("sysContact for host '%s' set to '%s'\n", $hostname, 
      $response->{$sysContact}
   );

   $session->close;

   exit 0; 


=head1 AUTHOR

David M. Town <dtown@fore.com>

=head1 ACKNOWLEDGMENTS

The original concept for this module was based on F<SNMP_Session.pm> written 
by Simon Leinen <simon@switch.ch>.

The Abstract Syntax Notation One (ASN.1) encode and decode methods were 
derived by example from the CMU SNMP package whose copyright follows: 
Copyright (c) 1988, 1989, 1991, 1992 by Carnegie Mellon University.  
All rights reserved. 

=head1 COPYRIGHT

Copyright (c) 1998-1999 David M. Town.  All rights reserved.  This program 
is free software; you may redistribute it and/or modify it under the same
terms as Perl itself.

