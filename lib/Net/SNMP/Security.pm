# -*- mode: perl -*-
# ============================================================================

package Net::SNMP::Security;

# $Id: Security.pm,v 1.2 2001/11/09 14:03:52 dtown Exp $

# Base object that implements the Net::SNMP Security Models.

# Copyright (c) 2001 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Net::SNMP::Message qw(:versions TRUE FALSE);

## Version of the Net::SNMP::Security module

our $VERSION = v1.0.0;

## Package variables

our $DEBUG = FALSE;  # Debug flag

our $AUTOLOAD;       # Used by the AUTOLOAD method

our $NO_V3_SUPPORT;  # String to indicate SNMPv3 support

sub BEGIN 
{
   # We load the two modules for the two Security Models that we currently
   # support.  The Net::SNMP::Security::USM module requires four non-core
   # modules.  If any of these modules are not available, we still load
   # the Secruity module, but disable SNMPv3 support.

   require Net::SNMP::Security::Community;

   if (!eval('require Net::SNMP::Security::USM')) {
      $NO_V3_SUPPORT = 'SNMPv3 support unavailable';
      if ($@ =~ /(\S+\.pm)/) {
         $NO_V3_SUPPORT .= sprintf(' (Required module %s not found)', $1);
      } else {
         $NO_V3_SUPPORT .= sprint(' (%s)', $@);
      } 
   }
}

# [public methods] -----------------------------------------------------------

sub new 
{
   my ($class, %argv) = @_;

   my $version = SNMP_VERSION_1;

   # See if a SNMP version has been passed
   foreach (keys %argv) {
      if (/^-?version$/i) {
         if (($argv{$_} == SNMP_VERSION_1)  ||
             ($argv{$_} == SNMP_VERSION_2C) ||
             ($argv{$_} == SNMP_VERSION_3))
         {
            $version = $argv{$_};
         }
      }
   }

   if ($version == SNMP_VERSION_3) {
      if (!defined($NO_V3_SUPPORT)) {
         Net::SNMP::Security::USM->new(%argv);
      } else {
         wantarray ? (undef, $NO_V3_SUPPORT) : undef;
      }
   } else {
      Net::SNMP::Security::Community->new(%argv);
   }
}

sub version
{
   if (@_ == 2) {
      $_[0]->_error_clear;
      return $_[0]->_error('SNMP version is not modifiable');
   }

   $_[0]->{_version};
}

sub discovered
{
   TRUE; # Always true
}

sub security_model
{
   $_[0]->{_version};
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

sub error
{
   $_[0]->{_error} || '';
}

sub AUTOLOAD
{
   return if $AUTOLOAD =~ /::DESTROY$/;

   $AUTOLOAD =~ s/.*://;

   $_[0]->_error(
     'Feature not supported by this Security Model [%s]', $AUTOLOAD
   );
}

# [private methods] ----------------------------------------------------------

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

# ============================================================================
1; # [end Net::SNMP::Security]

