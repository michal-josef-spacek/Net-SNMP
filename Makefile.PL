# -*- mode: perl -*-
# ============================================================================

# $Id: Makefile.PL,v 4.6 2003/09/09 12:44:54 dtown Exp $

# Makefile for the Perl module Net::SNMP.

# Copyright (c) 1998-2003 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

eval { require 5.6.0 } or die <<'EOD'; 

 This version of Net::SNMP uses syntax that is not supported 
 in versions of Perl earlier than v5.6.0.

 Unable to install Net::SNMP with the current version of Perl.

EOD

use ExtUtils::MakeMaker qw(WriteMakefile);

WriteMakefile(
   AUTHOR        => 'David M. Town <dtown@cpan.org>',
   ABSTRACT      => 'Object oriented interface to SNMP',
   NAME          => 'Net::SNMP',
   DISTNAME      => 'Net-SNMP',
   VERSION       => '4.1.1',
#  VERSION_FROM  => 'lib/Net/SNMP.pm', # Does not handle v-strings properly
   EXE_FILES	 => ['snmpkey'],
   PL_FILES      => {'snmpkey.PL' => 'snmpkey'},
   PREREQ_PM     => {
      Crypt::DES   => '2.03',
      Digest::MD5  => '2.11',
      Digest::SHA1 => '1.02',
      Digest::HMAC => '1.00'
   },   
   dist          => { 
      CI       => 'ci -u -m\"Changes for v$(VERSION)\"',
      COMPRESS => 'gzip --best', 
      SUFFIX   => 'gz' 
   },
);

exit 0;

# ============================================================================

