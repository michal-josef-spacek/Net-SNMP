# -*- mode: perl -*-
# ============================================================================

# $Id: Makefile.PL,v 2.0 2000/05/06 04:16:30 dtown Exp $
# $Source: /us/dtown/Projects/Net-SNMP/Makefile.PL,v $

# Makefile for Perl module Net::SNMP.

# Copyright (c) 1998-2000 David M. Town <dtown@fore.com>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use ExtUtils::MakeMaker qw(WriteMakefile);

WriteMakefile(
   NAME          => 'Net::SNMP',
   DISTNAME      => 'Net-SNMP',
   VERSION_FROM  => 'lib/Net/SNMP.pm',
   dist          => { COMPRESS => 'gzip', SUFFIX => 'gz' },
   ($] ge '5.005') ? (
      'AUTHOR'   => 'David M. Town <dtown@fore.com>',
      'ABSTRACT' => 'Object oriented interface to SNMP',
   ) : (),
);

exit 0;

# ============================================================================

