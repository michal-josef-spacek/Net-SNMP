# -*- mode: perl -*-
# ============================================================================

# $Id: Makefile.PL,v 1.3 1999/03/17 13:23:27 dtown Exp $
# $Source: /us/dtown/Projects/Net-SNMP/Makefile.PL,v $

# Makefile for Perl module Net::SNMP.

# Copyright (c) 1998-1999 David M. Town <dtown@fore.com>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use ExtUtils::MakeMaker qw(WriteMakefile);

WriteMakefile(
   NAME         => 'Net::SNMP',
   DISTNAME     => 'Net-SNMP',
   VERSION_FROM => 'lib/Net/SNMP.pm',
   dist         => { COMPRESS => 'gzip', SUFFIX => 'gz' },
);

exit 0;

# ============================================================================

