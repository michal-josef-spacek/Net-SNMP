# -*- mode: perl -*-
# ============================================================================

# $Id: Makefile.PL,v 1.4 2000/01/01 17:54:38 dtown Exp $
# $Source: /us/dtown/Projects/Net-SNMP/Makefile.PL,v $

# Makefile for Perl module Net::SNMP.

# Copyright (c) 1998-2000 David M. Town <dtown@fore.com>.
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

