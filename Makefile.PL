# -*- mode: perl -*-
# ============================================================================

# $Id: Makefile.PL,v 1.2 1998/11/06 14:00:56 dtown Exp $
# $Source: /home/dtown/Projects/Net-SNMP/Makefile.PL,v $

# Makefile for Perl module Net::SNMP.

# Copyright (c) 1998 David M. Town <dtown@fore.com>.
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

