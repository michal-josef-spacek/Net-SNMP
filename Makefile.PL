# -*- mode: perl -*-
# ============================================================================

# $Id: Makefile.PL,v 1.1 1998/10/14 12:24:43 dtown Exp $
# $Source: /home/dtown/Projects/Net-SNMP/Makefile.PL,v $

# Makefile for Perl module Net::SNMP.

# Copyright (c) 1998 David M. Town <town+@pitt.edu>.
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

