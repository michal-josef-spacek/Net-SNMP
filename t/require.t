# ============================================================================

# $Id: require.t,v 1.0 1999/04/26 13:16:14 dtown Exp $
# $Source: /home/dtown/Projects/Net-SNMP/require.t,v $

# Required module test for Perl module Net::SNMP.

# Copyright (c) 1999 David M. Town <dtown@fore.com>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

BEGIN { $|=1; $^W=1; }

use strict;
use Test;

BEGIN { plan tests => 4 };

# Exporter.pm
eval { require Exporter; };
ok($@, '', 'Required module Exporter missing');

# Socket.pm
eval { require Socket; };
ok($@, '', 'Required module Socket missing');

# Symbol.pm
eval { require Symbol; };
ok($@, '', 'Required module Symbol missing');

# Sys::Hostname.pm
eval { require Sys::Hostname; };
ok($@, '', 'Required module Sys::Hostname missing');

# ============================================================================
