# -*- mode: perl -*-
# ============================================================================

# $Id: require.t,v 2.2 2000/09/09 14:29:28 dtown Exp $
# $Source: /us/dtown/Projects/Net-SNMP/require.t,v $

# Required module test for Perl module Net::SNMP.

# Copyright (c) 1999-2000 David M. Town <david.town@marconi.com>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

BEGIN { $|=1; $^W=1; }

use strict;
use Test;

BEGIN { plan tests => 5 };

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

# Math::BigInt.pm
eval { require Math::BigInt; };
ok($@, '', 'Required module Math::BigInt missing');

# ============================================================================
