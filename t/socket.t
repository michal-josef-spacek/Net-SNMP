# ============================================================================

# $Id: socket.t,v 1.0 1999/04/26 13:16:48 dtown Exp $
# $Source: /home/dtown/Projects/Net-SNMP/socket.t,v $

# Socket test for Perl module Net::SNMP.

# Copyright (c) 1999 David M. Town <dtown@fore.com>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

BEGIN { $|=1; $^W=1; }

use strict;
use Test;

BEGIN { plan tests => 3 };

my $r;

# Load the socket module
use Socket qw(PF_INET SOCK_DGRAM); 

# Create a UDP socket
ok(socket(S, PF_INET, SOCK_DGRAM, 0), 1, "Failed to create a socket: $!");

# Check for input on socket - it should return 0.
vec($r='', fileno(S), 1) = 1;
ok(select($r, '', '', 0), 0, "Failed select(): $!");

# Close the socket
ok(close(S), 1, "Failed to close the socket: $!");

# ============================================================================
