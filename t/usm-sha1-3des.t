# -*- mode: perl -*- 
# ============================================================================

# Test of the SNMPv3 User-based Security Model. 

# Copyright (c) 2001-2009 David M. Town <dtown@cpan.org>.
# Copyright (c) 2024 Michal Josef Špaček <skim@cpan.org>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as the Perl 5 programming language system itself.

# ============================================================================

use strict;
use Test;

BEGIN
{
   $|  = 1;
   $^W = 1;
   plan tests => 7
}

use Net::SNMP::Message qw(SEQUENCE OCTET_STRING FALSE);

#
# Load the Net::SNMP::Security::USM module
#

eval 'use Net::SNMP::Security::USM';

my $skip = ($@ =~ /locate (:?\S+\.pm)/) ? $@ : FALSE;

#
# 1. Create the Net::SNMP::Security::USM object
#

my ($u, $e);

eval
{
   ($u, $e) = Net::SNMP::Security::USM->new(
      -username     => 'dtown',
      -authpassword => 'maplesyrup',
      -authprotocol => 'sha',
      -privpassword => 'maplesyrup',
      -privprotocol => '3des',
   );

   # "Perform" discovery...
   $u->_engine_id_discovery(pack 'x11H2', '02');

   # ...and synchronization
   $u->_synchronize(10, time);
};

skip(
   $skip, ($@ || $e), q{}, 'Failed to create Net::SNMP::Security::USM object'
);

#
# 2. Check the localized authKey
#

eval
{
   $e = unpack 'H*', $u->auth_key();
};

skip(
   $skip,
   ($@ || $e),
   '6695febc9288e36282235fc7151f128497b38f3f',
   'Invalid authKey calculated'
);

#
# 3. Check the localized privKey
#

eval
{
   $e = unpack 'H*', $u->priv_key();
};

skip(
   $skip,
   ($@ || $e),
   '6695febc9288e36282235fc7151f128497b38f3f9b8b6d78936ba6e7d19dfd9c',
   'Invalid privKey calculated'
);

#
# 4. Create and initalize a Message
#

my $m;

eval
{
   ($m, $e) = Net::SNMP::Message->new();
   $m->prepare(SEQUENCE, pack('H*', 'deadbeef') x 8);
   $e = $m->error();
};

skip($skip, ($@ || $e), q{}, 'Failed to create Net::SNMP::Message object');

#
# 5. Calculate the HMAC
#

my $h;

eval
{
   $h = unpack 'H*', $u->_auth_hmac($m);
};

skip($skip, $@, q{}, 'Calculate the HMAC failed');

#
# 6. Encrypt/descrypt the Message
#

my $henc;

eval
{
   my $salt;
   my $len = $m->length();
   my $buff = $m->clear();
   my $encrypted = $u->_encrypt_data($m, $salt, $buff);
   $henc = unpack 'H*', $encrypted;
   $m->append($encrypted);
   $u->_decrypt_data($m, $salt, $m->process(OCTET_STRING));
   $e = $u->error();
   # Remove padding if necessary
   if ($len -= $m->length()) {
      substr ${$m->reference()}, $len, -$len, q{};
   }
};

skip(
   $skip,
   ($@ || $e || $henc),
   '042858d3a9fffa5afd8ef5cb338fdd79f452e13c0e77f4a918a069a84687c462726148c53198e6c97346',
   'Privacy failed',
);

#
# 7. Check the HMAC
#

my $h2;

eval
{
   $h2 = unpack 'H*', $u->_auth_hmac($m);
};

skip($skip, ($@ || $h2), $h, 'Authentication failed');

# ============================================================================
