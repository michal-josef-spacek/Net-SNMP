# -*- mode: perl -*- 
# ============================================================================

# $Id: usm.t,v 4.0 2001/10/15 13:41:26 dtown Exp $

# Test of the SNMPv3 User-based Security Model. 

# Copyright (c) 2001 David M. Town <dtown@cpan.org>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;
use Test;

BEGIN
{
   $|  = 1;
   $^W = 1;
   plan tests => 15
}

use Net::SNMP::Message qw(SEQUENCE);

#
# 1. Load the Net::SNMP::Security::USM module
#

eval 'use Net::SNMP::Security::USM';

ok($@, '', 'Failed to load Net::SNMP::Security::USM module');

#
# 2. Create the Net::SNMP::Security::USM object
#

my ($u, $e); 

eval 
{ 
   ($u, $e) = Net::SNMP::Security::USM->new(
      -username     => 'dtown',
      -authpassword => '5678ABCD',
      -privpassword => 'efgh4321',
   );

   # "Perform" discovery
   $u->_discovery(pack('x11H2', '01'), 10, time()) if defined($u);
};

ok(($@ || $e), '', 'Failed to create Net::SNMP::Security::USM object');

#
# 3. Check the localized authKey
#

eval 
{ 
   $e = unpack('H*', $u->_auth_key); 
};

ok(
   ($@ || $e), 
   '24c807c13145d08362a705edc8f63a11', 
   'Invalid authKey calculated'
);

#
# 4. Check the localized privKey
#

eval 
{ 
   $e = unpack('H*', $u->_priv_key); 
};

ok(
   ($@ || $e), 
   '03f2c3755a93e93f61f40cf6b78d285f', 
   'Invalid privKey calculated'
);

#
# 5. Create and initalize a Message
#

my $m;

eval 
{
   ($m, $e) = Net::SNMP::Message->new;
   $m->prepare(SEQUENCE, pack('H*', 'deadbeef')) if defined($m);
   $e = $m->error if defined($m);
};

ok(($@ || $e), '', 'Failed to create Net::SNMP::Message object');

#
# 6. Calculate the HMAC
#

my $h;

eval 
{ 
   $h = unpack('H*', $u->_auth_hmac($m)); 
};

ok($@, '', 'Calculate the HMAC failed');

#
# 7. Encrypt/descrypt the Message
#

eval 
{
   my $salt;
   my $len = $m->length;
   $m->append($u->_priv_encrypt_des($salt, $m->clear));
   $m->append($u->_priv_decrypt_des($salt, $m->clear));
   $e = $u->error;
   # Remove padding
   $len -= $m->length;
   substr(${$m->reference}, $len, -$len, '');
};

ok(($@ || $e), '', 'Privacy failed');

#
# 8. Check the HMAC
#

my $h2;

eval 
{ 
   $h2 = unpack('H*', $u->_auth_hmac($m)); 
};

ok(($@ || $h2), $h, 'Authentication failed');

#
# 9. Create the Net::SNMP::Security::USM object
#

eval 
{ 
   ($u, $e) = Net::SNMP::Security::USM->new(
      -username     => 'dtown',
      -authpassword => '123-wxyz',
      -authprotocol => 'sha1',
      -privpassword => 'DAVE0987',
   );

   # "Perform" discovery
   $u->_discovery(pack('x11H2', '01'), 10, time()) if defined($u);
};

ok(($@ || $e), '', 'Failed to create Net::SNMP::Security::USM object');

#
# 10. Check the localized authKey
#

eval 
{ 
   $e = unpack('H*', $u->_auth_key); 
};

ok(
   ($@ || $e), 
   '806a48c0ec611bb68834e583b3332f35f6d1b506', 
   'Invalid authKey calculated'
);

#
# 11. Check the localized privKey
#

eval 
{ 
   $e = unpack('H*', $u->_priv_key); 
};

ok(
   ($@ || $e), 
   'b78d80e9a94a8a78cad331b31e5de4d83847e9b0', 
   'Invalid privKey calculated'
);

#
# 12. Create and initalize a Message
#

eval 
{
   ($m, $e) = Net::SNMP::Message->new;
   $m->prepare(SEQUENCE, pack('H*', 'deadbeef')) if defined($m);
   $e = $m->error if defined($m);
};

ok(($@ || $e), '', 'Failed to create Net::SNMP::Message object');

#
# 13. Calculate the HMAC
#

eval 
{ 
   $h = unpack('H*', $u->_auth_hmac($m)); 
};

ok($@, '', 'Calculate the HMAC failed');

#
# 14. Encrypt/descrypt the Message
#

eval 
{
   my $salt;
   my $len = $m->length;
   $m->append($u->_priv_encrypt_des($salt, $m->clear));
   $m->append($u->_priv_decrypt_des($salt, $m->clear));
   $e = $u->error;
   # Remove padding
   $len -= $m->length;
   substr(${$m->reference}, $len, -$len, '');
};

ok(($@ || $e), '', 'Privacy failed');

#
# 15. Check the HMAC
#

eval 
{ 
   $h2 = unpack('H*', $u->_auth_hmac($m)); 
};

ok(($@ || $h2), $h, 'Authentication failed');

# ============================================================================
