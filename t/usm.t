# -*- mode: perl -*- 
# ============================================================================

# $Id: usm.t,v 4.2 2003/05/06 11:00:46 dtown Exp $

# Test of the SNMPv3 User-based Security Model. 

# Copyright (c) 2001-2003 David M. Town <dtown@cpan.org>.
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

use Net::SNMP::Message qw(SEQUENCE OCTET_STRING);

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
      -authpassword => 'maplesyrup',
      -privpassword => 'maplesyrup',
      -privprotocol => 'des'
   );

   # "Perform" discovery...
   $u->_engine_id_discovery(pack('x11H2', '02')) if defined($u);

   # ...and synchronization
   $u->_synchronize(10, time()) if defined($u); 
};

ok(($@ || $e), '', 'Failed to create Net::SNMP::Security::USM object');

#
# 3. Check the localized authKey
#

eval 
{ 
   $e = unpack('H*', $u->auth_key); 
};

ok(
   ($@ || $e), 
   '526f5eed9fcce26f8964c2930787d82b', # RFC 2574 - A.3.1 
   'Invalid authKey calculated'
);

#
# 4. Check the localized privKey
#

eval 
{ 
   $e = unpack('H*', $u->priv_key); 
};

ok(
   ($@ || $e), 
   '526f5eed9fcce26f8964c2930787d82b', 
   'Invalid privKey calculated'
);

#
# 5. Create and initalize a Message
#

my $m;

eval 
{
   ($m, $e) = Net::SNMP::Message->new;
   $m->prepare(SEQUENCE, pack('H*', 'deadbeef') x 8) if defined($m);
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
   my $buff = $m->clear; 
   $m->append($u->_encrypt_data($m, $salt, $buff));
   $u->_decrypt_data($m, $salt, $m->process(OCTET_STRING));
   $e = $u->error;
   # Remove padding if necessary
   substr(${$m->reference}, $len, -$len, '') if ($len -= $m->length); 
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
      -authpassword => 'maplesyrup',
      -authprotocol => 'sha1',
      -privpassword => 'maplesyrup',
      -privprotocol => 'des'
   );

   # "Perform" discovery...
   $u->_engine_id_discovery(pack('x11H2', '02')) if defined($u);

   # ...and synchronization
   $u->_synchronize(10, time()) if defined($u);
};

ok(($@ || $e), '', 'Failed to create Net::SNMP::Security::USM object');

#
# 10. Check the localized authKey
#

eval 
{ 
   $e = unpack('H*', $u->auth_key); 
};

ok(
   ($@ || $e), 
   '6695febc9288e36282235fc7151f128497b38f3f', # RFC 2574 - A.3.2 
   'Invalid authKey calculated'
);

#
# 11. Check the localized privKey
#

eval 
{ 
   $e = unpack('H*', $u->priv_key); 
};

ok(
   ($@ || $e), 
   '6695febc9288e36282235fc7151f1284', 
   'Invalid privKey calculated'
);

#
# 12. Create and initalize a Message
#

eval 
{
   ($m, $e) = Net::SNMP::Message->new;
   $m->prepare(SEQUENCE, pack('H*', 'deadbeef') x 8) if defined($m);
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
   my $buff = $m->clear;
   $m->append($u->_encrypt_data($m, $salt, $buff));
   $u->_decrypt_data($m, $salt, $m->process(OCTET_STRING));
   $e = $u->error;
   # Remove padding if necessary
   substr(${$m->reference}, $len, -$len, '') if ($len -= $m->length);
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
