#! /usr/local/bin/perl

eval '(exit $?0)' && eval 'exec /usr/local/bin/perl $0 ${1+"$@"}'
&& eval 'exec /usr/local/bin/perl $0 $argv:q'
if 0;

# ============================================================================

# $Id: snmpkey.PL,v 1.2 2002/01/01 14:03:44 dtown Exp $

# Copyright (c) 2001-2002 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use Config;

my $file = shift || 'snmpkey';

open(OUT, ">$file") || die "Failed to open file '$file' [$!]";

print OUT "$Config{startperl}\n";

print OUT <<'AS-IS';

# ============================================================================

# $Id: snmpkey.PL,v 1.2 2002/01/01 14:03:44 dtown Exp $

# Copyright (c) 2001-2002 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

=head1 NAME

snmpkey - Create a SNMPv3 security key for the Net::SNMP module

=head1 SYNOPSIS

The C<snmpkey> utility generates a security key based on a password and
an authoritativeEngineID passed on the command line.  This key can then
be used by the Net::SNMP module instead of the plain text password when
creating SNMPv3 objects.

   snmpkey md5|sha1 <password> <authoritativeEngineID>

=head1 DESCRIPTION

The User-based Security Model used by SNMPv3 defines an algorithm which
"localizes" a plain text password to a specific authoritativeEngineID using
a one-way hash.  This resulting key is used by the SNMP application instead
of the plain text password for security reasons.

The Net::SNMP module allows the user to either provide a plain text password
or a localized key to the object constructor when configuring authentication
or privacy.  The C<snmpkey> utility can be used to generate the key to be
used by the B<-authkey> or B<-privkey> named arguments when they are passed 
to the Net::SNMP C<session()> constructor.

The C<snmpkey> utility expects three command line arguments.  The first
argument defines which hash algorithm to use when creating the key.  Either
MD5 (RFC 1321) or SHA-1 (NIST FIPS PUB 180) can be specified with the
string 'md5' or 'sha1' respectively.  This choice must match the
algorithm passed to the B<-authprotocol> argument when creating Net::SNMP
objects.  The second argument is the plain text password that is to be 
localized.  The final argument is the authoritativeEngineID of the remote 
SNMP engine associated with the Net::SNMP argument B<-hostname>.  The
authoritativeEngineID is to be entered as a hexadecimal string 10 to 64 
characters (5 to 32 octets) long and can be prefixed with an optional "0x".

=head1 AUTHOR

David M. Town <dtown@cpan.org>

=head1 COPYRIGHT

Copyright (c) 2001-2002 David M. Town.  All rights reserved.  This program
is free software; you may redistribute it and/or modify it under the same
terms as Perl itself.

=head1 SEE ALSO

L<Net::SNMP>

=cut

# ============================================================================

use strict;

use Net::SNMP::Security::USM;

my $SCRIPT  = 'snmpkey';
my $VERSION = v1.0.1;

# Do we have enough/too much information?
if (@ARGV != 3) {
   _usage();
}

my ($usm, $error) = Net::SNMP::Security::USM->new(
   -authoritative => 1, # Undocumented / unsupported argument
   -username      => 'initial',
   -authprotocol  => shift,
   -authpassword  => shift,
   -engineid      => shift,
);

if (!defined($usm)) {
   _exit($error);
}

printf("Key: 0x%s\n", unpack('H*', $usm->auth_key));

exit 0;


# [private] ------------------------------------------------------------------

sub _exit
{
   printf sprintf('%s: ', $SCRIPT) . shift(@_) . ".\n", @_;
   exit 1;
}

sub _usage
{
   printf("%s v%vd\n", $SCRIPT, $VERSION);
   printf("Copyright (c) 2001-2002 David M. Town <dtown\@cpan.org>\n");
   printf("All rights reserved.\n");

   printf("Usage: %s md5|sha1 <password> <authoritativeEngineID>\n",
      $SCRIPT
   );

   exit 1;
}

# ============================================================================

AS-IS

close(OUT) || die "Failed to close file '$file' [$!]";

chmod(0755, $file) || die "Failed to set permissions for file '$file' [$!]";

exit 0;

# ============================================================================

