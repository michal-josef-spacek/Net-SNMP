#! /usr/local/bin/perl 

eval '(exit $?0)' && eval 'exec /usr/local/bin/perl $0 ${1+"$@"}'
&& eval 'exec /usr/local/bin/perl $0 $argv:q'
if 0;

# ============================================================================

# $Id: snmpset.pl,v 2.1 2002/05/06 12:30:37 dtown Exp $

# Copyright (c) 2000-2002 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use Net::SNMP qw(:asn1 oid_lex_sort DEBUG_ALL);
use Getopt::Std;

use strict;
use vars qw($SCRIPT $VERSION %OPTS);

$SCRIPT  = 'snmpset';
$VERSION = '2.0.1';

# Validate the command line options
if (!getopts('a:A:c:dE:m:n:p:r:t:u:v:X:', \%OPTS)) {
   _usage();
}

# Do we have enough information?
if (@ARGV < 4) {
   _usage();
}

# Create the SNMP session
my ($s, $e) = Net::SNMP->session(
   -hostname  => shift,
   exists($OPTS{a}) ? (-authprotocol =>  $OPTS{a}) : (),
   exists($OPTS{A}) ? (-authpassword =>  $OPTS{A}) : (),
   exists($OPTS{c}) ? (-community    =>  $OPTS{c}) : (),
   exists($OPTS{d}) ? (-debug        => DEBUG_ALL) : (),
   exists($OPTS{m}) ? (-maxmsgsize   =>  $OPTS{m}) : (),
   exists($OPTS{p}) ? (-port         =>  $OPTS{p}) : (),
   exists($OPTS{r}) ? (-retries      =>  $OPTS{r}) : (),
   exists($OPTS{t}) ? (-timeout      =>  $OPTS{t}) : (),
   exists($OPTS{u}) ? (-username     =>  $OPTS{u}) : (),
   exists($OPTS{v}) ? (-version      =>  $OPTS{v}) : (),
   exists($OPTS{X}) ? (-privpassword =>  $OPTS{X}) : ()
);

# Was the session created?
if (!defined($s)) {
   _exit($e);
}

# Convert the ASN.1 types to the respresentation expected by Net::SNMP
if (_convert_asn1_types(\@ARGV)) {
   _usage();
}

my @args = (
   exists($OPTS{E}) ? (-contextengineid => $OPTS{E}) : (),
   exists($OPTS{n}) ? (-contextname     => $OPTS{n}) : (),
   -varbindlist    => \@ARGV
);

# Send the SNMP message
if (!defined($s->set_request(@args))) {
   _exit($s->error());
}

# Print the results
foreach (oid_lex_sort(keys(%{$s->var_bind_list()}))) {
   printf("%s => %s\n", $_, $s->var_bind_list()->{$_});
}

# Close the session
$s->close();
 
exit 0;


# [private] ------------------------------------------------------------------


sub _convert_asn1_types
{
   my ($argv) = @_;

   my %asn1_types = (
      'a' => IPADDRESS,
      'c' => COUNTER32,
      'C' => COUNTER64,
      'g' => GAUGE32,
      'h' => OCTET_STRING,
      'i' => INTEGER32,
      'o' => OBJECT_IDENTIFIER,
      'p' => OPAQUE,
      's' => OCTET_STRING,
      't' => TIMETICKS,
   );

   if ((ref($argv) ne 'ARRAY') || (scalar(@{$argv}) % 3)) {
      return 1;
   }

   for (my $i = 0; $i < scalar(@{$argv}); $i += 3) {
      if (exists($asn1_types{$argv->[$i+1]})) {
         if ($argv->[$i+1] eq 'h') {
            if ($argv->[$i+2] =~ /^(?i:0x)?([0-9a-fA-F]+)$/) {
               $argv->[$i+2] = pack('H*', length($1) % 2 ? '0'.$1 : $1);
            } else {
               _exit("Expected hex string for type 'h'");
            }
         } 
         $argv->[$i+1] = $asn1_types{$argv->[$i+1]};
      } else {
         _exit('Unknown ASN.1 type [%s]', $argv->[$i+1]);
      }
   }

   0; 
}

sub _exit
{
   printf join('', sprintf('%s: ', $SCRIPT), shift(@_), ".\n"), @_;
   exit 1;
}

sub _usage
{
   printf("%s v%s\n", $SCRIPT, $VERSION);

   printf(
      "Usage: %s [options] <hostname> <oid> <type> <value> [...]\n",
      $SCRIPT
   );

   printf("Options: -v 1|2c|3      SNMP version\n");
   printf("         -d             Enable debugging\n");

   printf("   SNMPv1/SNMPv2c:\n");
   printf("         -c <community> Community name\n");

   printf("   SNMPv3:\n");
   printf("         -u <username>  Username (required)\n");
   printf("         -E <engineid>  Context Engine ID\n");
   printf("         -n <name>      Context Name\n");
   printf("         -a md5|sha1    Authentication protocol\n");
   printf("         -A <password>  Authentication password\n");
   printf("         -X <password>  Privacy password\n");

   printf("   Transport Layer:\n");
   printf("         -m <octets>    Maximum message size\n");
   printf("         -p <port>      Destination UDP port\n");
   printf("         -r <attempts>  Number of retries\n");
   printf("         -t <secs>      Timeout period\n");

   printf("Valid type values:\n");
   printf("          a - IpAddress         o - OBJECT IDENTIFIER\n");
   printf("          c - Counter           p - Opaque\n");
   printf("          C - Counter64         s - OCTET STRING\n");
   printf("          g - Gauge             t - TimeTicks\n");
   printf("          i - INTEGER           h - OCTET STRING (hex)\n");

   exit 1;
}

# ============================================================================

