#! /usr/local/bin/perl 

eval '(exit $?0)' && eval 'exec /usr/local/bin/perl $0 ${1+"$@"}'
&& eval 'exec /usr/local/bin/perl $0 $argv:q'
if 0;

# ============================================================================

# $Id: snmpwalk.pl,v 2.0 2001/10/15 13:21:52 dtown Exp $

# Copyright (c) 2000-2001 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use Net::SNMP qw(oid_lex_sort oid_base_match SNMP_VERSION_1 DEBUG_ALL);
use Getopt::Std;

use strict;
use vars qw($SCRIPT $VERSION %OPTS);

$SCRIPT  = 'snmpwalk';
$VERSION = '2.0.0';

# Validate the command line options
if (!getopts('a:A:c:dE:m:n:p:r:t:u:v:X:', \%OPTS)) {
   _usage();
}

# Do we have enough/too much information?
if (@ARGV != 2) {
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

# Perform repeated get-next-requests or get-bulk-requests (SNMPv2c) 
# until the last returned OBJECT IDENTIFIER is no longer a child of
# OBJECT IDENTIFIER passed in on the command line.

my @args = (
   exists($OPTS{E}) ? (-contextengineid => $OPTS{E}) : (),
   exists($OPTS{n}) ? (-contextname     => $OPTS{n}) : (),
   -varbindlist    => [$ARGV[0]]
);

if ($s->version == SNMP_VERSION_1) {

   while (defined($s->get_next_request(@args))) {
      $_ = (keys(%{$s->var_bind_list}))[0];

      if (!oid_base_match($ARGV[0], $_)) { last; }
      printf("%s => %s\n", $_, $s->var_bind_list->{$_});   

      @args = (-varbindlist => [$_]);
   }

} else {

   push(@args, -maxrepetitions => 25); 

   outer: while (defined($s->get_bulk_request(@args))) {

      my @oids = oid_lex_sort(keys(%{$s->var_bind_list}));

      foreach (@oids) {

         if (!oid_base_match($ARGV[0], $_)) { last outer; }
         printf("%s => %s\n", $_, $s->var_bind_list->{$_});

         # Make sure we have not hit the end of the MIB
         if ($s->var_bind_list->{$_} eq 'endOfMibView') { last outer; } 
      }

      # Get the last OBJECT IDENTIFIER in the returned list
      @args = (-maxrepetitions => 25, -varbindlist => [pop(@oids)]);
   }

}

# Let the user know about errors (except noSuchName).
if (($s->error() ne '') && ($s->error_status() != 2)) {
   _exit($s->error());
}

# Close the session
$s->close();
 
exit 0;

# [private] ------------------------------------------------------------------

sub _exit
{
   printf join('', sprintf("%s: ", $SCRIPT), shift(@_), ".\n"), @_;
   exit 1;
}

sub _usage
{
   printf("%s v%s\n", $SCRIPT, $VERSION);

   printf("Usage: %s [options] <hostname> <oid>\n", 
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

   exit 1;
}

# ============================================================================

