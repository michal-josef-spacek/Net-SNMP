#! /usr/local/bin/perl 

eval '(exit $?0)' && eval 'exec /usr/local/bin/perl $0 ${1+"$@"}'
&& eval 'exec /usr/local/bin/perl $0 $argv:q'
if 0;

# ============================================================================

# $Id: snmpgetbulk.pl,v 2.0 2001/10/15 13:20:34 dtown Exp $

# Copyright (c) 2000-2001 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use Net::SNMP qw(oid_lex_sort DEBUG_ALL);
use Getopt::Std;

use strict; 
use vars qw($SCRIPT $VERSION %OPTS);

$SCRIPT  = 'snmpgetbulk';
$VERSION = '2.0.0';

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
   exists($OPTS{v}) ? (-version      =>  $OPTS{v}) : (-version => 'snmpv2c'),
   exists($OPTS{X}) ? (-privpassword =>  $OPTS{X}) : ()
);

# Was the session created?
if (!defined($s)) {
   _exit($e);
}

my @args = (
   exists($OPTS{E}) ? (-contextengineid => $OPTS{E}) : (),
   exists($OPTS{n}) ? (-contextname     => $OPTS{n}) : (),
   -nonrepeaters   => shift,
   -maxrepetitions => shift,
   -varbindlist    => \@ARGV
);

# Send the SNMP message
if (!defined($s->get_bulk_request(@args))) {
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

sub _exit
{
   printf join('', sprintf("%s: ", $SCRIPT), shift(@_), ".\n"), @_;
   exit 1;
}

sub _usage
{
   printf("%s v%s\n", $SCRIPT, $VERSION);

   printf(
      "Usage: %s [options] <hostname> <non-repeaters> <max-repetitions> " .
      "<oid> [...]\n", $SCRIPT 
   );

   
   printf("Options: -v 2c|3        SNMP version\n");
   printf("         -d             Enable debugging\n");

   printf("   SNMPv2c:\n");
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

