#! /usr/local/bin/perl

# ============================================================================

# $Id: example4.pl,v 4.0 2001/10/15 13:16:42 dtown Exp $

# Copyright (c) 2000-2001 David M. Town <david.town@marconi.com>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Net::SNMP qw(snmp_dispatcher ticks_to_time);

# List of hosts to poll

my @hosts = qw(1.1.1.1 1.1.1.2 localhost);

# Poll interval (in seconds).  This value should be greater than
# the number of retries times the timeout value.

my $INTERVAL = 60;

# Maximum number of polls after the initial poll

my $MAX_POLLS = 10;

my @sessions;

# Create a session for each host
foreach (@hosts) {
   my ($session, $error) = Net::SNMP->session(
      -hostname    => $_,
      -nonblocking => 0x1,   # Create non-blocking objects
      -translate   => [
         -timeticks => 0x0   # Turn off so sysUpTime is numeric
      ]  
   );
   if (!defined($session)) {
      printf("ERROR: %s.\n", $error);
      exit 1;
   }

   # Create an array of arrays which contains the new object, 
   # the last sysUpTime, and the total number of polls.

   push(@sessions, [$session, 0, 0]);
}

my $sysUpTime = '1.3.6.1.2.1.1.3.0';

# Queue each of the queries for sysUpTime
foreach (@sessions) {
   $_->[0]->get_request(
       -varbindlist => [$sysUpTime],
       -callback    => [\&validate_sysUpTime_cb, \$_->[1], \$_->[2]]
   );
}

# Define a reference point for all of the polls
my $EPOC = time();

# Enter the event loop
snmp_dispatcher();

exit 0;

sub validate_sysUpTime_cb
{
   my ($session, $last_uptime, $num_polls) = @_;

   if (!defined($session->var_bind_list)) {

      printf("%-15s  ERROR: %s\n", $session->hostname, $session->error);

   } else {
   
      # Validate the sysUpTime

      my $uptime = $session->var_bind_list()->{$sysUpTime};
      if ($uptime < ${$last_uptime}) {
         printf("%-15s  WARNING: %s is less than %s\n",
            $session->hostname, 
            ticks_to_time($uptime), 
            ticks_to_time(${$last_uptime})
         );
      } else {
         printf("%-15s  Ok (%s)\n", 
            $session->hostname, ticks_to_time($uptime)
         );
      }

      # Store the new sysUpTime
      ${$last_uptime} = $uptime;

   }

   # Queue the next message if we have not reach MAX_POLLS

   if (++${$num_polls} <= $MAX_POLLS) {
      my $delay = (($INTERVAL * ${$num_polls}) + $EPOC) - time();
      $session->get_request(
         -delay       => ($delay >= 0) ? $delay : 0,
         -varbindlist => [$sysUpTime],
         -callback    => [\&validate_sysUpTime_cb, $last_uptime, $num_polls]
      );
   }

   $session->error_status;
}
