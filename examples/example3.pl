#! /usr/local/bin/perl

# ============================================================================

# $Id: example3.pl,v 1.1 2001/09/09 13:19:44 dtown Exp $

# Copyright (c) 2000-2001 David M. Town <david.town@marconi.com>.
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;
use vars qw(@hosts @sessions $MAX_POLLS $INTERVAL $EPOC);

use Net::SNMP qw(snmp_event_loop ticks_to_time);

# List of hosts to poll

@hosts = qw(.1.1.1 1.1.1.2 localhost);

# Poll interval (in seconds).  This value should be greater than
# the number of retries times the timeout value.

$INTERVAL = 60;

# Maximum number of polls after initial poll

$MAX_POLLS = 10;

# Create a session for each host
foreach (@hosts) {
   my ($session, $error) = Net::SNMP->session(
      -hostname    => $_,
      -nonblocking => 0x1,   # Create non-blocking objects
      -translate   => [
         -timeticks => 0x0   # Turn off so sysUpTime is numeric
      ]  
,-debug => 1 
   );
   if (!defined($session)) {
      printf("ERROR: %s.\n", $error);
      foreach (@sessions) { $_->[0]->close(); }
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
$EPOC = time();

# Enter the event loop
snmp_event_loop();

# Not necessary, but it is nice to clean up after yourself
foreach (@sessions) { $_->[0]->close(); }

exit 0;


sub validate_sysUpTime_cb
{
   my ($this, $last_uptime, $num_polls) = @_;

   if (!defined($this->var_bind_list())) {

      printf("%-15s  ERROR: %s\n", $this->hostname(), $this->error());

   } else {
   
      # Validate the sysUpTime

      my $uptime = $this->var_bind_list()->{$sysUpTime};
      if ($uptime < ${$last_uptime}) {
         printf("%-15s  WARNING: %s is less than %s\n",
            $this->hostname(), 
            ticks_to_time($uptime), 
            ticks_to_time(${$last_uptime})
         );
      } else {
         printf("%-15s  Ok (%s)\n", 
            $this->hostname(), 
            ticks_to_time($uptime)
         );
      }

      # Store the new sysUpTime
      ${$last_uptime} = $uptime;

   }

   # Queue the next message if we have not reach MAX_POLLS

   if (++${$num_polls} <= $MAX_POLLS) {
      my $delay = (($INTERVAL * ${$num_polls}) + $EPOC) - time();
      $this->get_request(
         -delay       => ($delay >= 0) ? $delay : 0,
         -varbindlist => [$sysUpTime],
         -callback    => [\&validate_sysUpTime_cb, $last_uptime, $num_polls]
      );
   }

   $this->error_status();
}