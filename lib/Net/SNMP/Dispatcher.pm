# -*- mode: perl -*- 
# ============================================================================

package Net::SNMP::Dispatcher;

# $Id: Dispatcher.pm,v 1.5 2003/05/06 11:00:46 dtown Exp $

# Object the dispatches SNMP messages and handles the scheduling of events.

# Copyright (c) 2001-2003 David M. Town <dtown@cpan.org>
# All rights reserved.

# This program is free software; you may redistribute it and/or modify it
# under the same terms as Perl itself.

# ============================================================================

use strict;

use Net::SNMP::MessageProcessing();
use Net::SNMP::Message qw(TRUE FALSE);

## Version of the Net::SNMP::Dispatcher module

our $VERSION = v1.0.4;

## Package variables

our $INSTANCE;            # Reference to our Singleton object

our $DEBUG = FALSE;       # Debug flag

our $MESSAGE_PROCESSING;  # Reference to the Message Processing object

## Event array indexes

sub _ACTIVE()   { 0 }     # State of the event
sub _TIME()     { 1 }     # Execution time
sub _CALLBACK() { 2 }     # Callback reference
sub _PREVIOUS() { 3 }     # Previous event
sub _NEXT()     { 4 }     # Next event

BEGIN
{
   # Use a higher resolution of time() if the Time::HiRes module is available. 

   if (eval('require Time::HiRes')) {
      Time::HiRes->import('time');
   }

   # Validate the creation of the Message Processing object. 

   if (!defined($MESSAGE_PROCESSING = Net::SNMP::MessageProcessing->instance)) {
      die('FATAL: Failed to create Message Processing instance');
   }
}

# [public methods] -----------------------------------------------------------

sub instance
{
   $INSTANCE || ($INSTANCE = Net::SNMP::Dispatcher->_new);
}

sub activate
{
   my ($this) = @_;

   # Return immediately if the Dispatcher is already active.
   return TRUE if ($this->{_active});

   # Indicate that the Dispatcher is active and block  
   # on select() calls.  

   $this->{_active}   = TRUE;
   $this->{_blocking} = TRUE;

   while (defined($this->{_event_queue_h})) { 
      $this->_event_handle; 
   }

   # Flag the Dispatcher as not active 
   $this->{_active} = FALSE; 
}

sub one_event
{
   my ($this) = @_;

   # Return immediately if the Dispatcher is already active.
   return TRUE if ($this->{_active});

   # Indicate that the Dispatcher is active and DO NOT 
   # block on select() calls.
   
   $this->{_active}   = TRUE; 
   $this->{_blocking} = FALSE;

   $this->_event_handle;

   # Flag the Dispatcher as not active
   $this->{_active} = FALSE;

   defined($this->{_event_queue_h}) ? TRUE : FALSE; 
}

sub send_pdu
{
   my ($this, $pdu, $delay) = @_;

   # Clear any previous errors
   $this->_error_clear;

   if ((@_ < 2) || !ref($pdu)) {
      return $this->_error('Required PDU missing');
   }

   # If the Dispatcher is active and there is
   # no delay just send the message.

   if (($this->{_active}) && (!$delay)) {
      $this->_send_pdu($pdu, $pdu->timeout, $pdu->retries);
   } else {
      $this->_schedule(
         $delay, [\&_send_pdu, $pdu, $pdu->timeout, $pdu->retries]
      );
   }
}

sub error
{
   $_[0]->{_error} || '';
}

sub debug
{
   (@_ == 2) ? $DEBUG = ($_[1]) ? TRUE : FALSE : $DEBUG;
}

# [private methods] ----------------------------------------------------------

sub _new
{
   my ($class) = @_;

   # The constructor is private since we only want one 
   # Dispatcher object.

   bless {
      '_active'        => FALSE,  # State of this Dispatcher object
      '_blocking'      => TRUE,   # Block on select()
      '_error'         => undef,  # Error message
      '_event_queue_h' => undef,  # Head of the event queue
      '_event_queue_t' => undef,  # Tail of the event queue
      '_rin'           => undef,  # Readable vector for select()
      '_descriptors'   => {},     # List of file descriptors to monitor
   }, $class;
}

sub _schedule
{
   my ($this, $time, $callback) = @_;

   $this->_event_create($time, $this->_callback_create($callback));
}

sub _cancel 
{
   my ($this, $event) = @_;

   $this->_event_delete($event);
}

sub _listen
{
   my ($this, $transport, $callback) = @_;

   # Transport Layer and file descriptor must be valid.
   my $fileno;

   if ((!defined($transport)) || (!defined($fileno = $transport->fileno))) {
      return $this->_error('Invalid Transport Layer');
   }

   # NOTE: The callback must read the data associated with the
   #       file descriptor or the Dispatcher will continuously 
   #       call the callback and get stuck in an infinite loop.

   if (!exists($this->{_descriptors}->{$fileno})) {

      DEBUG_INFO('adding descriptor [%d]', $fileno);
     
      $this->{_rin} = '' unless defined($this->{_rin});
 
      # Add the file descriptor to the list
      $this->{_descriptors}->{$fileno} = [
         $this->_callback_create($callback), # Callback
         $transport,                         # Transport Layer 
         1                                   # Reference count
      ];
 
      # Add the file descriptor to the "readable" vector
      vec($this->{_rin}, $fileno, 1) = 1;
   
   } else {
      # Bump up the reference count
      $this->{_descriptors}->{$fileno}->[2]++;
   }

   # Return the Transport Layer reference
   $transport;  
}

sub _unlisten
{
   my ($this, $transport) = @_;
  
   # Transport Layer and file descriptor must be valid. 
   my $fileno; 

   if ((!defined($transport)) || (!defined($fileno = $transport->fileno))) {
      return $this->_error('Invalid Transport Layer');
   }

   if (exists($this->{_descriptors}->{$fileno})) {

      # Check reference count
      if (--$this->{_descriptors}->{$fileno}->[2] < 1) {

         DEBUG_INFO('removing descriptor [%d]', $fileno);

         # Remove the file descriptor from the list
         delete($this->{_descriptors}->{$fileno});

         # Remove the file descriptor from the "readable" vector
         vec($this->{_rin}, $fileno, 1) = 0;

         # Undefine the vector if there are no file descriptors, 
         # some systems expect this to make select() work properly.

         $this->{_rin} = undef unless keys(%{$this->{_descriptors}});
      }

   } else {
      return $this->_error('Not listening for this Transport Layer');
   }

   # Return the Transport Layer reference
   $transport; 
}

sub _send_pdu
{
   my ($this, $pdu, $timeout, $retries) = @_;

   # Pass the PDU to Message Processing so that it can
   # create the new outgoing message.

   my $msg = $MESSAGE_PROCESSING->prepare_outgoing_msg($pdu);

   if (!defined($msg)) {
      $pdu->error($MESSAGE_PROCESSING->error);
      $pdu->callback_execute;
      return $this->_error($pdu->error); 
   }

   # Actually send the message

   if (!defined($msg->send)) {
      if ($pdu->expect_response) {
         $MESSAGE_PROCESSING->msg_handle_delete($pdu->msg_id);
      }
      $pdu->error($msg->error);
      $pdu->callback_execute;
      return $this->_error($pdu->error);
   }

   # Schedule the timeout handler if the message expects a response.

   if ($pdu->expect_response) {
      $this->_listen($msg->transport, [\&_transport_response_received]);
      $msg->timeout_id(
         $this->_schedule(
            $timeout, 
            [\&_transport_timeout, $pdu, $timeout, $retries] 
         )
      ); 
   }

   # Return the message
   $msg;
}

sub _transport_timeout
{
   my ($this, $pdu, $timeout, $retries) = @_;

   # Stop listening for responses
   $this->_unlisten($pdu->transport);

   if ($retries-- > 0) {

      # Resend a new message
      DEBUG_INFO('retries left %d', $retries); 
      $this->_send_pdu($pdu, $timeout, $retries);

   } else {

      # Delete the msgHandle 
      $MESSAGE_PROCESSING->msg_handle_delete($pdu->msg_id);

      # Upcall 
      $pdu->error("No response from remote host '%s'", $pdu->dstname);
      $pdu->callback_execute;

      $this->_error($pdu->error);

   } 
}

sub _transport_response_received
{
   my ($this, $transport) = @_;

   # Clear any previous errors
   $this->_error_clear;

   die('FATAL: Invalid Transport Layer') unless ref($transport);

   # Create a new message to receive the response
   my ($msg, $error) = Net::SNMP::Message->new(
      -transport => $transport,
   );

   die("FATAL: $error") unless defined($msg);

   # Read the message from the Transport Layer
   if (!defined($msg->recv)) {
      return $this->_error($msg->error);
   }

   # Hand the message over to Message Processing
   if (!defined($MESSAGE_PROCESSING->prepare_data_elements($msg))) {
      return $this->_error($MESSAGE_PROCESSING->error);  
   }

   # Set the error if applicable 
   $msg->error($MESSAGE_PROCESSING->error) if ($MESSAGE_PROCESSING->error);

   # Cancel the timeout
   $this->_cancel($msg->timeout_id);

   # Stop listening for responses
   $this->_unlisten($msg->transport);

   # Invoke the callback   
   $msg->callback_execute; 
}

sub _event_create
{
   my ($this, $time, $callback) = @_;

   # Create a new event anonymous array and add it to the queue.   
   # The event is initialized based on the currrent state of the 
   # Dispatcher object.  If the Dispatcher is not currently running
   # the event needs to be created such that it will get properly
   # initialized when the Dispatcher is started.

   $this->_event_insert(
      [
         $this->{_active},                          # State of the object
         $this->{_active} ? time() + $time : $time, # Execution time
         $callback,                                 # Callback reference
         undef,                                     # Previous event
         undef,                                     # Next event 
      ]
   ); 
}

sub _event_insert
{
   my ($this, $event) = @_;

   # If the head of the list is not defined, we _must_ be the only
   # entry in the list, so create a new head and tail reference.

   if (!defined($this->{_event_queue_h})) {
      DEBUG_INFO('created new head and tail [%s]', $event);
      return $this->{_event_queue_h} = $this->{_event_queue_t} = $event;
   }

   # Estimate the midpoint of the list by calculating the average of
   # the time associated with the head and tail of the list.  Based
   # on this value either start at the head or tail of the list to
   # search for an insertion point for the new Event.

   my $midpoint = (($this->{_event_queue_h}->[_TIME] +
                    $this->{_event_queue_t}->[_TIME]) / 2);


   if ($event->[_TIME] >= $midpoint) {

      # Search backwards from the tail of the list

      for (my $e = $this->{_event_queue_t}; defined($e); $e = $e->[_PREVIOUS])
      {
         if ($e->[_TIME] <= $event->[_TIME]) {
            $event->[_PREVIOUS] = $e;
            $event->[_NEXT] = $e->[_NEXT];
            if ($e eq $this->{_event_queue_t}) {
               DEBUG_INFO('modified tail [%s]', $event);
               $this->{_event_queue_t} = $event;
            } else {
               DEBUG_INFO('inserted [%s] into list', $event);
               $e->[_NEXT]->[_PREVIOUS] = $event;
            }
            return $e->[_NEXT] = $event;
         }
      }

      DEBUG_INFO('added [%s] to head of list', $event);
      $event->[_NEXT] = $this->{_event_queue_h};
      $this->{_event_queue_h} = $this->{_event_queue_h}->[_PREVIOUS] = $event;

   } else {

      # Search forward from the head of the list

      for (my $e = $this->{_event_queue_h}; defined($e); $e = $e->[_NEXT]) {
         if ($e->[_TIME] > $event->[_TIME]) {
            $event->[_NEXT] = $e;
            $event->[_PREVIOUS] = $e->[_PREVIOUS];
            if ($e eq $this->{_event_queue_h}) {
               DEBUG_INFO('modified head [%s]', $event);
               $this->{_event_queue_h} = $event;
            } else {
               DEBUG_INFO('inserted [%s] into list', $event);
               $e->[_PREVIOUS]->[_NEXT] = $event; 
            }
            return $e->[_PREVIOUS] = $event;
         }
      }

      DEBUG_INFO('added [%s] to tail of list', $event);
      $event->[_PREVIOUS] = $this->{_event_queue_t};
      $this->{_event_queue_t} = $this->{_event_queue_t}->[_NEXT] = $event;

   }
}

sub _event_delete
{
   my ($this, $event) = @_;

   # Update the previous event
   if (defined($event->[_PREVIOUS])) {
      $event->[_PREVIOUS]->[_NEXT] = $event->[_NEXT];
   } elsif ($event eq $this->{_event_queue_h}) {
      if (defined($this->{_event_queue_h} = $event->[_NEXT])) {
         DEBUG_INFO('defined new head [%s]', $event->[_NEXT]);
      } else {
         DEBUG_INFO('deleted [%s], list is now empty', $event);
         $this->{_event_queue_t} = undef @{$event}; 
         return TRUE;
      }
   } else {
      die('FATAL: Attempt to delete invalid Event head');
   }

   # Update the next event
   if (defined($event->[_NEXT])) {
      $event->[_NEXT]->[_PREVIOUS] = $event->[_PREVIOUS];
   } elsif ($event eq $this->{_event_queue_t}) {
      DEBUG_INFO('defined new tail [%s]', $event->[_PREVIOUS]);
      $this->{_event_queue_t} = $event->[_PREVIOUS];
   } else {
      die('FATAL: Attempt to delete invalid Event tail');
   }

   DEBUG_INFO('deleted [%s]', $event);
   undef @{$event};

   TRUE;
}

sub _event_init
{
   my ($this, $event) = @_;

   # The execution time of the event needs to be updated
   # if the event was inserted while the Dispatcher was
   # not active.

   DEBUG_INFO('initializing event [%s]', $event);

   if ($event->[_TIME] == 0) {
      $this->_callback_execute($event->[_CALLBACK]);
      $this->_event_delete($event);
   } else {
      $this->_event_create($event->[_TIME], $event->[_CALLBACK]);
      $this->_event_delete($event);
   }
}

sub _event_handle
{
   my ($this) = @_;

   # Events are sorted by time, so the event at the head of the list
   # is the next event that needs to be executed.

   return unless defined(my $event = $this->{_event_queue_h});

   # Calculate a timeout based on the current time and the lowest 
   # event time (if the event does not need initialized).

   my $timeout = ($event->[_ACTIVE]) ? ($event->[_TIME] - time()) : 0;

   # If the timeout is less than 0, we are running late.  In an 
   # attempt to recover from this we do not check the status of  
   # the file descriptors.

   if ($timeout >= 0) {
      DEBUG_INFO('poll delay = %f' , $timeout);
      if (select(my $rout = $this->{_rin}, undef, undef,
                 ($this->{_blocking} ? $timeout : 0)))
      {
         # Find out which file descriptors have data ready
         if (defined($rout)) {
            foreach (keys(%{$this->{_descriptors}})) {
               if (vec($rout, $_, 1)) {
                  DEBUG_INFO('descriptor [%d] ready', $_);
                  $this->_callback_execute(@{$this->{_descriptors}->{$_}});
               }
            }
            return TRUE;
         }
      }
      if ((!$this->{_blocking}) && ($timeout > 0)) {
         return TRUE;
      }
   } else {
      DEBUG_INFO('skew = %f', -$timeout);
   }

   # If we made it here, no data was received during the poll cycle, so
   # we take action on the object at the head of the queue.

   if (!$event->[_ACTIVE]) {
      return $this->_event_init($event);
   } else {
      $this->_callback_execute($event->[_CALLBACK]);
   }

   # Once we reach here, we are done with the event, so remove it
   # from the head of the queue.

   $this->_event_delete($event);
}

sub _callback_create
{
   return unless (@_ == 2);

   # Callbacks can be passed in two different ways.  If the callback
   # has options, the callback must be passed as an ARRAY reference
   # with the first element being a CODE reference and the remaining
   # elements the arguments.  If the callback has not options it
   # is just passed as a CODE reference.

   if ((ref($_[1]) eq 'ARRAY') && (ref($_[1]->[0]) eq 'CODE')) {
      $_[1];
   } elsif (ref($_[1]) eq 'CODE') {
      [$_[1]];
   } else {
      return;
   }
}

sub _callback_execute
{
   return unless (@_ > 1) && defined($_[1]);

   # The callback is invoked passing a reference to this object
   # with the parameters passed by the user next and then any 
   # parameters that we provide.

   my $this = shift(@_);
   my @argv = @{shift(@_)};
   my $cb   = shift(@argv);
   
   # Protect ourselves from user error. 
   eval { $cb->($this, @argv, @_); };

   ($@) ? $this->_error($@) : TRUE;
}

sub _error
{
   my $this = shift;

   if (!defined($this->{_error})) {
      $this->{_error} = sprintf(shift(@_), @_);
      if ($this->debug) {
         printf("error: [%d] %s(): %s\n",
            (caller(0))[2], (caller(1))[3], $this->{_error}
         );
      }
   }

   return;
}

sub _error_clear
{
   $_[0]->{_error} = undef;
}

sub DEBUG_INFO
{
   return unless $DEBUG;

   printf(
      sprintf('debug: [%d] %s(): ', (caller(0))[2], (caller(1))[3]) . 
      shift(@_) . 
      "\n",
      @_
   );

   $DEBUG;
}

# ============================================================================
1; # [end Net::SNMP::Dispatcher]
