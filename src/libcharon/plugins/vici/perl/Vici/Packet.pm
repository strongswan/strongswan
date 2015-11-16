package Vici::Packet;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(new, request, register, unregister, streamed_request);
our @VERSION = 0.9;

use strict;
use Switch;
use Vici::Transport;

use constant {
    CMD_REQUEST      => 0,  # Named request message
    CMD_RESPONSE     => 1,  # Unnamed response message for a request
    CMD_UNKNOWN      => 2,  # Unnamed response if requested command is unknown
    EVENT_REGISTER   => 3,  # Named event registration request
    EVENT_UNREGISTER => 4,  # Named event de-registration request
    EVENT_CONFIRM    => 5,  # Unnamed confirmation for event (de-)registration
    EVENT_UNKNOWN    => 6,  # Unnamed response if event (de-)registration failed
    EVENT            => 7,  # Named event message
};

sub new {
    my $class = shift;
    my $socket = shift;
    my $self = {
       Transport => Vici::Transport->new($socket),
    };
    bless($self, $class);
    return $self;
}

sub request {
    my ($self, $command, $data) = @_;
    my $request = pack('CC/a*a*', CMD_REQUEST, $command, $data);
    $self->{'Transport'}->send($request);

    my $response = $self->{'Transport'}->receive();
    my ($type, $msg) = unpack('Ca*', $response);

	switch ($type)
    {
        case CMD_RESPONSE
        {
            return $msg
        }
        case CMD_UNKNOWN
        {
            die "unknown command '", $command, "'\n"
        }
        else
        {
            die "invalid response type\n"
        }
    }; 
}

sub register {
    my ($self, $event) = @_;
    my $request = pack('CC/a*a*', EVENT_REGISTER, $event);
    $self->{'Transport'}->send($request);

    my $response = $self->{'Transport'}->receive();
    my ($type, $data) = unpack('Ca*', $response);

	switch ($type)
    {
        case EVENT_CONFIRM
        {
            return
        }
        case EVENT_UNKNOWN
        {
            die "unknown event '", $event, "'\n"
        }
        else
        {
            die "invalid response type\n"
        }
    }; 
}

sub unregister {
    my ($self, $event) = @_;
    my $request = pack('CC/a*a*', EVENT_UNREGISTER, $event);
    $self->{'Transport'}->send($request);

    my $response = $self->{'Transport'}->receive();
    my ($type, $data) = unpack('Ca*', $response);

	switch ($type)
    {
        case EVENT_CONFIRM
        {
            return
        }
        case EVENT_UNKNOWN
        {
            die "unknown event '", $event, "'\n"
        }
        else
        {
            die "invalid response type\n"
        }
    }; 
}

sub streamed_request {
    my ($self, $command, $event, $data) = @_;
    $self->register($event);

    my $request = pack('CC/a*a*', CMD_REQUEST, $command, $data);
    $self->{'Transport'}->send($request);
    my $more = 1;
    my $msg = "";

	while ($more)
	{
        my $response = $self->{'Transport'}->receive();
        my ($type, $data) = unpack('Ca*', $response);

        switch ($type)
        {
            case EVENT
            {
               (my $event_name, $data) = unpack('C/a*a*', $data);
               if ($event_name == $event)
               {
                   $msg .= $data;
               }
            }
            case CMD_RESPONSE
            {
                $self->unregister($event);
                $more = 0;
            }
            else
            {
                $self->unregister($event);
                die "invalid response type\n";
            }
        }
    }
    return $msg;
}

1;


