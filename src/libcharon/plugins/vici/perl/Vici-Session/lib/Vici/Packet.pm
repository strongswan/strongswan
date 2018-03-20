package Vici::Packet;

our $VERSION = '0.9';

use strict;
use Vici::Message;
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
    my ($self, $command, $vars) = @_;
    my $out = defined $vars ? $vars->encode() : '';
    my $request = pack('CC/a*a*', CMD_REQUEST, $command, $out);
    return (0, 'could not send data')
        unless defined $self->{'Transport'}->send($request);

    my $response = $self->{'Transport'}->receive();
    return Vici::Message->new({
        errmsg  => 'could not get data',
        success => 'no'
    }) unless $response;

    my ($type, $data) = unpack('Ca*', $response);

    if ( $type == CMD_RESPONSE )
    {
        return Vici::Message->from_data($data);
    }
    elsif ( $type == CMD_UNKNOWN )
    {
        return Vici::Message->new({
            errmsg  => 'unknown command: '. $command,
            success => 'no'
        });
    }
    else
    {
        return Vici::Message->new({
            errmsg  => 'invalid response type',
            success => 'no'
        });
    }
}

sub register {
    my ($self, $event) = @_;
    my $request = pack('CC/a*a*', EVENT_REGISTER, $event);
    return (0, 'could not send data')
        unless defined $self->{'Transport'}->send($request);

    my $response = $self->{'Transport'}->receive();
    return (0, 'could not get data') unless $response;
    my ($type, $data) = unpack('Ca*', $response);

    if ( $type == EVENT_CONFIRM )
    {
        return (1, undef);
    }
    elsif ( $type == EVENT_UNKNOWN )
    {
        return (0, "unknown event '${event}'");
    }
    else
    {
        return (0, 'invalid response type');
    }
}

sub unregister {
    my ($self, $event) = @_;
    my $request = pack('CC/a*a*', EVENT_UNREGISTER, $event);
    return (0, 'could not send data')
        unless defined $self->{'Transport'}->send($request);

    my $response = $self->{'Transport'}->receive();
    return (0, 'could not get data') unless $response;
    my ($type, $data) = unpack('Ca*', $response);

    if ( $type == EVENT_CONFIRM )
    {
        return (1, undef);
    }
    elsif ( $type == EVENT_UNKNOWN )
    {
        return (0, "unknown event '${event}'");
    }
    else
    {
        return (0, 'invalid response type');
    }
}

sub streamed_request {
    my ($self, $command, $event, $vars) = @_;
    my $out = defined $vars ? $vars->encode() : '';

    my ($success, $errmsg) = $self->register($event);
    return ([], $errmsg) unless $success;

    my $request = pack('CC/a*a*', CMD_REQUEST, $command, $out);
    return (0, 'could not send data')
        unless defined $self->{'Transport'}->send($request);

    my $more = 1;
    my @list = ();

    while ($more)
    {
        my $response = $self->{'Transport'}->receive();
        unless ($response) {
            $self->unregister($event);
            $errmsg = 'could not get data';
            $more = 0;
            next;
        }
        my ($type, $data) = unpack('Ca*', $response);

        if ( $type == EVENT )
        {
           (my $event_name, $data) = unpack('C/a*a*', $data);

           if ($event_name eq $event)
           {
               my $msg = Vici::Message->from_data($data);
               push(@list, $msg);
           }
        }
        elsif ( $type == CMD_RESPONSE )
        {
            ($success, $errmsg) = $self->unregister($event);
            $more = 0;
        }
        else
        {
            $self->unregister($event);
            $errmsg = 'invalid response type';
        }
    }
    return (\@list, $errmsg);
}

1;
__END__
=head1 NAME

Vici::Packet - Perl extension for sending and receiving strongSwan VICI packets

=head1 SYNOPSIS

  use Vici::Packet;

=head1 DESCRIPTION

The Vici::Packet module is needed by the Vici::Session module to send and
receive packets used in the communication with the open source strongSwan IPsec
daemon (https://www.strongswan.com) via the documented Versatile IKE
Configuration Interface (VICI). VICI allows the configuration, management and
monitoring of multiple IPsec connections.

=head2 EXPORT

None by default.

=head1 SEE ALSO

strongSwan Wiki:  https://wiki.strongswan.org/projects/strongswan/wiki/Vici

strongSwan Mailing list:  users@lists.strongswan.org

=head1 AUTHOR

Andreas Steffen, E<lt>andreas.steffen@strongswan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2015 by Andreas Steffen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

=cut
