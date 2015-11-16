package Vici::Transport;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(new, send, receive);
our @VERSION = 0.9;

use strict;

sub new {
    my $class = shift;
    my $self = {
        Socket => shift,
    };
    bless($self, $class);
    return $self;
}

sub send {
    my ($self, $data) = @_;
    my $packet = pack('N/a*', $data);
    $self->{'Socket'}->send($packet);
}

sub receive {
    my $self = shift;
    my $packet_header;
    my $data;

    $self->{'Socket'}->recv($packet_header, 4);
    my $packet_len = unpack('N', $packet_header);
    $self->{'Socket'}->recv($data, $packet_len);
	return $data;
}

1;


