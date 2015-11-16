package Vici::Session;

require Exporter;

our @ISA = qw(Exporter);
our @EXPORT = qw(new, version, stats, reload_settings, initiate, list_sas,
                 list_policies, list_conns, get_conns, list_certs,
                 list_authorities, get_authorities, get_pools);
our @VERSION = 0.9;

use strict;
use Vici::Packet;
use Vici::Message;

sub new {
    my $class = shift;
    my $socket = shift;
    my $self = {
        Packet => Vici::Packet->new($socket),
    };
    bless($self, $class);
    return $self;
}

sub version {
    my $self = shift;
    my $data = $self->{'Packet'}->request('version');
    return Vici::Message->from_data($data);
}

sub stats {
    my $self = shift;
    my $data = $self->{'Packet'}->request('stats');
    return Vici::Message->from_data($data);
}

sub reload_settings {
    my $self = shift;
    my $data = $self->{'Packet'}->request('reload-settings');
    my $msg = Vici::Message->from_data($data);
    my $res = $msg->hash();
    return $res->{'success'} == 'yes';
}

sub initiate {
    my ($self, $msg) = @_;
    my $vars = '';
    if (defined $msg)
    {
        $vars = $msg->encode();
    }
    my $data = $self->{'Packet'}->request('initiate', $vars);
    my $msg = Vici::Message->from_data($data);
    my $res = $msg->hash();
    return $res->{'success'} == 'yes';
}

sub list_sas {
    my ($self, $msg) = @_;
    my $vars = '';
    if (defined $msg)
    {
        $vars = $msg->encode();
    }
    my $data = $self->{'Packet'}->streamed_request('list-sas',
                                                   'list-sa', $vars);
    return Vici::Message->from_data($data);
}

sub list_policies {
    my $self = shift;
    my $data = $self->{'Packet'}->streamed_request('list-policies',
                                                   'list-policy');
    return Vici::Message->from_data($data);
}

sub list_conns {
    my ($self, $msg) = @_;
    my $vars = '';
    if (defined $msg)
    {
        $vars = $msg->encode();
    }
    my $data = $self->{'Packet'}->streamed_request('list-conns',
                                                   'list-conn', $vars);
    return Vici::Message->from_data($data);
}

sub get_conns {
    my $self = shift;
    my $data = $self->{'Packet'}->request('get-conns');
    return Vici::Message->from_data($data);
}

sub list_certs {
    my ($self, $msg) = @_;
    my $vars = '';
    if (defined $msg)
    {
        $vars = $msg->encode();
    }
    my $data = $self->{'Packet'}->streamed_request('list-authorities',
                                                   'list-authority', $vars);
    return Vici::Message->from_data($data);
}

sub list_authorities {
    my $self = shift;
    my $data = $self->{'Packet'}->streamed_request('list-authorities',
                                                   'list-authority');
    return Vici::Message->from_data($data);
}

sub get_authorities {
    my $self = shift;
    my $data = $self->{'Packet'}->request('get-authorities');
    return Vici::Message->from_data($data);
}

sub get_pools {
    my $self = shift;
    my $data = $self->{'Packet'}->request('get-pools');
    return Vici::Message->from_data($data);
}

1;
