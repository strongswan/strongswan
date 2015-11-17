package Vici::Session;

require Exporter;
use AutoLoader qw(AUTOLOAD);

our @ISA = qw(Exporter);
our @EXPORT = qw(
    new, version, stats, reload_settings, initiate, list_sas, list_policies,
    list_conns, get_conns, list_certs, list_authorities, get_authorities,
    get_pools
);
our $VERSION = '0.9';

use strict;
use warnings;
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
__END__
=head1 NAME

Vici::Session - Perl binding for the strongSwan VICI configuration interface

=head1 SYNOPSIS

  use Vici::Session;

=head1 DESCRIPTION

The Vici::Session module allows a Perl script to communicate with the open
source strongSwan IPsec daemon (https://www.strongswan.com) via the documented
Versatile IKE Configuration Interface (VICI). VICI allows the configuration,
management and monitoring of multiple IPsec connections.

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
