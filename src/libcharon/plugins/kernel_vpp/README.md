# VPP plugin #

## Overview ##
The kernel-vpp plugin is an interface to the IPsec and networking backend for [**VPP**](https://wiki.fd.io/view/VPPhttps://wiki.fd.io/view/VPP) platform using the [**VPP C API**](https://wiki.fd.io/view/VPP/How_To_Use_The_C_API). It provides address and routing lookup functionality and installs routes for IPsec traffic. It installs and maintains Security Associations and Policies to the [**VPP IPsec**](https://wiki.fd.io/view/VPP/IPSec_and_IKEv2#IPSec).
The socket-vpp plugin is a replacement for socket-default for the VPP. It provides an IPv4/IPv6 IKE socket backend based on the VPP UDP punt socket. The plugin initialize VPP UDP IPv4 and IPv6 punt socket for IKE ports 500 and 4500 (NAT-T IKE). To have VPP punt IKE packets to strongswan, the VPP command `vppctl set punt udp 500 4500` must be executed. Custom port can be specified using the `charon.port` and `charon.port_nat_t` options in `strongswan.conf`. `charon.plugins.socket-vpp.path` configures custom path for read socket. Write socket path is configured in VPP startup configuration `punt { socket <socket_path> }`, VPP returns this path in punt_socket_register API reply. The read socket path and write socket path must be different, otherwise, VPP plugin cannot be loaded properly.

GCM is also supported and VPP must run with DPDK with crypto device or device that support RTE Security.

## How to build strongswan for VPP ##
Install vpp-lib and vpp-dev packages. The plugins are disabled by default and can be enabled by adding:

    --enable-socket-vpp --enable-kernel-vpp

to the ./configure options.

## Example configuration ##
In this scenario VPP and strongSwan is gateway for roadwarriors.

    10.1.0.0/24 -- | 192.168.0.1 | === | x.x.x.x |
    gateway-net        gateway           roadwarrior

VPP config:

    set int state GigabitEthernet0/8/0 up
    set int ip address GigabitEthernet0/8/0 192.168.0.1/24
    set int state GigabitEthernet0/a/0 up
    set int ip address GigabitEthernet0/a/0 10.1.0.1/24

strongSwan config (ipsec.conf):

    config setup
        strictcrlpolicy=no
    
    conn %default
        mobike=no
        ikelifetime=60m
        keylife=20m
        rekeymargin=3m
        keyingtries=1
        keyexchange=ikev2
        authby=secret
    
    conn rw
        left=192.168.0.1
        leftsubnet=10.1.0.0/24
        right=%any
        auto=add

First you need to start VPP and then strongSwan.

