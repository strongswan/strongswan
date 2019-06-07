#!/usr/bin/env python

import vici
import daemon
import logging
from logging.handlers import SysLogHandler
import subprocess


logger = logging.getLogger('updownLogger')
handler = SysLogHandler(address='/dev/log', facility=SysLogHandler.LOG_DAEMON)
handler.setFormatter(logging.Formatter('charon-updown: %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def handle_interfaces(ike_sa, up):
    if_id_in = int(ike_sa['if-id-in'], 16)
    if_id_out = int(ike_sa['if-id-out'], 16)
    ifname_in = "xfrm-{}-in".format(if_id_in)
    ifname_out = "xfrm-{}-out".format(if_id_out)

    if up:
        logger.info("add XFRM interfaces %s and %s", ifname_in, ifname_out)
        subprocess.call(["/usr/local/libexec/ipsec/xfrmi", "-n", ifname_out,
                         "-i", str(if_id_out), "-d", "eth0"])
        subprocess.call(["/usr/local/libexec/ipsec/xfrmi", "-n", ifname_in,
                         "-i", str(if_id_in), "-d", "eth0"])
        subprocess.call(["ip", "link", "set", ifname_out, "up"])
        subprocess.call(["ip", "link", "set", ifname_in, "up"])
        subprocess.call(["iptables", "-A", "FORWARD", "-o", ifname_out,
                         "-j", "ACCEPT"])
        subprocess.call(["iptables", "-A", "FORWARD", "-i", ifname_in,
                         "-j", "ACCEPT"])

    else:
        logger.info("delete XFRM interfaces %s and %s", ifname_in, ifname_out)
        subprocess.call(["iptables", "-D", "FORWARD", "-o", ifname_out,
                         "-j", "ACCEPT"])
        subprocess.call(["iptables", "-D", "FORWARD", "-i", ifname_in,
                         "-j", "ACCEPT"])
        subprocess.call(["ip", "link", "del", ifname_out])
        subprocess.call(["ip", "link", "del", ifname_in])


def install_routes(ike_sa):
    if_id_out = int(ike_sa['if-id-out'], 16)
    ifname_out = "xfrm-{}-out".format(if_id_out)
    child_sa = next(ike_sa["child-sas"].itervalues())

    for ts in child_sa['remote-ts']:
        logger.info("add route to %s via %s", ts, ifname_out)
        subprocess.call(["ip", "route", "add", ts, "dev", ifname_out])


# daemonize and run parallel to the IKE daemon
with daemon.DaemonContext():
    logger.debug("starting Python updown listener")
    try:
        session = vici.Session()
        ver = session.version()
        logger.info("connected to {daemon} {version} ({sysname}, {release}, "
                    "{machine})".format(**ver))
    except:
        logger.error("failed to get status via vici")
        sys.exit(1)

    try:
        for label, event in session.listen(["ike-updown", "child-updown"]):
            logger.debug("received event: %s %s", label, repr(event))

            name = next((x for x in iter(event) if x != "up"))
            up = event.get("up", "") == "yes"
            ike_sa = event[name]

            if label == "ike-updown":
                handle_interfaces(ike_sa, up)

            elif label == "child-updown" and up:
                install_routes(ike_sa)

    except IOError:
        logger.error("daemon disconnected")
    except:
        logger.error("exception while listening for events " +
                     repr(sys.exc_info()[1]))
