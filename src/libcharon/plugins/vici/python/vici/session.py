import collections

from .exception import SessionException
from .protocol import Transport, Packet, Message


CommandResult = collections.namedtuple(
    "CommandResult",
    ["success", "errmsg", "log"]
)


class Session(object):
    def __init__(self, address="/var/run/charon.vici"):
        self.handler = SessionHandler(Transport(address))

    def version(self):
        """Retrieve daemon and system specific version information.

        :return: daemon and system specific version information
        :rtype: dict
        """
        return self.handler.request("version")

    def stats(self):
        """Retrieve IKE daemon statistics and load information.

        :return: IKE daemon statistics and load information
        :rtype: dict
        """
        return self.handler.request("stats")

    def reload_settings(self):
        """Reload strongswan.conf settings and any plugins supporting reload.

        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("reload-settings"))

    def initiate(self, sa):
        """Initiate an SA.

        :param sa: the SA to initiate
        :type sa: dict
        :return: logs emitted by command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        response = self.handler.streamed_request("initiate", "control-log", sa)
        return self._result(*response)

    def terminate(self, sa):
        """Terminate an SA.

        :param sa: the SA to terminate
        :type sa: dict
        :return: logs emitted by command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        response = self.handler.streamed_request("terminate", "control-log", sa)
        return self._result(*response)

    def install(self, policy):
        """Install a trap, drop or bypass policy defined by a CHILD_SA config.

        :param policy: policy to install
        :type policy: dict
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("install", policy))

    def uninstall(self, policy):
        """Uninstall a trap, drop or bypass policy defined by a CHILD_SA config.

        :param policy: policy to uninstall
        :type policy: dict
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("uninstall", policy))

    def list_sas(self, filters=None):
        """Retrieve active IKE_SAs and associated CHILD_SAs.

        :param filters: retrieve only matching IKE_SAs (optional)
        :type filters: dict
        :return: list of active IKE_SAs and associated CHILD_SAs
        :rtype: list
        """
        _, sa_list = self.handler.streamed_request("list-sas",
                                                   "list-sa", filters)
        return sa_list

    def list_policies(self, filters=None):
        """Retrieve installed trap, drop and bypass policies.

        :param filters: retrieve only matching policies (optional)
        :type filters: dict
        :return: list of installed trap, drop and bypass policies
        :rtype: list
        """
        _, policy_list = self.handler.streamed_request("list-policies",
                                                       "list-policy", filters)
        return policy_list

    def list_conns(self, filters=None):
        """Retrieve loaded connections.

        :param filters: retrieve only matching configuration names (optional)
        :type filters: dict
        :return: list of connections
        :rtype: list
        """
        _, connection_list = self.handler.streamed_request("list-conns",
                                                           "list-conn", filters)
        return connection_list

    def get_conns(self):
        """Retrieve connection names loaded exclusively over vici.

        :return: connection names
        :rtype: dict
        """
        return self.handler.request("get-conns")

    def list_certs(self, filters=None):
        """Retrieve loaded certificates.

        :param filters: retrieve only matching certificates (optional)
        :type filters: dict
        :return: list of installed trap, drop and bypass policies
        :rtype: list
        """
        _, cert_list = self.handler.streamed_request("list-certs",
                                                     "list-cert", filters)
        return cert_list

    def load_conn(self, connection):
        """Load a connection definition into the daemon.

        :param connection: connection definition
        :type connection: dict
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("load-conn", connection))

    def unload_conn(self, name):
        """Unload a connection definition.

        :param name: connection definition name
        :type name: dict
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("unload-conn", name))

    def load_cert(self, certificate):
        """Load a certificate into the daemon.

        :param certificate: PEM or DER encoded certificate
        :type certificate: dict
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("load-cert", certificate))

    def load_key(self, private_key):
        """Load a private key into the daemon.

        :param private_key: PEM or DER encoded key
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("load-key", private_key))

    def load_shared(self, secret):
        """Load a shared IKE PSK, EAP or XAuth secret into the daemon.

        :param secret: shared IKE PSK, EAP or XAuth secret
        :type secret: dict
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("load-shared", secret))

    def clear_creds(self):
        """Clear credentials loaded over vici.

        Clear all loaded certificate, private key and shared key credentials.
        This affects only credentials loaded over vici, but additionally
        flushes the credential cache.

        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("clear-creds"))

    def load_pool(self, pool):
        """Load a virtual IP pool.

        Load an in-memory virtual IP and configuration attribute pool.
        Existing pools with the same name get updated, if possible.

        :param pool: virtual IP and configuration attribute pool
        :type pool: dict
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("load-pool", pool))

    def unload_pool(self, pool_name):
        """Unload a virtual IP pool.

        Unload a previously loaded virtual IP and configuration attribute pool.
        Unloading fails for pools with leases currently online.

        :param pool_name: pool by name
        :type pool_name: dict
        :return: result of command, with `errmsg` given on failure
        :rtype: :py:class:`vici.session.CommandResult`
        """
        return self._result(self.handler.request("unload-pool", pool_name))

    def get_pools(self):
        """Retrieve loaded pools.

        :return: loaded pools
        :rtype: dict
        """
        return self.handler.request("get-pools")

    def _result(self, command_response, log=None):
        """Create a CommandResult for a request response.

        :param command_response: command request response
        :type command_response: dict
        :param log: list of log messages (optional)
        :type log: list
        :return: a CommandResult containing any given log messages
        :rtype: :py:class:`vici.session.CommandResult`
        """
        if command_response["success"] == "yes":
            return CommandResult(True, None, log)
        else:
            return CommandResult(False, command_response["errmsg"], log)


class SessionHandler(object):
    """Handles client command execution requests over vici."""

    def __init__(self, transport):
        self.transport = transport
        self.log_events = collections.deque()

    def _communicate(self, packet):
        """Send packet over transport and parse response.

        :param packet: packet to send
        :type packet: :py:class:`vici.protocol.Packet`
        :return: parsed packet in a tuple with message type and payload
        :rtype: :py:class:`collections.namedtuple`
        """
        self.transport.send(packet)
        return self._read()

    def request(self, command, message=None):
        """Send command request with an optional message.

        :param command: command to send
        :type command: str
        :param message: message (optional)
        :type message: str
        :return: command result
        :rtype: dict
        """
        if message is not None:
            message = Message.serialize(message)
        packet = Packet.request(command, message)
        response = self._communicate(packet)

        if response.response_type != Packet.CMD_RESPONSE:
            raise SessionException(
                "Unexpected response type {type}, "
                "expected '{response}' (CMD_RESPONSE)".format(
                    type=response.response_type,
                    response=Packet.CMD_RESPONSE
                )
            )

        return Message.deserialize(response.payload)

    def streamed_request(self, command, event_stream_type, message=None):
        """Send command request and collect and return all emitted events.

        :param command: command to send
        :type command: str
        :param event_stream_type: event type emitted on command execution
        :type event_stream_type: str
        :param message: message (optional)
        :type message: str
        :return: a pair of the command result and a list of emitted events
        :rtype: tuple
        """
        result = []

        if message is not None:
            message = Message.serialize(message)

        # subscribe to event stream
        packet = Packet.register_event(event_stream_type)
        response = self._communicate(packet)

        if response.response_type != Packet.EVENT_CONFIRM:
            raise SessionException(
                "Unexpected response type {type}, "
                "expected '{confirm}' (EVENT_CONFIRM)".format(
                    type=response.response_type,
                    confirm=Packet.EVENT_CONFIRM,
                )
            )

        # issue command, and read any event messages
        packet = Packet.request(command, message)
        self.transport.send(packet)
        response = self._read()
        while response.response_type == Packet.EVENT:
            result.append(Message.deserialize(response.payload))
            response = self._read()

        if response.response_type == Packet.CMD_RESPONSE:
            response_message = Message.deserialize(response.payload)
        else:
            raise SessionException(
                "Unexpected response type {type}, "
                "expected '{response}' (CMD_RESPONSE)".format(
                    type=response.response_type,
                    response=Packet.CMD_RESPONSE
                )
            )

        # unsubscribe from event stream
        packet = Packet.unregister_event(event_stream_type)
        response = self._communicate(packet)
        if response.response_type != Packet.EVENT_CONFIRM:
            raise SessionException(
                "Unexpected response type {type}, "
                "expected '{confirm}' (EVENT_CONFIRM)".format(
                    type=response.response_type,
                    confirm=Packet.EVENT_CONFIRM,
                )
            )

        return (response_message, result)

    def _read(self):
        """Get next packet from transport.

        :return: parsed packet in a tuple with message type and payload
        :rtype: :py:class:`collections.namedtuple`
        """
        raw_response = self.transport.receive()
        response = Packet.parse(raw_response)

        # FIXME
        if response.response_type == Packet.EVENT and response.event_type == "log":
            # queue up any debug log messages, and get next
            self.log_events.append(response)
            # do something?
            self._read()
        else:
            return response
