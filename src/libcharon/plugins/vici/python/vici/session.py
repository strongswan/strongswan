import collections

from .exception import SessionException
from .protocol import Packet, Message


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
