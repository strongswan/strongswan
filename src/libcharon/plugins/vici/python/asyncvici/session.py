import socket

from vici.exception import SessionException
from vici.exception import CommandException
from vici.exception import EventUnknownException
from vici.protocol import Packet, Message

from .command_wrappers import AsyncCommandWrappers
from .protocol import AsyncTransport


class AsyncSession(AsyncCommandWrappers):
    def __init__(self, sock=None, path="/var/run/charon.vici"):
        if sock is None:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.setblocking(False)
        self.transport = AsyncTransport(sock, path)

    async def connect(self):
        await self.transport.connect()

    def close(self):
        self.transport.close()

    async def _communicate(self, packet):
        await self.transport.send(packet)
        return Packet.parse(await self.transport.receive())

    async def _register_unregister(self, event_type, register):
        if register:
            packet = Packet.register_event(event_type)
        else:
            packet = Packet.unregister_event(event_type)
        response = await self._communicate(packet)
        if response.response_type == Packet.EVENT_UNKNOWN:
            raise EventUnknownException(
                "Unknown event type '{event}'".format(event=event_type)
            )
        elif response.response_type != Packet.EVENT_CONFIRM:
            raise SessionException(
                "Unexpected response type {type}, "
                "expected '{confirm}' (EVENT_CONFIRM)".format(
                    type=response.response_type,
                    confirm=Packet.EVENT_CONFIRM,
                )
            )

    async def request(self, command, message=None):
        if message is not None:
            message = Message.serialize(message)
        packet = Packet.request(command, message)
        response = await self._communicate(packet)

        if response.response_type != Packet.CMD_RESPONSE:
            raise SessionException(
                "Unexpected response type {type}, "
                "expected '{response}' (CMD_RESPONSE)".format(
                    type=response.response_type,
                    response=Packet.CMD_RESPONSE
                )
            )

        command_response = Message.deserialize(response.payload)
        if "success" in command_response:
            if command_response["success"] != b"yes":
                raise CommandException(
                    "Command failed: {errmsg}".format(
                        errmsg=command_response["errmsg"].decode("UTF-8")
                    )
                )

        return command_response

    async def streamed_request(self, command, event_stream_type, message=None):
        if message is not None:
            message = Message.serialize(message)

        await self._register_unregister(event_stream_type, True)

        try:
            packet = Packet.request(command, message)
            await self.transport.send(packet)
            exited = False
            while True:
                response = Packet.parse(await self.transport.receive())
                if response.response_type == Packet.EVENT:
                    if not exited:
                        try:
                            yield Message.deserialize(response.payload)
                        except GeneratorExit:
                            exited = True
                else:
                    break

            if response.response_type == Packet.CMD_RESPONSE:
                command_response = Message.deserialize(response.payload)
            else:
                raise SessionException(
                    "Unexpected response type {type}, "
                    "expected '{response}' (CMD_RESPONSE)".format(
                        type=response.response_type,
                        response=Packet.CMD_RESPONSE
                    )
                )

        finally:
            await self._register_unregister(event_stream_type, False)

        # evaluate command result, if any
        if "success" in command_response:
            if command_response["success"] != b"yes":
                raise CommandException(
                    "Command failed: {errmsg}".format(
                        errmsg=command_response["errmsg"].decode("UTF-8")
                    )
                )

    async def listen(self, event_types):
        for event_type in event_types:
            await self._register_unregister(event_type, True)

        try:
            while True:
                response = Packet.parse(await self.transport.receive())
                if response.response_type == Packet.EVENT:
                    try:
                        msg = Message.deserialize(response.payload)
                        yield response.event_type, msg
                    except GeneratorExit:
                        break

        finally:
            for event_type in event_types:
                await self._register_unregister(event_type, False)

    async def __aenter__(self):
        try:
            await self.connect()
        except Exception:
            self.close()
            raise
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        self.close()
