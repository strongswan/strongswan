import asyncio
import struct
import socket

from vici.protocol import Transport


class AsyncTransport(Transport):
    def __init__(self, sock, path):
        super().__init__(sock)
        self.path = path

    async def connect(self):
        await asyncio.get_event_loop().sock_connect(
            self.socket, self.path)

    async def send(self, packet):
        await asyncio.get_event_loop().sock_sendall(
            self.socket,
            struct.pack("!I", len(packet)) + packet
        )

    async def receive(self):
        raw_length = await self._recvall(self.HEADER_LENGTH)
        length, = struct.unpack("!I", raw_length)
        payload = await self._recvall(length)
        return payload

    async def _recvall(self, count):
        data = b""
        while len(data) < count:
            buf = await asyncio.get_event_loop().sock_recv(
                self.socket, count - len(data))
            if not buf:
                raise socket.error('Connection closed')
            data += buf
        return data
