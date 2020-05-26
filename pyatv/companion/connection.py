"""Connection abstraction for Companion protocol."""
import asyncio
import logging

from pyatv.support import log_binary

_LOGGER = logging.getLogger(__name__)


# TODO: Temporary solution for a connection
class CompanionConnection(asyncio.Protocol):
    """Remote connection to a Companion device."""

    def __init__(self, loop, host, port):
        """Initialize a new CompanionConnection instance."""
        self.loop = loop
        self.host = str(host)
        self.port = port
        self.transport = None
        self.semaphore = asyncio.Semaphore(value=0)
        self.buffer = b""

    async def connect(self):
        """Connect to device."""
        _LOGGER.debug("Connecting to Companion client")
        await self.loop.create_connection(lambda: self, self.host, self.port)

    def close(self):
        """Close connection to device."""
        _LOGGER.debug("Closing connection")
        if self.transport:
            self.transport.close()
        self.transport = None

    def send(self, data):
        """Send data to companion."""
        log_binary(_LOGGER, "Send data", Data=data)
        self.transport.write(data)

    async def read(self):
        """Wait for data to be available and return it."""
        await asyncio.wait_for(
            self.semaphore.acquire(), timeout=3,
        )
        buffer = self.buffer
        self.buffer = b""
        return buffer

    def connection_made(self, transport):
        """Handle that connection was eatablished."""
        _LOGGER.debug("Connected to companion device")
        self.transport = transport

    def data_received(self, data):
        """Handle data received from companion."""
        log_binary(_LOGGER, "Received data", Data=data)
        self.buffer += data
        self.semaphore.release()

    def error_received(self, exc):
        """Error received from companion."""
        _LOGGER.debug("Error: %s", exc)

    def connection_lost(self, exc):
        """Handle that connection was lost from companion."""
        _LOGGER.debug("Connection lost: %s", exc)

