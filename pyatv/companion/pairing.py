"""Device pairing and derivation of encryption keys."""

import asyncio
import logging

from pyatv import exceptions
from pyatv.const import Protocol
from pyatv.interface import PairingHandler
from pyatv.companion.auth import CompanionPairingProcedure
from pyatv.companion.srp import SRPAuthHandler
from pyatv.support import error_handler, log_binary

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


class CompanionPairingHandler(PairingHandler):
    """Pairing handler used to pair the Companion link protocol."""

    def __init__(self, config, session, loop):
        """Initialize a new CompanionPairingHandler."""
        super().__init__(session, config.get_service(Protocol.Companion))
        self.connection = CompanionConnection(loop, config.address, self.service.port)
        self.srp = SRPAuthHandler()
        self.pairing_procedure = CompanionPairingProcedure(self.connection, self.srp)
        self.pin_code = None
        self._has_paired = False

    async def close(self):
        """Call to free allocated resources after pairing."""
        self.connection.close()
        await super().close()

    @property
    def has_paired(self):
        """If a successful pairing has been performed."""
        return self._has_paired

    async def begin(self):
        """Start pairing process."""
        _LOGGER.debug("Start pairing Companion")
        await error_handler(
            self.pairing_procedure.start_pairing, exceptions.PairingError
        )

    async def finish(self):
        """Stop pairing process."""
        _LOGGER.debug("Finish pairing Companion")
        if not self.pin_code:
            raise exceptions.PairingError("no pin given")

        self.service.credentials = str(
            await error_handler(
                self.pairing_procedure.finish_pairing,
                exceptions.PairingError,
                self.pin_code,
            )
        )
        self._has_paired = True

    @property
    def device_provides_pin(self):
        """Return True if remote device presents PIN code, else False."""
        return True

    def pin(self, pin):
        """Pin code used for pairing."""
        self.pin_code = str(pin).zfill(4)
        _LOGGER.debug("Companion PIN changed to %s", self.pin_code)
