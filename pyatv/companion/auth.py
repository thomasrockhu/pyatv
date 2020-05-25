"""Device pairing and derivation of encryption keys.

THIS IS PROTOTYPE AND DOES NOT WORK!
"""

import logging
from enum import Enum
from collections import namedtuple

from pyatv.companion import opack
from pyatv.support import log_binary, tlv8

_LOGGER = logging.getLogger(__name__)

Frame = namedtuple("Frame", "type data")


class FrameType(Enum):
    """Frame type values."""

    Unknown = 0
    NoOp = 1
    PS_Start = 3
    PS_Next = 4
    PV_Start = 5
    PV_Next = 6
    U_OPACK = 7
    E_OPACK = 8
    P_OPACK = 9
    PA_Req = 10
    PA_Rsp = 11
    SessionStartRequest = 16
    SessionStartResponse = 17
    SessionData = 18
    FamilyIdentityRequest = 32
    FamilyIdentityResponse = 33
    FamilyIdentityUpdate = 34


def decode_frame(data: bytes):
    """Decode a frame from bytes."""
    frame_type = FrameType(data[0])
    length = (data[1] << 16) | (data[2] << 8) | data[3]
    payload, _ = opack.unpack(data[4 : 4 + length])
    payload["_pd"] = tlv8.read_tlv(payload["_pd"])
    return Frame(frame_type, payload), data[4 + length :]


def encode_frame(frame_type: FrameType, data: bytes):
    """Encode a frame as bytes."""
    payload = opack.pack(data)
    header = bytes([frame_type.value]) + len(payload).to_bytes(3, byteorder="big")
    return header + payload


class CompanionPairingProcedure:
    """Perform pairing and return new credentials."""

    def __init__(self, connection, srp):
        """Initialize a new MrpPairingHandler."""
        self.connection = connection
        self.srp = srp
        self._atv_salt = None
        self._atv_pub_key = None

    # TODO: Should not be here
    async def _send_and_receive(self, frame_type, message):
        frame = encode_frame(frame_type, message)
        self.connection.send(frame)
        resp = await self.connection.read()
        return decode_frame(resp)[0]

    async def start_pairing(self):
        """Start pairing procedure."""
        self.srp.initialize()

        await self.connection.connect()

        msg = {
            "_pd": tlv8.write_tlv({tlv8.TLV_METHOD: b"\x00", tlv8.TLV_SEQ_NO: b"\x01"}),
            "_pwTy": 1,
        }
        resp = await self._send_and_receive(FrameType.PS_Start, msg)

        pairing_data = resp.data["_pd"]
        self._atv_salt = pairing_data[tlv8.TLV_SALT]
        self._atv_pub_key = pairing_data[tlv8.TLV_PUBLIC_KEY]
        log_binary(
            _LOGGER,
            "Got pub key and salt",
            Salt=self._atv_salt,
            PubKey=self._atv_pub_key,
        )

    async def finish_pairing(self, pin):
        """Finish pairing process."""
        self.srp.step1(pin)

        pub_key, proof = self.srp.step2(self._atv_pub_key, self._atv_salt)

        msg = {
            "_pd": tlv8.write_tlv(
                {
                    tlv8.TLV_SEQ_NO: b"\x03",
                    tlv8.TLV_PUBLIC_KEY: pub_key,
                    tlv8.TLV_PROOF: proof,
                }
            ),
            "_pwTy": 1,
        }

        resp = await self._send_and_receive(FrameType.PS_Next, msg)

        pairing_data = resp.data["_pd"]
        atv_proof = pairing_data[tlv8.TLV_PROOF]
        log_binary(_LOGGER, "Device", Proof=atv_proof)

        encrypted_data = self.srp.step3()
        msg = {
            "_pd": {tlv8.TLV_SEQ_NO: b"\x05", tlv8.TLV_ENCRYPTED_DATA: encrypted_data}
        }
        resp = await self._send_and_receive(FrameType.PS_Next, msg)

        pairing_data = resp.data["_pd"]
        encrypted_data = pairing_data[tlv8.TLV_ENCRYPTED_DATA]

        return self.srp.step4(encrypted_data)
