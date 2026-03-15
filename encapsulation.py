import typing
import struct

from Demos.mmapfile_demo import offset
from pyasn1.codec.ber.decoder import decode


def layer2_encapsulate(address: int, data: bytes) -> bytes:
    """Encapsulate a PDU of layer 3 into a PDU of layer 2."""
    assert 0x0000 <= address <= 0xffff, "Invalid layer 2 address"
    assert len(data) <= 0xffff, "Too much data for a layer 2 PDU"
    return bytes(struct.pack(">H", address)
                 + struct.pack(">H", len(data))
                 + data)

def layer3_encapsulate(offset: int, data: bytes) -> bytes:
    """Encapsulate a chunk of user data into a PDU of layer 3."""
    assert 0x0000 <= offset <= 0xffff, "Invalid layer 3 offset"
    assert len(data) <= 0xffff, "Too much data for a layer 3 PDU"
    return bytes(struct.pack(">H", offset)
                 + struct.pack(">H", len(data))
                 + data)

def stack_send(data: bytes, output_file: typing.BinaryIO):
    layer3_pdu = layer3_encapsulate(offset=0, data=data)
    layer2_pdu = layer2_encapsulate(address=0xabcd, data=layer3_pdu)
    return layer2_pdu
    #output_file.write(layer2_pdu)

### start my code ###
def layer2_decapsulate (data: bytes) -> (int, bytes):
    destination_addr = int.from_bytes(data[:2], byteorder="big", signed=False)
    payload_len = int.from_bytes(data[2:4], byteorder="big", signed=False)
    payload_l3 = data[4:payload_len+4]
    return destination_addr, payload_l3

def layer3_decapsulate (data: bytes) -> (int, bytes):
    fragment_offset = int.from_bytes(data[:2], byteorder="big", signed=False)
    payload_len = int.from_bytes(data[2:4], byteorder="big", signed=False)
    payload_msg = data[4:payload_len+4].decode("utf-8")
    return fragment_offset, payload_msg

def stack_receive (data: bytes):
    dest, layer3_pdu = layer2_decapsulate(data=data)
    frg_offset, message = layer3_decapsulate(layer3_pdu)
    return message
    

### end ###
if __name__ == '__main__':
    with (open("message.txt", "rb") as input_file,
          open(1, "wb") as output_file):
        payload = input_file.read()
        sent_msg = stack_send(data=payload, output_file=output_file)
        received_msg = stack_receive(sent_msg)
        print(received_msg)
