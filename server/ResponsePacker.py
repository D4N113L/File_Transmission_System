import struct

class ResponsePacketPacker:
    def __init__(self, version, code):
        self.version = version
        self.code = code
        self.payload = b""

    def pack(self):
        packet = bytearray()
        # Pack version (1 byte)
        packet.append(struct.pack('<B', self.version)[0])

        # Pack code (2 bytes, little-endian)
        packet.extend(struct.pack('<H', self.code))

        # Compute payload size (4 bytes, little-endian)
        payload_size = len(self.payload)
        packet.extend(struct.pack('<I', payload_size))

        # Append the payload
        packet.extend(self.payload)

        return bytes(packet)

class RegistrationSucceededPacker(ResponsePacketPacker):
    def __init__(self, version, client_id):
        super().__init__(version, 1600)
        # Payload is client_id (16 bytes)
        self.payload = client_id

class RegistrationFailedPacker(ResponsePacketPacker):
    def __init__(self, version):
        super().__init__(version, 1601)

class EncryptedAESKeyRegistrationPacker(ResponsePacketPacker):
    def __init__(self, version, client_id, encrypted_aes_key):
        super().__init__(version, 1602)
        # Payload is client_id (16 bytes) + encrypted_aes_key (variable size)
        self.payload = client_id + encrypted_aes_key

class FileReceivedPacker(ResponsePacketPacker):
    def __init__(self, version, client_id, content_size, file_name, crc):
        super().__init__(version, 1603)
        # Payload is client_id (16 bytes) + content_size (4 bytes) + file_name (255 bytes) + crc (4 bytes)
        padded_file_name = file_name.ljust(255, '\x00').encode('ascii')
        self.payload = client_id + struct.pack('<I', content_size) + padded_file_name + struct.pack('<I', crc)

class AcceptingMessagePacker(ResponsePacketPacker):
    def __init__(self, version, client_id):
        super().__init__(version, 1604)
        # Payload is client_id (16 bytes)
        self.payload = client_id

class EncryptedAESKeyReconnectionPacker(ResponsePacketPacker):
    def __init__(self, version, client_id, encrypted_aes_key):
        super().__init__(version, 1605)
        # Payload is client_id (16 bytes) + encrypted_aes_key (variable size)
        self.payload = client_id + encrypted_aes_key

class ReconnectionDeclinedPacker(ResponsePacketPacker):
    def __init__(self, version, client_id):
        super().__init__(version, 1606)
        # Payload is client_id (16 bytes)
        self.payload = client_id

class GeneralErrorPacker(ResponsePacketPacker):
    def __init__(self, version):
        super().__init__(version, 1607)
