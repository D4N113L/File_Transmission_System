import struct

def get_payload_size(header):
    return struct.unpack('<I', header[19:23])[0]

class RequestPacketUnpacker:
    def __init__(self, data):
        self.data = data
        self.packet = {}
        self.unpack_general()

    def unpack_general(self):
        # Unpack the general packet fields
        self.packet['client_id'] = self.data[:16]
        self.packet['version'] = self.data[16]
        self.packet['code'] = struct.unpack('<H', self.data[17:19])[0]
        self.packet['payload_size'] = struct.unpack('<I', self.data[19:23])[0]
        self.packet['payload'] = self.data[23:23+self.packet['payload_size']]

    def unpack(self):
        code = self.packet['code']
        if code == 825:
            return self.unpack_registration()
        elif code == 826:
            return self.unpack_public_key()
        elif code == 827:
            return self.unpack_reconnection()
        elif code == 828:
            return self.unpack_file_send()
        elif code in [900, 901, 902]:
            return self.unpack_crc()
        else:
            raise ValueError(f"Unsupported packet code: {code}")

    def unpack_registration(self):
        # Payload contains only a name (255 bytes max, with null termination)
        name = self.packet['payload'].split(b'\x00', 1)[0].decode('ascii')
        return {'code': self.packet['code'], 'client_id':self.packet['client_id'], 'name': name}

    def unpack_public_key(self):
        # Payload contains name (255 bytes) + public key (160 bytes)
        name = self.packet['payload'][:255].split(b'\x00', 1)[0].decode('ascii')
        public_key = self.packet['payload'][255:255+160]
        return {'code': self.packet['code'], 'client_id':self.packet['client_id'], 'name': name, 'public_key': public_key}

    def unpack_reconnection(self):
        # Payload contains only a name (255 bytes max, with null termination)
        name = self.packet['payload'].split(b'\x00', 1)[0].decode('ascii')
        return {'code': self.packet['code'], 'client_id':self.packet['client_id'], 'name': name}

    def unpack_file_send(self):
        # Payload structure: content size (4 bytes), original file size (4 bytes),
        # packet number and total packets (4 bytes), file name (255 bytes), message content
        content_size = struct.unpack('<I', self.packet['payload'][:4])[0]
        original_size = struct.unpack('<I', self.packet['payload'][4:8])[0]
        total_packets, packet_number = struct.unpack('<HH', self.packet['payload'][8:12])
        file_name = self.packet['payload'][12:267].split(b'\x00', 1)[0].decode('ascii')
        message_content = self.packet['payload'][267:]
        return {
            'code': self.packet['code'], 
            'client_id':self.packet['client_id'],
            'content_size': content_size,
            'original_size': original_size,
            'packet_number': packet_number,
            'total_packets': total_packets,
            'file_name': file_name,
            'message_content': message_content
        }

    def unpack_crc(self):
        # Payload contains only the file name (255 bytes max, with null termination)
        file_name = self.packet['payload'].split(b'\x00', 1)[0].decode('ascii')
        return {'code': self.packet['code'], 'client_id':self.packet['client_id'], 'file_name': file_name}
    
def getFileMetadata(packet):
        file_name = packet['file_name'].split("\\")[-1]
        total_packets = packet['total_packets']
        enc_file_size = packet['content_size']
        file_size = packet['original_size']
        enc_file_content = packet['message_content']
        return file_name, total_packets, enc_file_size, file_size, enc_file_content
