#include "RequestPacker.h"

// Constructor implementation for RequestPacketPacker
RequestPacketPacker::RequestPacketPacker(const std::vector<uint8_t>& clientId, uint8_t version, uint16_t code, const std::vector<uint8_t>& payload)
    : version(version), code(code), payload(payload) {

    // Validate client ID size (must be 16 bytes)
    if (clientId.size() != 16) {
        throw std::invalid_argument("Client ID must be 16 bytes.");
    }
    std::copy(clientId.begin(), clientId.end(), this->client_id);
}

// pack function implementation for RequestPacketPacker
std::vector<uint8_t> RequestPacketPacker::pack() const {
    std::vector<uint8_t> packet;

    // Pack client ID (16 bytes)
    packet.insert(packet.end(), client_id, client_id + sizeof(client_id));

    // Pack version (1 byte)
    packet.push_back(version);

    // Pack code (2 bytes)
    packet.push_back(code & 0xFF);
    packet.push_back((code >> 8) & 0xFF);

    // Compute payload size dynamically based on the payload length
    uint32_t payloadSize = payload.size();

    // Pack payload size (4 bytes)
    packet.push_back(payloadSize & 0xFF);
    packet.push_back((payloadSize >> 8) & 0xFF);
    packet.push_back((payloadSize >> 16) & 0xFF);
    packet.push_back((payloadSize >> 24) & 0xFF);

    // Pack the payload
    packet.insert(packet.end(), payload.begin(), payload.end());

    return packet;
}

// Constructor implementation for RegistrationPacket
RegistrationPacket::RegistrationPacket(const std::vector<uint8_t>& clientId, uint8_t version, const std::string& name)
    : RequestPacketPacker(clientId, version, 825, {}) {

    if (name.size() > 254) {
        throw std::invalid_argument("Name must be 254 bytes or less (255 with the NULL terminator)");
    }
    std::vector<uint8_t> nameBytes(255, 0); // Initialize with null terminators
    std::copy(name.begin(), name.end(), nameBytes.begin());
    payload = nameBytes;
}

// Constructor implementation for PublicKeyPacket
PublicKeyPacket::PublicKeyPacket(const std::vector<uint8_t>& clientId, uint8_t version, const std::string& name, const std::string& publicKey)
    : RequestPacketPacker(clientId, version, 826, {}) {

    if (name.size() > 254) {
        throw std::invalid_argument("Name must be 254 bytes or less (255 with the NULL terminator)");
    }
    if (publicKey.size() != 160) {
        throw std::invalid_argument("Public key must be exactly 160 bytes");
    }
    std::vector<uint8_t> nameBytes(255, 0);
    std::copy(name.begin(), name.end(), nameBytes.begin());
    std::vector<uint8_t> publicKeyBytes(160, 0);
    std::copy(publicKey.begin(), publicKey.end(), publicKeyBytes.begin());

    payload.insert(payload.end(), nameBytes.begin(), nameBytes.end());
    payload.insert(payload.end(), publicKeyBytes.begin(), publicKeyBytes.end());
}

// Constructor implementation for ReconnectionPacket
ReconnectionPacket::ReconnectionPacket(const std::vector<uint8_t>& clientId, uint8_t version, const std::string& name)
    : RequestPacketPacker(clientId, version, 827, {}) {

    if (name.size() > 254) {
        throw std::invalid_argument("Name must be 254 bytes or less (255 with the NULL terminator)");
    }
    std::vector<uint8_t> nameBytes(255, 0);
    std::copy(name.begin(), name.end(), nameBytes.begin());
    payload = nameBytes;
}

// Constructor implementation for FileSendPacket
FileSendPacket::FileSendPacket(const std::vector<uint8_t>& clientId, uint8_t version, uint32_t contentSize, uint32_t originalFileSize, uint16_t packetNum, uint16_t totalPackets, const std::string& fileName, const std::vector<uint8_t>& messageContent)
    : RequestPacketPacker(clientId, version, 828, {}) {

    if (fileName.size() > 254) {
        throw std::invalid_argument("File name must be 255 bytes or less (255 with the NULL terminator)");
    }

    // Pack content size (4 bytes) in little-endian
    payload.push_back(contentSize & 0xFF);             // Least significant byte first
    payload.push_back((contentSize >> 8) & 0xFF);
    payload.push_back((contentSize >> 16) & 0xFF);
    payload.push_back((contentSize >> 24) & 0xFF);     // Most significant byte last

    // Pack original file size (4 bytes) in little-endian
    payload.push_back(originalFileSize & 0xFF);        // Least significant byte first
    payload.push_back((originalFileSize >> 8) & 0xFF);
    payload.push_back((originalFileSize >> 16) & 0xFF);
    payload.push_back((originalFileSize >> 24) & 0xFF); // Most significant byte last

    // Pack total packets (2 bytes) in little-endian
    payload.push_back(totalPackets & 0xFF);            // Least significant byte first
    payload.push_back((totalPackets >> 8) & 0xFF);     // Most significant byte last

    // Pack packet number (2 bytes) in little-endian
    payload.push_back(packetNum & 0xFF);               // Least significant byte first
    payload.push_back((packetNum >> 8) & 0xFF);        // Most significant byte last

    // Pack file name (255 bytes)
    std::vector<uint8_t> fileNameBytes(255, 0);
    std::copy(fileName.begin(), fileName.end(), fileNameBytes.begin());
    payload.insert(payload.end(), fileNameBytes.begin(), fileNameBytes.end());

    // Pack message content (variable size)
    payload.insert(payload.end(), messageContent.begin(), messageContent.end());
}

// Constructor implementation for CRCPacket
CRCPacket::CRCPacket(const std::vector<uint8_t>& clientId, uint8_t version, uint16_t code, const std::string& fileName)
    : RequestPacketPacker(clientId, version, code, {}) {

    if (fileName.size() > 254) {
        throw std::invalid_argument("File name must be 254 bytes or less (255 with the NULL terminator)");
    }
    std::vector<uint8_t> fileNameBytes(255, 0);
    std::copy(fileName.begin(), fileName.end(), fileNameBytes.begin());
    payload = fileNameBytes;
}
