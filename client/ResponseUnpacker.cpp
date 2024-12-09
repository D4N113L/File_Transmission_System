#include "ResponseUnpacker.h"

// Constructor
ResponsePacketUnpacker::ResponsePacketUnpacker(const std::vector<uint8_t>& data) : data(data) {
    unpack_general();
}

// Method to unpack the packet
std::vector<std::string> ResponsePacketUnpacker::unpack() {
    std::vector<std::string> result;

    result.push_back("Version: " + std::to_string(packet.version));
    result.push_back("Code: " + std::to_string(packet.code));
    result.push_back("Payload Size: " + std::to_string(packet.payload_size));

    switch (packet.code) {
    case 1600:
        result.push_back("Client ID: " + unpack_uuid(packet.payload));
        break;
    case 1601:
        result.push_back("Registration Failed");
        break;
    case 1602:
    case 1605:
        unpack_aes_key(result);
        break;
    case 1603:
        unpack_file_received(result);
        break;
    case 1604:
        result.push_back("Client ID: " + unpack_uuid(packet.payload));
        break;
    case 1606:
        result.push_back("Client ID: " + unpack_uuid(packet.payload));
        break;
    case 1607:
        result.push_back("General Error");
        break;
    default:
        throw std::runtime_error("Unknown packet code");
    }
    return result;
}

// Method to unpack general data
void ResponsePacketUnpacker::unpack_general() {
    if (data.size() < 7) {
        throw std::runtime_error("Invalid packet size");
    }

    packet.version = data[0];
    packet.code = data[1] | (data[2] << 8);
    packet.payload_size = data[3] | (data[4] << 8) | (data[5] << 16) | (data[6] << 24);

    if (data.size() < 7 + packet.payload_size) {
        throw std::runtime_error("Invalid payload size");
    }

    packet.payload.assign(data.begin() + 7, data.end());
}

// Method to unpack UUID (16 bytes)
std::string ResponsePacketUnpacker::unpack_uuid(const std::vector<uint8_t>& payload) {
    if (payload.size() < 16) {
        throw std::runtime_error("Payload too small to contain a UUID.");
    }
    // Create a string containing the raw UUID bytes
    return std::string(payload.begin(), payload.begin() + 16);
}

// Method to unpack AES key
void ResponsePacketUnpacker::unpack_aes_key(std::vector<std::string>& result) {
    std::string client_id = unpack_uuid(packet.payload);
    result.push_back("Client ID: " + client_id);
    std::string encrypted_aes_key(packet.payload.begin() + 16, packet.payload.end());
    result.push_back("Encrypted AES Key: " + encrypted_aes_key);
}

// Method to unpack file received information
void ResponsePacketUnpacker::unpack_file_received(std::vector<std::string>& result) {
    std::string client_id = unpack_uuid(packet.payload);
    uint32_t content_size = packet.payload[16] | (packet.payload[17] << 8) | (packet.payload[18] << 16) | (packet.payload[19] << 24);
    std::string file_name(reinterpret_cast<const char*>(packet.payload.data() + 20), 255);
    uint32_t crc = packet.payload[275] | (packet.payload[276] << 8) | (packet.payload[277] << 16) | (packet.payload[278] << 24);

    result.push_back("Client ID: " + client_id);
    result.push_back("Content Size: " + std::to_string(content_size));
    result.push_back("File Name: " + file_name);
    result.push_back("CRC: " + std::to_string(crc));
}

uint32_t getCode(std::shared_ptr<std::vector<std::string>> data) {
    return std::stoi((*data)[1].substr(6));
}

std::string getAESKey(std::shared_ptr<std::vector<std::string>> packet) {
    return (*packet)[AES_KEY_CELL].substr(AES_KEY_OFFSET);
}

uint32_t getCRC(std::shared_ptr<std::vector<std::string>> packet) {
    return std::stoul((*packet)[CRC_CELL].substr(CRC_OFFSET));
}
