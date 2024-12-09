#pragma once

#include <iostream>
#include <vector>
#include <stdexcept>
#include <string>
#include <cstring> // for memcpy

// Base class for packing request packets
class RequestPacketPacker {
public:
    // Constructor to initialize RequestPacketPacker fields
    RequestPacketPacker(const std::vector<uint8_t>& clientId, uint8_t version, uint16_t code, const std::vector<uint8_t>& payload);

    // Virtual function to pack the packet
    virtual std::vector<uint8_t> pack() const;

protected:
    uint8_t client_id[16];
    uint8_t version;
    uint16_t code;
    std::vector<uint8_t> payload;
};

// Registration Packet (Code 825)
class RegistrationPacket : public RequestPacketPacker {
public:
    // Constructor to initialize RegistrationPacket fields
    RegistrationPacket(const std::vector<uint8_t>& clientId, uint8_t version, const std::string& name);
};

// Public Key Packet (Code 826)
class PublicKeyPacket : public RequestPacketPacker {
public:
    // Constructor to initialize PublicKeyPacket fields
    PublicKeyPacket(const std::vector<uint8_t>& clientId, uint8_t version, const std::string& name, const std::string& publicKey);
};

// Reconnection Packet (Code 827)
class ReconnectionPacket : public RequestPacketPacker {
public:
    // Constructor to initialize ReconnectionPacket fields
    ReconnectionPacket(const std::vector<uint8_t>& clientId, uint8_t version, const std::string& name);
};

// File Send Packet (Code 828)
class FileSendPacket : public RequestPacketPacker {
public:
    // Constructor to initialize FileSendPacket fields
    FileSendPacket(const std::vector<uint8_t>& clientId, uint8_t version, uint32_t contentSize, uint32_t originalFileSize, uint16_t packetNum, uint16_t totalPackets, const std::string& fileName, const std::vector<uint8_t>& messageContent);
};

// CRC Packet (Codes 900, 901, 902)
class CRCPacket : public RequestPacketPacker {
public:
    // Constructor to initialize CRCPacket fields
    CRCPacket(const std::vector<uint8_t>& clientId, uint8_t version, uint16_t code, const std::string& fileName);
};

