#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <iomanip>
#include <sstream>
#include <cstdint>

class ResponsePacketUnpacker {
public:
    explicit ResponsePacketUnpacker(const std::vector<uint8_t>& data);

    std::vector<std::string> unpack();

private:
    struct Packet {
        uint8_t version;
        uint16_t code;
        uint32_t payload_size;
        std::vector<uint8_t> payload;
    };

    Packet packet;
    const std::vector<uint8_t>& data;

    void unpack_general();

    std::string unpack_uuid(const std::vector<uint8_t>& payload);

    void unpack_aes_key(std::vector<std::string>& result);

    void unpack_file_received(std::vector<std::string>& result);
};

uint32_t getCode(std::shared_ptr<std::vector<std::string>> data);

std::string getAESKey(std::shared_ptr<std::vector<std::string>> packet);

uint32_t getCRC(std::shared_ptr<std::vector<std::string>> packet);

// --- Client Info ---
#define CLIENT_VER 3
#define CLIENT_NAME_MAX_LEN 100
#define CLIENT_ID_SIZE 16
#define CLIENT_ID_CELL 3
#define CLIENT_ID_OFFSET 11

// --- Buffer Sizes ---
#define FILE_CHUNK_SIZE 1024
#define BUFFER_SIZE 1024

// --- Port Info ---
#define DEFAULT_PORT 1256

// --- AES Key ---
#define AES_KEY_CELL 4
#define AES_KEY_OFFSET 19

// --- CRC ---
#define CRC_CELL 6
#define CRC_OFFSET 5
#define CRC_SUCCESS_REQUEST_NUM 900
#define CRC_FAIL_REQUEST_NUM 901
#define CRC_TOTAL_FAIL_REQUEST_NUM 902

// --- Error Handling ---
#define PROCESSING_ERROR 2
#define ERROR 1

// --- Processing Status ---
#define PROCESSING_SUCCESS 0
#define PROCESSING_FAIL 1

// --- Registration Status ---
#define REGISTRATION_ERROR 1
#define REGISTRATION_SUCCESS 0

// --- Reconnection Status ---
#define RECONNECTION_SUCCESS 0
#define RECONNECTION_ERROR 1

// --- Retry Attempts ---
#define NUM_OF_TRIES_FOR_SERVER_FAIL 4

// --- Other Codes ---
#define CODE_CELL 1

