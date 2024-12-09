#pragma once

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include "client.h"
#include "AESWrapper.h"
#include "ResponseUnpacker.h"
#include "RequestPacker.h"

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
#define SUCCESS 0

class FileProcessor {
public:
    // Constructor
    FileProcessor(const std::shared_ptr<Client>& client);

    // Primary file processing functions
    std::vector<uint8_t> readFile(const std::string& filePath);
    std::string encryptFile(const std::vector<uint8_t>& fileContent, const std::string& aesKey);
    uint32_t calcCRC(const std::vector<uint8_t>& fileContent);
    void sendFileInChunks(const std::string& ciphertext, uint32_t originalFileSize, uint32_t encryptedFileSize);
    void processFile();
    uint32_t processCRC(uint32_t attempt);

private:
    std::shared_ptr<Client> client; // Client connection for sending data
    uint32_t crc;                   // CRC checksum for file integrity

    // Helper functions for processing and validation
    std::shared_ptr<std::vector<std::string>> recvAndValidateCRCPacket();
    uint32_t processCRCMatch();
    uint32_t processCRCMismatch(uint32_t attempt);
    uint32_t handleFinalPacketSend(CRCPacket& packet, const std::string& successMessage);

    // Utility to get file size
    uint32_t getFileSize(std::ifstream& file);
};

