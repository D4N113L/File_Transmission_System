#include "FileProcessor.h"

// Constructor
FileProcessor::FileProcessor(const std::shared_ptr<Client>& client) : client(client), crc(0) {}

// Reads the file content from the given file path
std::vector<uint8_t> FileProcessor::readFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Error: Could not open the file.");
    }

    uint32_t originalFileSize = getFileSize(file);

    // Check for overflow in file size to prevent buffer overflow issues
    if (originalFileSize + 1 < originalFileSize) {
        throw std::runtime_error("Potential buffer overflow detected.");
    }

    std::vector<uint8_t> fileContent(originalFileSize + 1, 0);
    if (!file.read(reinterpret_cast<char*>(fileContent.data()), originalFileSize)) {
        throw std::runtime_error("Error: Could not read the file.");
    }

    file.close();
    return fileContent;
}

// Encrypts the file content using AES encryption with the provided AES key
std::string FileProcessor::encryptFile(const std::vector<uint8_t>& fileContent, const std::string& aesKey) {
    AESWrapper aes(reinterpret_cast<const unsigned char*>(aesKey.data()), AESWrapper::DEFAULT_KEYLENGTH);
    return aes.encrypt(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());
}

// Calculates CRC for the file content to verify integrity
uint32_t FileProcessor::calcCRC(const std::vector<uint8_t>& fileContent) {
    return memcrc(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());
}

// Sends the file in chunks to the server, each chunk being of predefined size
void FileProcessor::sendFileInChunks(const std::string& ciphertext, uint32_t originalFileSize, uint32_t encryptedFileSize) {
    uint32_t totalPackets = (encryptedFileSize + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE;
    uint32_t currentPacketNum = 1;
    uint32_t bytesProcessed = 0;

    while (bytesProcessed < ciphertext.size()) {
        uint32_t contentSize = std::min(static_cast<size_t>(FILE_CHUNK_SIZE), ciphertext.size() - bytesProcessed);
        std::vector<uint8_t> buffer(FILE_CHUNK_SIZE);

        // Copy current chunk of ciphertext into buffer
        std::memcpy(buffer.data(), ciphertext.data() + bytesProcessed, contentSize);
        std::string id = client->getId();

        // Create and send the packet
        FileSendPacket packet(
            std::vector<uint8_t>(id.begin(), id.end()), CLIENT_VER, encryptedFileSize,
            originalFileSize, currentPacketNum, totalPackets, client->getFilePath(),
            std::vector<uint8_t>(buffer.begin(), buffer.begin() + contentSize)
        );

        client->sendPacket(packet.pack());
        bytesProcessed += contentSize;
        ++currentPacketNum;
    }
}

// High-level function to process the file by reading, encrypting, calculating CRC, and sending
void FileProcessor::processFile() {
    try {
        auto fileContent = readFile(client->getFilePath());
        auto ciphertext = encryptFile(fileContent, client->getAesKey());
        crc = calcCRC(fileContent);

        std::cout << "CRC of the original file: " << crc << std::endl;

        sendFileInChunks(ciphertext, fileContent.size(), ciphertext.length());
        std::cout << "Successfully sent file " << client->getFilePath() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error during file processing: " << e.what() << std::endl;
    }
}

// Manages CRC validation process with the server, attempting retransmissions if needed
uint32_t FileProcessor::processCRC(uint32_t attempt) {
    auto unpacked_crc_pckt = recvAndValidateCRCPacket();
    if (!unpacked_crc_pckt) {
        return PROCESSING_ERROR;
    }

    uint32_t crc_pckt_code = getCode(unpacked_crc_pckt);

    if (crc_pckt_code == 1607) {
        return PROCESSING_FAIL;
    }

    uint32_t server_crc = getCRC(unpacked_crc_pckt);

    if (crc == server_crc) {
        return processCRCMatch();
    }
    else {
        return processCRCMismatch(attempt);
    }
}

// Receives and validates CRC response from server
std::shared_ptr<std::vector<std::string>> FileProcessor::recvAndValidateCRCPacket() {
    auto unpacked_crc_pckt = client->recvPacket();

    if (!unpacked_crc_pckt) {
        std::cerr << "Error: Didn't manage to unpack." << std::endl;
    }
    else if (getCode(unpacked_crc_pckt) != 1603 && getCode(unpacked_crc_pckt) != 1607) {
        std::cerr << "Error: Unknown (or not valid) response code." << std::endl;
        unpacked_crc_pckt = nullptr;
    }
    return unpacked_crc_pckt;
}

// Process successful CRC match by notifying server
uint32_t FileProcessor::processCRCMatch() {
    std::string id = client->getId();
    CRCPacket success_pckt(std::vector<uint8_t>(id.begin(), id.end()), CLIENT_VER, CRC_SUCCESS_REQUEST_NUM, client->getFilePath());

    return handleFinalPacketSend(success_pckt, "File successfully stored on server! Finishing");
}

// Process CRC mismatch by retrying or notifying server of failure
uint32_t FileProcessor::processCRCMismatch(uint32_t attempt) {
    std::string id = client->getId();
    if (attempt < NUM_OF_TRIES_FOR_SERVER_FAIL) {
        std::cout << "Error: CRC mismatch. Retrying file transmission." << std::endl;
        CRCPacket try_again_pckt(std::vector<uint8_t>(id.begin(), id.end()), CLIENT_VER, CRC_FAIL_REQUEST_NUM, client->getFilePath());
        client->sendPacket(try_again_pckt.pack());
        return PROCESSING_FAIL;
    }
    else {
        CRCPacket fail_pckt(std::vector<uint8_t>(id.begin(), id.end()), CLIENT_VER, CRC_TOTAL_FAIL_REQUEST_NUM, client->getFilePath());
        return handleFinalPacketSend(fail_pckt, "File failed to store on server. Terminating.");
    }
}

// Handles sending the final packet and logs success message upon successful transmission
uint32_t FileProcessor::handleFinalPacketSend(CRCPacket& packet, const std::string& successMessage) {
    auto unpacked_fin_pckt = client->sendAndRecvPacket(packet.pack());

    if (getCode(unpacked_fin_pckt) == 1604) {
        std::cout << successMessage << std::endl;
        return PROCESSING_SUCCESS;
    }
    else {
        std::cerr << "Error: Received unknown or invalid response code." << std::endl;
        return PROCESSING_ERROR;
    }
}

// Helper function to get file size
uint32_t FileProcessor::getFileSize(std::ifstream& file) {
    file.seekg(0, std::ios::end);
    uint32_t fileSize = static_cast<uint32_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    return fileSize;
}
