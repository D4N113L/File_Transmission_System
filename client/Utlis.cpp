#include "Utils.h"

// Converts a byte array to a hexadecimal string representation.
// Each byte is converted to a two-character hex code.
std::string bytesToHexString(const std::string& byteStr) {
    std::ostringstream hexStream;

    for (unsigned char byte : byteStr) {
        // Convert each byte to a two-character hex string and append to the stream
        hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return hexStream.str();
}

// Converts a hexadecimal client ID string to a byte array.
// Each pair of hex characters represents one byte in the resulting array.
std::string hexToByteArray(const std::string& client_id_hex) {
    std::vector<uint8_t> client_id;

    for (size_t i = 0; i < client_id_hex.length(); i += 2) {
        // Extract each pair of hex characters as a substring and convert to a byte
        std::string byteString = client_id_hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        client_id.push_back(byte);
    }

    // Return the byte array as a string for ease of handling
    return std::string(client_id.begin(), client_id.end());
}

// Saves client data to a specified file. Writes up to three data strings, one per line.
// Returns true if the data is successfully saved; false otherwise.
bool SaveToFile(const std::string& filename, const std::string& data1, const std::string& data2, const std::string& data3) {
    std::ofstream file(filename);

    // Check if file opened successfully
    if (!file) return false;

    // Write each piece of data to the file on a new line
    file << data1 << std::endl;
    if (!data2.empty()) file << data2 << std::endl;
    if (!data3.empty()) file << data3;

    file.close();
    return true;
}
