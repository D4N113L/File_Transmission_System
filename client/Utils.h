#pragma once

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>

/**
 * @brief Converts a byte array to a hexadecimal string.
 *
 * @param byteStr Byte array in the form of a string.
 * @return Hexadecimal representation of the byte array.
 */
std::string bytesToHexString(const std::string& byteStr);

/**
 * @brief Converts a hexadecimal client ID string to a byte array.
 *
 * @param client_id_hex Hexadecimal representation of the client ID.
 * @return Byte array representation of the client ID.
 */
std::string hexToByteArray(const std::string& client_id_hex);

/**
 * @brief Saves client data to a file.
 *
 * @param filename Name of the file to save the data.
 * @param data1 First data string to save.
 * @param data2 (Optional) Second data string to save.
 * @param data3 (Optional) Third data string to save.
 * @return True if data is saved successfully, false otherwise.
 */
bool SaveToFile(const std::string& filename, const std::string& data1, const std::string& data2 = "", const std::string& data3 = "");

