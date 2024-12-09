#pragma once

#include <boost/asio.hpp>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem> 
#include <vector>
#include <memory>
#include <cstring>
#include <iomanip>

#include "RequestPacker.h"
#include "ResponseUnpacker.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "cksum_new.h"
#include "ClientClass.h"
#include "FileProcessor.h"
#include "Utils.h"

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



