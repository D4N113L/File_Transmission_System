#include "client.h"
using boost::asio::ip::tcp;

/* Initialization functions */

// Create the client structure
std::shared_ptr<Client> createClient() {
    // Read transfer.info first
    std::ifstream tr_info_file("transfer.info");
    if (!tr_info_file) {
        std::cerr << "Error: Could not open 'transfer.info' file." << std::endl;
        return nullptr;
    }

    // Read first line (IP:port)
    std::string line;
    std::getline(tr_info_file, line);
    std::istringstream address_stream(line);
    std::string ip_address;
    std::string port_str;

    // Parse the IP and port
    if (std::getline(address_stream, ip_address, ':') && std::getline(address_stream, port_str)) {
        std::cout << "IP: " << ip_address << ", Port: " << port_str << std::endl;
    }
    else {
        std::cerr << "Error: Invalid IP:port format in 'transfer.info'." << std::endl;
        return nullptr;
    }

    uint32_t port;
    try {
        port = std::stoul(port_str);  // Convert port to integer
    }
    catch (...) {
        std::cerr << "Error: Invalid port number. Setting default: 1256" << std::endl;
        port = DEFAULT_PORT;
    }

    // Read second line (client name)
    std::string client_name;
    std::getline(tr_info_file, client_name);
    if (client_name.empty() || client_name.size() > CLIENT_NAME_MAX_LEN) {
        std::cerr << "Error: Invalid client name in 'transfer.info'." << std::endl;
        return nullptr;
    }
    std::cout << "Client Name: " << client_name << std::endl;

    // Read third line (file path)
    std::string file_path;
    std::getline(tr_info_file, file_path);
    if (!std::filesystem::exists(file_path)) {
        std::cerr << "Error: File does not exist: " << file_path << std::endl;
        return nullptr;
    }
    std::cout << "File Path: " << file_path << std::endl;

    auto curr_client =  std::make_shared<Client>(client_name, ip_address, port, file_path);
    if (!curr_client) {
        throw std::runtime_error("Error: Couldn't create client.");
    }
    return curr_client;
}

// Function to extract client information from 'me.info'
std::tuple<std::string, std::string> extractClientInfo(std::ifstream& me_info_file) {
    std::string stored_client_name, client_id_hex;

    std::getline(me_info_file, stored_client_name);
    std::getline(me_info_file, client_id_hex);
    me_info_file.close();

    return std::make_tuple(stored_client_name, client_id_hex);
}


/* Registration related funstions */

// Function to extract private key from 'priv.key'
std::string extractPrivateKey() {
    std::ifstream priv_key_file("priv.key");
    if (!priv_key_file) {
        throw std::runtime_error("Error: Couldn't open file 'priv.key'");
    }
    std::stringstream privkey_buffer;
    privkey_buffer << priv_key_file.rdbuf();
    priv_key_file.close();

    return privkey_buffer.str();
}

// Function to send reconnection packet and process server response
uint32_t sendReconnectionPacket(Client* client, const std::string& client_id_str) {
    ReconnectionPacket recon_pckt(std::vector<uint8_t>(client_id_str.begin(), client_id_str.end()), CLIENT_VER, client->getName());
    auto unpacked_recon_pckt = client->sendAndRecvPacket(recon_pckt.pack());
    if (!unpacked_recon_pckt) {
        std::cerr << "Error: Couldn't unpack packet" << std::endl;
        return RECONNECTION_ERROR;
    }

    uint32_t code = getCode(unpacked_recon_pckt);
    if (code == 1605) {
        std::cout << "Reconnection Successful. Got encrypted AES key." << std::endl;
        std::string enc_aes_key = getAESKey(unpacked_recon_pckt);
        RSAPrivateWrapper rsapriv(client->getRsaPrivateKey());
        std::string aes_key = rsapriv.decrypt(enc_aes_key);
        client->setAesKey(aes_key);
        return RECONNECTION_SUCCESS;
    }
    else if (code == 1606) {
        std::cerr << "Reconnection Failed" << std::endl;
        return RECONNECTION_ERROR;
    }
    else {
        std::cerr << "Error: Unknown (or not a valid for this part) response code." << std::endl;
        return RECONNECTION_ERROR;
    }
}

// Main Reconnect function using the above helper functions
uint32_t Reconnect(std::shared_ptr<Client> curr_client, std::ifstream& me_info_file) {
    try {
        // Step 1: Extract client info from 'me.info'
        auto [stored_client_name, client_id_hex] = extractClientInfo(me_info_file);
        std::string client_id_str = hexToByteArray(client_id_hex);

        // Step 2: Extract private key from 'priv.key'
        std::string private_key = extractPrivateKey();

        // Set client ID and private key
        curr_client->setId(client_id_str);
        curr_client->setRsaPrivateKey(Base64Wrapper::decode(private_key));

        // Validate client name
        if (stored_client_name != curr_client->getName()) {
            std::cerr << "Error: Client name in 'me.info' does not match 'transfer.info'." << std::endl;
            return RECONNECTION_ERROR;
        }

        // Step 3: Send reconnection packet and handle response
        return sendReconnectionPacket(curr_client.get(), client_id_str);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while handling client reconnection: " << e.what() << std::endl;
        return RECONNECTION_ERROR;
    }
    catch (...) {
        std::cerr << "Unknown error while handling client reconnection" << std::endl;
        return RECONNECTION_ERROR;
    }
}


/* Reconnection related functions */

// Step 1: Prepare and Send Registration Packet
std::shared_ptr<std::vector<std::string>> SendRegistrationPacket(std::shared_ptr<Client> curr_client) {
    std::vector<uint8_t> client_id(CLIENT_ID_SIZE, 0); // Initialize client ID with zeroes
    RegistrationPacket reg_pckt(client_id, CLIENT_VER, curr_client->getName());
    auto unpacked_reg_pckt = curr_client->sendAndRecvPacket(reg_pckt.pack());
    if (!unpacked_reg_pckt) {
        std::cerr << "Error: Couldn't unpack packet" << std::endl;
    }
    return unpacked_reg_pckt;
}

// Step 2: Process Registration Response
bool ProcessRegistrationResponse(uint32_t reg_code, std::shared_ptr<std::vector<std::string>> unpacked_reg_pckt, std::shared_ptr<Client> curr_client) {
    if (reg_code != 1600) {
        std::cerr << "Registration Failed or Unknown Response Code." << std::endl;
        return false;
    }
    std::string client_id_str = (*unpacked_reg_pckt)[CLIENT_ID_CELL].substr(CLIENT_ID_OFFSET);
    curr_client->setId(client_id_str);
    return true;
}

// Step 3: Generate and Set RSA Keys
void SetRsaKeys(std::shared_ptr<Client> curr_client, RSAPrivateWrapper& rsapriv) {
    curr_client->setRsaPublicKey(rsapriv.getPublicKey());
    curr_client->setRsaPrivateKey(rsapriv.getPrivateKey());
}

// Step 4: Send Public Key Packet
std::shared_ptr<std::vector<std::string>> SendPublicKeyPacket(std::shared_ptr<Client> curr_client, const std::string& pubkey) {
    PublicKeyPacket pubkey_pckt(curr_client->getIdAsBytes(), CLIENT_VER, curr_client->getName(), pubkey);
    auto unpacked_key_pckt = curr_client->sendAndRecvPacket(pubkey_pckt.pack());
    if (!unpacked_key_pckt) {
        std::cerr << "Error: Couldn't unpack packet" << std::endl;
    }
    return unpacked_key_pckt;
}

// Step 5: Process Server Response for AES Key
bool ProcessServerAesKey(std::shared_ptr<std::vector<std::string>> unpacked_key_pckt, std::shared_ptr<Client> curr_client, RSAPrivateWrapper& rsapriv) {
    if (getCode(unpacked_key_pckt) != 1602) {
        std::cerr << "Error: Unknown Response Code for AES Key" << std::endl;
        return false;
    }
    std::string enc_aes_key = getAESKey(unpacked_key_pckt); 
    curr_client->setAesKey(rsapriv.decrypt(enc_aes_key));
    return true;
}

// Step 6: Save Client Info for Reconnection
bool SaveClientInfo(std::shared_ptr<Client> curr_client, RSAPrivateWrapper& rsapriv) {
    if (!SaveToFile("me.info", curr_client->getName(), bytesToHexString(curr_client->getId()), Base64Wrapper::encode(rsapriv.getPrivateKey()))) {
        std::cerr << "Error: Could not save 'me.info' file" << std::endl;
        return false;
    }
    if (!SaveToFile("priv.key", Base64Wrapper::encode(rsapriv.getPrivateKey()))) {
        std::cerr << "Error: Could not save 'priv.key' file" << std::endl;
        return false;
    }
    return true;
}

// Registration function
uint32_t Register(std::shared_ptr<Client> curr_client) {
    // Step 1: Send Registration Packet and Unpack Response
    auto unpacked_reg_pckt = SendRegistrationPacket(curr_client);
    if (!unpacked_reg_pckt) return REGISTRATION_ERROR;

    // Step 2: Process Registration Response
    uint32_t reg_code = getCode(unpacked_reg_pckt);
    if (!ProcessRegistrationResponse(reg_code, unpacked_reg_pckt, curr_client)) return REGISTRATION_ERROR;

    // Step 3: Generate and Set RSA Keys
    RSAPrivateWrapper rsapriv;
    SetRsaKeys(curr_client, rsapriv);

    // Step 4: Send Public Key Packet and Process Server Response
    auto unpacked_key_pckt = SendPublicKeyPacket(curr_client, rsapriv.getPublicKey());
    if (!unpacked_key_pckt) return REGISTRATION_ERROR;

    // Step 5: Process Server Response for AES Key
    if (!ProcessServerAesKey(unpacked_key_pckt, curr_client, rsapriv)) return REGISTRATION_ERROR;

    // Step 6: Save Client Data for Reconnection
    if (!SaveClientInfo(curr_client, rsapriv)) return REGISTRATION_ERROR;

    return REGISTRATION_SUCCESS;
}


/* File sending related functions */

void sendFile(std::shared_ptr<Client>& curr_client) {
    FileProcessor processor(curr_client);
    for (uint32_t i = 0; i < NUM_OF_TRIES_FOR_SERVER_FAIL; i++) {
        processor.processFile();
        uint32_t result = processor.processCRC(i);
        if (result == PROCESSING_SUCCESS) {
            // Finish
            return;
        }
        if (result == PROCESSING_FAIL) {
            continue;
        }
        if (result == PROCESSING_ERROR) {
            throw std::runtime_error("Error while processing the CRC's.");
        }
    }
    throw std::runtime_error("Too many failed attempts trying to match CRC's.");
}


/* Client start functions */
int startClient() {
    try {
        std::shared_ptr<Client> curr_client = createClient();

        // Check if 'me.info' exists
        std::ifstream me_info_file("me.info");

        // If it does ,we preform reconnection
        if (me_info_file) {
            if (Reconnect(curr_client, me_info_file))
                return ERROR;
        }
        
        // If it ain't, we preform registration
        else {
            if (Register(curr_client))
                return ERROR;
        }

        // And now, sending the file itself 
        sendFile(curr_client);
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return SUCCESS;
}

int main() {
    return startClient();
}