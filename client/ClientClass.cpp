#include "client.h"

// Constructor: Initializes client and connects to server
Client::Client(std::string& client_name, std::string& host, uint32_t port, std::string& file_path)
    : name(client_name), id(""), socket(io_context), rsa_public_key(""), rsa_private_key(""), aes_key(""), host(host), port(port), file_path(file_path) {

    // Resolve server IP and port
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve(this->host, std::to_string(this->port));

    // Connect to the server
    boost::asio::connect(socket, endpoints);
    std::cout << "Connected to server " << this->host << ":" << this->port << std::endl << std::endl;
}

// Destructor: Clears sensitive data and closes the connection
Client::~Client() {
    // Securely clear AES and RSA keys
    std::fill(aes_key.begin(), aes_key.end(), 0);
    std::fill(rsa_public_key.begin(), rsa_public_key.end(), 0);
    std::cout << "Closing the connection." << std::endl;
    socket.close();
}

// Getters and Setters
std::string Client::getName() const { return name; }
void Client::setName(const std::string& name) { this->name = name; }

std::string Client::getId() const { return id; }
std::vector<uint8_t> Client::getIdAsBytes() const {
    return std::vector<uint8_t>(id.begin(), id.end());
}
void Client::setId(const std::string& id) { this->id = id; }

std::string Client::getRsaPublicKey() const { return rsa_public_key; }
void Client::setRsaPublicKey(const std::string& rsa_public_key) { this->rsa_public_key = rsa_public_key; }

std::string Client::getRsaPrivateKey() const { return rsa_private_key; }
void Client::setRsaPrivateKey(const std::string& rsa_private_key) { this->rsa_private_key = rsa_private_key; }

std::string Client::getAesKey() const { return aes_key; }
void Client::setAesKey(const std::string& aes_key) { this->aes_key = aes_key; }

std::string Client::getHost() const { return host; }
void Client::setHost(const std::string& host) { this->host = host; }

int Client::getPort() const { return port; }
void Client::setPort(const int port) { this->port = port; }

std::string Client::getFilePath() const { return file_path; }
void Client::setFilePath(const std::string& file_path) { this->file_path = file_path; }

// Sends a packet to the server
void Client::sendPacket(const std::vector<uint8_t>& packet) {
    try {
        boost::asio::write(socket, boost::asio::buffer(packet));
    }
    catch (const std::exception& e) {
        throw e; // Re-throw to signal failure to caller
    }
}

// Receives a packet from the server and unpacks it
std::shared_ptr<std::vector<std::string>> Client::recvPacket() {
    std::vector<uint8_t> response_buffer(BUFFER_SIZE);  // Create buffer for response
    size_t len = socket.read_some(boost::asio::buffer(response_buffer));  // Read response from server

    // Adjust buffer size to match the received data length
    response_buffer.resize(len);

    try {
        // Unpack the response
        ResponsePacketUnpacker unpacker(response_buffer);
        auto unpacked_data = std::make_shared<std::vector<std::string>>(unpacker.unpack());
        std::cout << "Received packet successfully. Content:" << std::endl;

        // Display the unpacked content
        for (const std::string& entry : *unpacked_data) {
            std::cout << "* " << entry << std::endl;
        }
        std::cout << std::endl;

        return unpacked_data;
    }
    catch (const std::exception& e) {
        throw e; // Propagate error to caller
    }
}

// Sends a packet and waits for a response, retrying if server error occurs
std::shared_ptr<std::vector<std::string>> Client::sendAndRecvPacket(const std::vector<uint8_t>& packet) {
    for (int i = 0; i < NUM_OF_TRIES_FOR_SERVER_FAIL; i++) {
        try {
            // Attempt to send packet
            sendPacket(packet);
        }
        catch (const std::exception& e) {
            std::cerr << "Failed sending the request packet: " << e.what() << std::endl;
            return nullptr;
        }

        try {
            // Attempt to receive the response
            auto unpacked_data = recvPacket();

            // Check if response indicates server error code (1607)
            if (unpacked_data && getCode(unpacked_data) == 1607) {
                std::cerr << "Had some problems sending the packet... Trying again. Attempt no. " << i << std::endl;
                continue; // Retry if server error is indicated
            }
            return unpacked_data; // Return unpacked data if successful
        }
        catch (const std::exception& e) {
            std::cerr << "Failed receiving the response packet: " << e.what() << std::endl;
        }
    }

    // Log final error message if retries exhausted
    std::cerr << "There was a server error, sorry :(" << std::endl;
    return nullptr;
}
