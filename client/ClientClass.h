#pragma once

#include <string>
#include <vector>
#include <memory>
#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

#define BUFFER_SIZE 1024 // Adjust buffer size as needed
#define NUM_OF_TRIES_FOR_SERVER_FAIL 3 // Number of retry attempts for server errors

class Client {
private:
    std::string name;
    std::string id;
    boost::asio::io_context io_context;
    tcp::socket socket;
    std::string rsa_public_key;
    std::string rsa_private_key;
    std::string aes_key;
    std::string host;
    uint32_t port;
    std::string file_path;

public:
    // Constructor & Destructor
    Client(std::string& client_name, std::string& host, uint32_t port, std::string& file_path);
    ~Client();

    // Getters and Setters
    std::string getName() const;
    void setName(const std::string& name);

    std::string getId() const;
    std::vector<uint8_t> getIdAsBytes() const;
    void setId(const std::string& id);

    std::string getRsaPublicKey() const;
    void setRsaPublicKey(const std::string& rsa_public_key);

    std::string getRsaPrivateKey() const;
    void setRsaPrivateKey(const std::string& rsa_private_key);

    std::string getAesKey() const;
    void setAesKey(const std::string& aes_key);

    std::string getHost() const;
    void setHost(const std::string& host);

    int getPort() const;
    void setPort(const int port);

    std::string getFilePath() const;
    void setFilePath(const std::string& file_path);

    // Packet Handling Methods
    void sendPacket(const std::vector<uint8_t>& packet);
    std::shared_ptr<std::vector<std::string>> recvPacket();
    std::shared_ptr<std::vector<std::string>> sendAndRecvPacket(const std::vector<uint8_t>& packet);
};