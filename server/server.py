# echo_server.py
import socket
import os
import uuid
import threading  # Import threading module to handle multiple clients concurrently
import RequestUnpacker
import ResponsePacker
import aes
import rsa
import cksum
import sqlite3
from datetime import datetime

HEADER_SIZE = 23  # 16 + 1 + 2 + 4
SERVER_VER = 3
NUMBER_OF_ATTEMPTS = 4

SUCCESS = 0
ERROR = 1
GENERAL_ERROR = 2

# Defaults
HOST = '127.0.0.1'  # Localhost
PORT = 1256
# Server configuration: If a new port is not specified, the default one stays (1256)
try:
    with open("port.info", 'r') as port_info:
        PORT = int(port_info.read())
except FileNotFoundError:
    print("Error: 'port.info' file not found. Please ensure the file exists.")
except ValueError:
    print("Error: Invalid port value in 'port.info'. Please check the file content.")
except Exception as e:
    print(f"An error occurred: {e}")

# **********************************************************************
# Dictionary to hold registered client names
# **********************************************************************
class Client:
    def __init__(self, name=None, id=None, rsa_public_key=None, aes_key=None):
        self.name = name
        self.id = id
        self.rsa_public_key = rsa_public_key
        self.aes_key = aes_key

clients_dict = {}

# **********************************************************************
# Database related functions
# **********************************************************************
def initialize_database():
    """
    Initialize the database with required tables if they don't already exist.
    - Creates 'clients' and 'files' tables in 'defensive.db' for storing client information and file details.
    """
    conn = sqlite3.connect("defensive.db")  # Connect to or create the database
    cursor = conn.cursor()
    
    # Create 'clients' table with fields for client details
    cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
        ID BLOB PRIMARY KEY,
        Name TEXT NOT NULL,
        Publickey BLOB,
        LastSeen DATETIME,
        AES_key BLOB
    )''')

    # Create 'files' table with fields for file details, linked to 'clients' table by client ID
    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
        ID BLOB,
        FileName TEXT NOT NULL,
        PathName TEXT NOT NULL,
        Verified BOOLEAN,
        FOREIGN KEY (ID) REFERENCES clients(ID)
    )''')

    conn.commit()  # Save changes
    conn.close()   # Close the database connection

def load_clients():
    """
    Load client data from the 'clients' table into the clients_dict for in-memory access.
    - Populates clients_dict with Client objects based on the database entries.
    """
    with sqlite3.connect("defensive.db") as conn:  # Open database connection
        cursor = conn.cursor()
        cursor.execute("SELECT ID, Name, Publickey, AES_key FROM clients")
        
        # Fetch each row from the result and populate the clients_dict
        for row in cursor.fetchall():
            client_id, name, public_key, aes_key = row
            # Store client data in clients_dict, creating a Client object for each row
            clients_dict[name] = Client(name=name, id=client_id, rsa_public_key=public_key, aes_key=aes_key)

# **********************************************************************
# Network related functions
# **********************************************************************
def recv_packet(conn):
    """
    Receive and unpack a packet from the connection.
    - Reads the packet header to determine payload size, then retrieves and unpacks the full packet.
    """
    header = conn.recv(HEADER_SIZE)  # Receive the fixed-size header
    payload_size = RequestUnpacker.get_payload_size(header)  # Get payload size from header
    # Combine header and payload, then unpack the packet
    packet = RequestUnpacker.RequestPacketUnpacker(header + conn.recv(payload_size)).unpack()
    return packet  # Return the unpacked packet

def send_packet(conn, packet):
    """
    Send a packet over the connection.
    - Sends the fully formed packet data to the connected peer.
    """
    conn.sendall(packet)  # Send the entire packet to the destination

# **********************************************************************
# Server start-up functions
# **********************************************************************
def handle_registration(packet, conn):
    """
    Handles new client registration.
    - Generates a UUID for the client, checks for existing registration, and stores the new client in the database.
    - Sends success or failure response based on registration outcome.
    """
    client_name = packet['name']
    print(f"Got a registration request, client name: {client_name}")

    # Generate a unique identifier for the client
    client_id = uuid.uuid4().bytes
    
    # Check if the client name is already registered in the database
    with sqlite3.connect("defensive.db") as conn_db:
        cursor = conn_db.cursor()
        cursor.execute("SELECT ID FROM clients WHERE Name = ?", (client_name,))
        result = cursor.fetchone()
        
        if result:
            # Client already registered, send failure response
            print(f"Client {client_name} is already registered, sending failure packet.")
            reg_fail_pckt = ResponsePacker.RegistrationFailedPacker(version=SERVER_VER)
            conn.sendall(reg_fail_pckt.pack())
            return ERROR
        else:
            # Register the new client by inserting into the database
            cursor.execute('''INSERT INTO clients (ID, Name, LastSeen) VALUES (?, ?, ?)''', 
                           (client_id, client_name, datetime.now()))
            conn_db.commit()

    # Add client to in-memory storage
    clients_dict[client_name] = Client(name=client_name, id=client_id)

    # Send success response with the assigned UUID
    reg_success_pckt = ResponsePacker.RegistrationSucceededPacker(version=SERVER_VER, client_id=client_id)
    conn.sendall(reg_success_pckt.pack())
    print(f"Registration successful for {client_name}. Assigned UUID: {client_id.hex()}")

    # Wait for public key packet
    packet = recv_packet(conn) 
    if packet['code'] != 826:
        print("Got an invalid packet code for this part.")
        return GENERAL_ERROR

    print(f"Public key request, name: {packet['name']}")
    # Save the public key to the client's profile
    clients_dict[client_name].rsa_public_key = packet['public_key']

    # Update database with the received public key
    with sqlite3.connect("defensive.db") as conn_db:
        cursor = conn_db.cursor()
        cursor.execute("UPDATE clients SET Publickey = ? WHERE ID = ?", (packet['public_key'], client_id))
        conn_db.commit()

    return SUCCESS

def handle_reconnection(packet, conn):
    """
    Handles reconnection of an existing client.
    - Verifies if client name and UUID match stored records.
    - Sends success or failure response depending on validity of reconnection request.
    """
    client_name = packet['name']
    client_id = packet['client_id']

    if client_name not in clients_dict:
        # Client not registered, reject reconnection
        print(f"Client {client_name} is not registered, sending failure packet.")
        recon_fail_pckt = ResponsePacker.ReconnectionDeclinedPacker(SERVER_VER, b"a" * 16)
        send_packet(conn, recon_fail_pckt.pack())
        return ERROR

    if client_id != clients_dict[client_name].id:
        # UUID mismatch, reject reconnection
        print(f"Client {client_name}'s UUID doesn't match received UUID, sending failure packet.")
        recon_fail_pckt = ResponsePacker.ReconnectionDeclinedPacker(SERVER_VER, b"a" * 16)
        send_packet(conn, recon_fail_pckt.pack())
        return ERROR

    print(f"Reconnection successful for {client_name}.")
    return SUCCESS

def handle_public_key(client_name, conn, is_reg):
    """
    Handles the client's public key exchange.
    - Generates an AES key, encrypts it with client's public RSA key, and sends the encrypted AES key back.
    - Updates the database with the new AES key.
    """
    aes_key = aes.generate_key()  # Generate a new AES key for the client
    clients_dict[client_name].aes_key = aes_key

    try:
        # Encrypt AES key using client's RSA public key
        enc_aes_key = rsa.encrypt(aes_key, clients_dict[client_name].rsa_public_key)
    except:
        if not is_reg:
            # Issue with encryption, send reconnection failure if it's not during registration
            print("Had an error while encrypting AES key with RSA public key. Possibly bad RSA key.")
            failed_recon_pckt = ResourceWarning.ReconnectionDeclinedPacker(SERVER_VER, clients_dict[client_name].id)
            conn.sendall(failed_recon_pckt)
            return ERROR
        return GENERAL_ERROR

    # Select the appropriate packet type based on registration or reconnection
    if is_reg:
        pubkey_pckt = ResponsePacker.EncryptedAESKeyRegistrationPacker(SERVER_VER, clients_dict[client_name].id, enc_aes_key)
    else:
        pubkey_pckt = ResponsePacker.EncryptedAESKeyReconnectionPacker(SERVER_VER, clients_dict[client_name].id, enc_aes_key)
    send_packet(conn, pubkey_pckt.pack())

    # Update the database with the newly generated AES key
    with sqlite3.connect("defensive.db") as conn_db:
        cursor = conn_db.cursor()
        cursor.execute("UPDATE clients SET AES_key = ? WHERE ID = ?", (aes_key, clients_dict[client_name].id))
        conn_db.commit()

    print(f"Public key accepted, encrypted AES key sent.")
    return SUCCESS

# **********************************************************************
# File recv related functions
# **********************************************************************
def get_enc_file_content(conn, file_name, total_packets, enc_file_size, file_size, enc_file_content):
    """
    Receives the encrypted file content by collecting packets from the connection.
    Validates each packet's code, packet number, and file name for integrity.
    
    Args:
        conn: The connection object.
        file_name (str): The expected name of the file being received.
        total_packets (int): Total number of packets expected.
        enc_file_size (int): Expected size of the encrypted file.
        file_size (int): Expected size of the decrypted file.
        enc_file_content (str): Placeholder for accumulating file content.
        
    Returns:
        str: The full encrypted file content if successful; otherwise, 0 on error.
    """
    for curr_packet in range(2, total_packets + 1): 
        # Receive the next packet and validate essential fields
        packet = recv_packet(conn)
        if packet['code'] != 828:
            print(f"Error: Invalid packet code: ({packet['code']} instead of 828)")
            return 0
        if packet['packet_number'] != curr_packet:
            print(f"Error: Invalid packet number ({packet['packet_number']} instead of {curr_packet})")
            return 0
        
        # Check if the file name matches the expected name
        packet_file_name = packet['file_name'].split('\\')[-1]
        if packet_file_name != file_name:
            print(f"Error: invalid file name ({packet_file_name} instead of {file_name})")
            return 0

        # Append current packet's content to the complete encrypted file content
        enc_file_content += packet['message_content']
        print(f"Packet {packet['packet_number']}/{total_packets}, content length: {len(enc_file_content)}")

    # Ensure the content length matches the expected encrypted file size
    if len(enc_file_content) != enc_file_size:
        print(f"Error: Encrypted file size mismatch: ({len(enc_file_content)} != {enc_file_size})")
        return 0

    return enc_file_content

def decrypt_file_content(enc_file_content, client_name, file_size):
    """
    Decrypts the encrypted file content using the client's AES key.
    
    Args:
        enc_file_content (str): The encrypted file content.
        client_name (str): Name of the client to retrieve their decryption key.
        file_size (int): Expected size of the decrypted file.
        
    Returns:
        str: The decrypted file content if successful; otherwise, 0 on error.
    """
    # Decrypt using the client's AES key and validate the decrypted size
    file_content = aes.decrypt(enc_file_content, clients_dict[client_name].aes_key)
    if len(file_content) != file_size:
        print(f"Error: Decrypted file size mismatch: ({len(file_content)} != {file_size})")
        return 0
    return file_content

def save_file_to_disk(client_name, file_name, file_content):
    """
    Saves the decrypted file content to the disk under a client-specific directory.
    
    Args:
        client_name (str): The client's name, used to create their directory.
        file_name (str): Name of the file to save.
        file_content (str): The decrypted content to write.
        
    Returns:
        str: The file path where the file was saved.
    """
    # Create base and user-specific directories if they don't exist
    base_dir = os.path.join(os.getcwd(), 'user_files')
    os.makedirs(base_dir, exist_ok=True)

    user_dir = os.path.join(base_dir, client_name)
    os.makedirs(user_dir, exist_ok=True)
    file_path = os.path.join(user_dir, file_name)

    # Write the file content to disk
    with open(file_path, 'wb') as f:
        print(f"Saving file as: {file_name}")
        f.write(file_content)
    return file_path

def update_file_in_database(client_name, file_name, file_path):    
    """
    Updates the database with the received file's information.
    
    Args:
        client_name (str): Client's name to link the file to their account.
        file_name (str): Name of the file.
        file_path (str): Path where the file is saved on disk.
    """
    with sqlite3.connect("defensive.db") as conn_db:
        cursor = conn_db.cursor()
        
        # Delete any existing record for this client and file name
        cursor.execute('''
            DELETE FROM files
            WHERE ID = ? AND FileName = ?
        ''', (clients_dict[client_name].id, file_name))
        
        # Insert the new file record
        cursor.execute('''
            INSERT INTO files (ID, FileName, PathName, Verified)
            VALUES (?, ?, ?, ?)
        ''', (clients_dict[client_name].id, file_name, file_path, False))
        
        # Update the record to Verified after the file is added
        cursor.execute('''
            UPDATE files
            SET Verified = ?
            WHERE ID = ? AND FileName = ?
        ''', (True, clients_dict[client_name].id, file_name))
        
        conn_db.commit()

def handle_file_transfer(conn, client_name):
    """
    Manages the file transfer process, including retries, decryption, and saving.
    
    Args:
        conn: The connection object for receiving/sending packets.
        client_name (str): Name of the client sending the file.
        
    Returns:
        str: SUCCESS if file transfer completed; otherwise, ERROR or GENERAL_ERROR.
    """
    for i in range(NUMBER_OF_ATTEMPTS):
        # Receive the initial packet and check if it is valid
        packet = recv_packet(conn)
        if packet['code'] != 828:
            if i == NUMBER_OF_ATTEMPTS - 1:
                print(f"Too many failed attempts. Incorrect packet code: {packet['code']}")
                return ERROR
            print(f"Error: Invalid first packet code: {packet['code']}")
            continue

        # Extract metadata for receiving the full file
        file_name, total_packets, enc_file_size, file_size, enc_file_content = RequestUnpacker.getFileMetadata(packet)
        print(f"Receiving file {file_name} from {client_name}, expecting {total_packets} packets.")

        enc_file_content = get_enc_file_content(conn, file_name, total_packets, enc_file_size, file_size, enc_file_content)
        if not enc_file_content:
            if i == NUMBER_OF_ATTEMPTS - 1:
                print("Too many failed attempts. Error in receiving content.")
                return ERROR
            continue

        file_content = decrypt_file_content(enc_file_content, client_name, file_size)
        if not file_content:
            if i == NUMBER_OF_ATTEMPTS - 1:
                print("Too many failed attempts. Error in decryption.")
                return ERROR
            continue

        # Prepare and send file receipt confirmation packet
        checksum = cksum.memcrc(file_content)
        file_recv_pckt = ResponsePacker.FileReceivedPacker(SERVER_VER, clients_dict[client_name].id, len(file_content), file_name, checksum)
        send_packet(conn, file_recv_pckt.pack())
        packet = recv_packet(conn)

        # Process response packet to finalize transfer
        if packet['code'] == 900:
            fin_pckt = ResponsePacker.AcceptingMessagePacker(SERVER_VER, clients_dict[client_name].id)
            send_packet(conn, fin_pckt.pack())
            file_path = save_file_to_disk(client_name, file_name, file_content)
            update_file_in_database(client_name, file_name, file_path)
            print(f"File successfully received: {file_size} bytes.")
            return SUCCESS
        elif packet['code'] == 902 or i == NUMBER_OF_ATTEMPTS - 1:
            print("File transfer failed after multiple attempts.")
            fin_pckt = ResponsePacker.AcceptingMessagePacker(SERVER_VER, clients_dict[client_name].id)
            send_packet(conn, fin_pckt.pack())
            return SUCCESS
        elif packet['code'] == 901:
            continue
        else:
            print(f"Error: Unexpected packet code: {packet['code']}")
            return GENERAL_ERROR

# **********************************************************************
# General server functions
# **********************************************************************
def handle_client(conn, addr):
    """
    Manages client connection lifecycle, including registration/reconnection, key exchange, and file transfer.
    
    Args:
        conn: The client connection socket.
        addr: Address of the connected client.
    """
    try:
        print(f"\nConnected by {addr}")

        # Receive and validate the initial packet from the client
        packet = recv_packet(conn)
        if packet['code'] not in [825, 827]:  # Codes for registration and reconnection
            print("Invalid packet code. Exiting with a general error.")
            return retry_on_general_error(conn, packet)

        # Map packet codes to corresponding handler functions for processing
        handlers = {825: handle_registration, 827: handle_reconnection}
        is_reg = (packet['code'] == 825)

        # Attempt to process registration or reconnection step
        if not process_step(conn, handlers[packet['code']], packet, conn):
            return  # Exit if the step fails after retries

        client_name = packet['name']
        
        # Process the public key exchange
        print("")
        if not process_step(conn, handle_public_key, client_name, conn, is_reg=is_reg):
            return

        # Initiate the file transfer process
        print("")
        if not process_step(conn, handle_file_transfer, conn, client_name=client_name):
            return

    except Exception as e:
        print(f"Client handling error: {e}")
    finally:
        print(f"Connection closed. See you soon!")
        conn.close()

def process_step(conn, handler_func, *args, **kwargs):
    """
    Executes a client interaction step, with retries for general errors or exceptions.
    
    Args:
        conn: The connection object.
        handler_func: The function to handle the specific step.
        *args, **kwargs: Arguments and keyword arguments for the handler function.
    
    Returns:
        bool: True if the step completes successfully, False on unrecoverable errors.
    """
    max_attempts = 3  # Maximum retry attempts
    attempts = 0

    while attempts < max_attempts:
        try:
            # Run the handler function for the current step
            result = handler_func(*args, **kwargs)
            if result == ERROR:
                handle_error(conn)  # Close connection on hard error
                return False
            elif result == GENERAL_ERROR:
                print(f"General error encountered. Retrying {attempts + 1}/{max_attempts}...")
                if retry_on_general_error(conn, *args):
                    attempts += 1
                else:
                    print("Exceeded max retries for general error.")
                    return False
            else:
                return True  # Step completed successfully
        except Exception as e:
            print(f"Exception encountered: {e}. Retrying {attempts + 1}/{max_attempts}...")
            attempts += 1

    print("Exceeded max retries due to persistent exceptions.")
    return False

def retry_on_general_error(conn, *args):
    """
    Manages general errors by sending an error response to the client and checking for retry eligibility.
    
    Args:
        conn: The client connection object.
        *args: Expected packet for retry comparison.
    
    Returns:
        bool: True if retry is permitted, False if retry limit is reached or packets do not match.
    """
    send_packet(conn, ResponsePacker.GeneralErrorPacker(SERVER_VER).pack())
    packet = recv_packet(conn)
    if packet == args[0]:  # Verifies if the received packet matches expected packet
        return True
    else:
        print("Unexpected packet received during retry.")
        return False

def handle_error(conn):
    """
    Handles unrecoverable errors by logging and closing the connection.
    
    Args:
        conn: The client connection object.
    """
    print("Exiting due to an error.")
    conn.close()

def start_server():
    """
    Initializes the server, binds it to the specified host and port, and begins listening for connections.
    Launches a new thread for each client connection to handle them concurrently.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server started and listening on {HOST}:{PORT}...")

        while True:
            # Accept a new client connection and start a thread to handle the client
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

# **********************************************************************
# main
# **********************************************************************
if __name__ == '__main__':
    try:
        initialize_database()
        load_clients()
        start_server()
    except KeyboardInterrupt:
        print("\nServer shutting down gracefully...")
    except Exception as e:
        print(f"Server error: {e}")
