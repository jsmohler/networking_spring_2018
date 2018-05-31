#include <iostream>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <vector>
#include <sys/types.h>
#include <netdb.h>
#include "openssl/sha.h"
#include "P2P.h"
#include "TCPClient.h"


void parse_P2PHeader(struct P2PHeader &header, char* data) {
  memcpy(&header.type, &data, 2);
  header.type = ntohs(header.type);
  memcpy(&header.length, &data[2], 2);
  header.length = ntohs(header.length);

  memcpy(&header.msg_hash, &data[4], 32);
}

void parse_connect_message(struct ConnectMessage &message, char* data) {
  memcpy(&message.control_header.header.type, &data, 2);
  message.control_header.header.type = ntohs(message.control_header.header.type);

  memcpy(&message.control_header.header.length, &data[2], 2);
  message.control_header.header.length = ntohs(message.control_header.header.length);

  memcpy(&message.control_header.header.msg_hash, &data[4], 32);

  memcpy(&message.control_header.control_type, &data[36], 2);
  message.control_header.control_type = ntohs(message.control_header.control_type);

  memcpy(&message.peer_data.peer_listen_port, &data[38], 2);
  message.peer_data.peer_listen_port = ntohs(message.peer_data.peer_listen_port);

  memcpy(&message.peer_data.ipv4_address, &data[44], 2);
  message.peer_data.ipv4_address = ntohs(message.peer_data.ipv4_address);
}

void update_message_digest(struct P2PHeader &header, const unsigned char* data) {
  unsigned char* hash = new unsigned char[32];
  size_t length = header.length - sizeof(P2PHeader);
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, &data, length);
  SHA256_Final(hash, &sha256);
  memcpy(&header.msg_hash, &hash, 32);
}

void parse_control_message(struct ControlMessage &message, char* data) {
  parse_P2PHeader(message.header, data);
  memcpy(&message.control_type, &data[sizeof(P2PHeader)], 2);
  message.control_type = ntohs(message.control_type);
}

void parse_data_message(struct DataMessage *message, char* data) {
  // parse_P2PHeader(&message.header, data);
  // memcpy(&message.data_type, &data[sizeof(P2PHeader)], 2);
  // message.data_type = ntohs(message.data_type);
}

void parse_error_message(struct ErrorMessage *message, char* data) {
  // parse_P2PHeader(&message.header, data);
  // memcpy(&message.error_type, &data[sizeof(P2PHeader)], 2);
  // message.error_type = ntohs(message.error_type);
}

int main(int argc, char *argv[]) {
  struct sockaddr_storage incoming_client;
  socklen_t incoming_client_len;
  std::vector<TCPClient *> client_list;
  std::vector<unsigned char*> message_history;
  TCPClient *temp_client;
  TCPClient *seed_client;
  char recv_buf[DEFAULT_BUFFER_SIZE];
  char send_buf[DEFAULT_BUFFER_SIZE];
  char scratch_buf[DEFAULT_BUFFER_SIZE];
  struct timeval timeout;

  struct addrinfo hints;
  struct addrinfo *results;
  struct addrinfo *results_it;

  struct addrinfo seed_hints;
  struct addrinfo *seed_results;
  struct addrinfo *seed_results_it;

  char *listen_hostname = NULL;
  char *listen_port = NULL;
  char *seed_host = NULL;
  char *seed_port = NULL;

  int server_socket;
  int seed_socket;
  int temp_fd;

  struct sockaddr* listen_address;
  int server_family;

  int ret;
  bool stop = false;

  fd_set read_set;
  fd_set write_set;
  int max_fd;

  if ((argc != 5)) {
    std::cerr << "Specify LISTEN_HOST LISTEN_PORT SEED_HOST SEED_PORT as first four arguments." << std::endl;
    return 1;
  }

  listen_hostname = argv[1];
  listen_port = argv[2];
  seed_host = argv[3];
  seed_port = argv[4];

  uint16_t l_port;
  int temp_port = atoi(listen_port);
  memcpy(&l_port, &temp_port, 2);

  // Create the TCP socket.
  // AF_INET is the address family used for IPv4 addresses
  // SOCK_STREAM indicates creation of a TCP socket
  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  // Make sure socket was created successfully, or exit.
  if (server_socket == -1) {
    std::cerr << "Failed to create tcp socket!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    return 1;
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_family = AF_INET;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_socktype = SOCK_STREAM;
  ret = getaddrinfo(listen_hostname, listen_port, &hints, &results);
  if (ret != 0) {
    std::cerr << "Getaddrinfo failed with error " << ret << std::endl;
    perror("getaddrinfo");
    return 1;
  }
  results_it = results;
  ret = -1;

  while (results_it != NULL) {
    ret = bind(server_socket, results_it->ai_addr, results_it->ai_addrlen);
      if (ret == 0) {
        break;
      }
      perror("bind");
      results_it = results_it->ai_next;
    }
    // Always free the result of calling getaddrinfo
    freeaddrinfo(results);

    listen_address = results_it->ai_addr;
    server_family = results_it->ai_family;

    if (ret != 0) {
      std::cerr << "Failed to bind to any addresses. Be sure to specify a local address/hostname, and an unused port?"
      << std::endl;
      return 1;
    }

    // Listen on the server socket with a max of 50 outstanding connections.
    ret = listen(server_socket, 50);

    if (ret != 0) {
      perror("listen");
      close(server_socket);
      return 1;
    }

    //Get nickname
    std::string nickname("");
    std::cout << "Please enter a nickname: ";
    std::cin >> nickname;

    // Create the TCP socket.
    // AF_INET is the address family used for IPv4 addresses
    // SOCK_STREAM indicates creation of a TCP socket
    seed_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (seed_socket == -1) {
      std::cerr << "Failed to create tcp socket!" << std::endl;
      std::cerr << strerror(errno) << std::endl;
      return 1;
    }

    //Connect to Seed Host
    // Create a new TCPClient from the connection
    memset(&seed_hints, 0, sizeof(struct addrinfo));
    seed_hints.ai_addr = NULL;
    seed_hints.ai_canonname = NULL;
    seed_hints.ai_family = AF_INET;
    seed_hints.ai_protocol = 0;
    seed_hints.ai_flags = AI_PASSIVE;
    seed_hints.ai_socktype = SOCK_STREAM;

    ret = getaddrinfo(seed_host, seed_port, &seed_hints, &seed_results);
    if (ret != 0) {
      std::cerr << "Getaddrinfo failed with error " << ret << std::endl;
      perror("getaddrinfo");
      return 1;
    }
    seed_results_it = seed_results;
    ret = -1;

    seed_client = new TCPClient(seed_socket, (struct sockaddr_storage *) seed_results_it->ai_addr, seed_results_it->ai_addrlen);

    //Connect to seed host
    while (seed_results_it != NULL) {
      ret = connect(seed_socket, seed_results_it->ai_addr, seed_results_it->ai_addrlen);
      if (ret == 0) {
          client_list.push_back(seed_client);
          std::cout << "Connected to seed host\n";
          break;
      }
      perror("connect");
      seed_results_it = seed_results_it->ai_next;
    }
    // Always free the result of calling getaddrinfo
    freeaddrinfo(results);

    max_fd = 0;

    while (stop == false) {
      FD_ZERO(&read_set);
      FD_ZERO(&write_set);

      // Mark the server_socket in the read set
      // If this is then set, it means we need to accept a new connection.
      FD_SET(server_socket, &read_set);

      if (server_socket > max_fd)
      max_fd = server_socket + 1;

      // For each client, set the appropriate descriptors in the select sets
      for (int i = 0; i < client_list.size(); i++) {
        // Lazy-legacy check. If we don't remove a client immediately set the vector entry to NULL
        if (client_list[i] == NULL) {
          continue;
        }

        // Always check if the client has sent us data
        FD_SET(client_list[i]->get_fd(), &read_set);

        // Check if client has data to send. If so, add it to the write_set
        // If there isn't data to write, don't set it (prevents pegging CPU)
        if (client_list[i]->bytes_ready_to_send() > 0) {
          FD_SET(client_list[i]->get_fd(), &write_set);
        }

        if (client_list[i]->get_fd() > max_fd)
        max_fd = client_list[i]->get_fd() + 1;
      }

      // If select hasn't returned after 5 seconds, return anyways so other asynchronous events can be triggered
      // HINT: send a find_peer request?
      timeout.tv_sec = 5;
      timeout.tv_usec = 0;

      ret = select(max_fd + 1, &read_set, &write_set, NULL, &timeout);

      if (ret == -1) {
        perror("select");
        continue;
      }

      // Check if server_socket is in the read set. If so, a new client has connected to us!
      if (FD_ISSET(server_socket, &read_set)) {
        temp_fd = accept(server_socket, (struct sockaddr *) &incoming_client, &incoming_client_len);
        if (temp_fd == -1) {
          perror("accept");
          continue;
        }

        // Create a new TCPClient from the connection
        temp_client = new TCPClient(temp_fd, &incoming_client, incoming_client_len);

        //Send ConnectMessage
        // Structure to fill in with connect message info
        struct ConnectMessage connect;
        // Zero out structure
        memset(&connect, 0, sizeof(struct ConnectMessage));
        connect.control_header.header.type = htons(CONTROL_MSG);
        connect.control_header.header.length = htons(sizeof(struct ConnectMessage));
        connect.control_header.control_type = htons(CONNECT);

        //Could have both, but might not
        if (results_it->ai_family == AF_INET) {
          memcpy(&connect.peer_data.ipv4_address, &listen_address, sizeof(struct in_addr));
        }
        if (results_it->ai_family == AF_INET6) {
          memcpy(&connect.peer_data.ipv6_address, &listen_address, sizeof(struct in6_addr));
        }

        connect.peer_data.peer_listen_port = htons(l_port);

        // Create hash after filling in rest of message.
        unsigned char* connect_data;
        memcpy(&connect_data, &connect, sizeof(struct ConnectMessage));
        update_message_digest(connect.control_header.header, connect_data);

        if (temp_client->add_send_data((char *) &connect, sizeof(struct ConnectMessage)) != true) {
          std::cerr << "Failed to add send data to client!" << std::endl;
        }
        //
        // //Send connect message
        // // Store how many bytes this client has ready to send
        // int send_bytes = temp_client->bytes_ready_to_send();
        // // Copy send bytes into our local send buffer
        // temp_client->get_send_data(send_buf, DEFAULT_BUFFER_SIZE);
        // // Finally, send the data to the client.
        // ret = send(temp_client->get_fd(), send_buf, send_bytes, 0);

        // Add the new client to the list of clients we have
        client_list.push_back(temp_client);
      }

      for (int i = 0; i < client_list.size(); i++) {
        // Lazy-legacy check. If we don't remove a client immediately set the vector entry to NULL
        if (client_list[i] == NULL) {
          continue;
        }

        // Check if this client has sent us data
        if (FD_ISSET(client_list[i]->get_fd(), &read_set)) {
          ret = recv(client_list[i]->get_fd(), recv_buf, DEFAULT_BUFFER_SIZE, 0);
          if (ret == -1) {
            perror("recv");
            // On error, something bad bad has happened to this client. Remove.
            close(client_list[i]->get_fd());
            client_list.erase(client_list.begin() + i);
            break;
          } else if (ret == 0) {
            // On 0 return, client has initiated connection shutdown.
            close(client_list[i]->get_fd());
            client_list.erase(client_list.begin() + i);
            break;
          } else {
            // Add the newly received data to the client buffer
            client_list[i]->add_recv_data(recv_buf, ret);
          }
        }

        // Check if this client data to send
        if ((client_list[i]->bytes_ready_to_send() > 0) && (FD_ISSET(client_list[i]->get_fd(), &write_set))) {
          // Store how many bytes this client has ready to send
          int bytes_to_send = client_list[i]->bytes_ready_to_send();
          // Copy send bytes into our local send buffer
          client_list[i]->get_send_data(send_buf, DEFAULT_BUFFER_SIZE);
          // Finally, send the data to the client.
          ret = send(client_list[i]->get_fd(), send_buf, bytes_to_send, 0);
          if (ret == -1) {
            perror("send");
            // On error, something bad bad has happened to this client. Remove.
            close(client_list[i]->get_fd());
            client_list.erase(client_list.begin() + i);
            break;
          }
        }

        // Finally, process any incoming client data. For this silly example, if we have received data
        // just add it to the same client's send buffer.
        if (client_list[i]->bytes_ready_to_recv() > 0) {
          // Store how many bytes are ready to be handled
          int bytes_to_process = client_list[i]->bytes_ready_to_recv();

          // Read the data into a temporary buffer
          client_list[i]->get_recv_data(scratch_buf, DEFAULT_BUFFER_SIZE);

          //Check message type
          struct P2PHeader header;
          uint16_t type;
          memcpy(&type, &scratch_buf, 2);
          type = ntohs(type);

          if (type == CONTROL_MSG) {

            struct ControlMessage control_message;
            std::cout << "Received Control Message.\n";
            parse_control_message(control_message, scratch_buf);

            if (control_message.control_type == CONNECT) {
              //Send CONNECT_OK
              std::cout << "Received Connect Message.\n";
              struct ConnectMessage connect;
              parse_connect_message(connect, scratch_buf);

              //Send ConnectMessage with CONNECT_OK
              // Structure to fill in with connect message info
              //struct ConnectMessage connect;
              // Zero out structure
              memset(&connect, 0, sizeof(struct ConnectMessage));

              connect.control_header.header.type = htons(CONTROL_MSG);
              connect.control_header.header.length = htons(sizeof(struct ConnectMessage));
              connect.control_header.control_type = htons(CONNECT_OK);

              //Could have both, but might not
              if (server_family == AF_INET) {
                memcpy(&connect.peer_data.ipv4_address, &listen_address, sizeof(struct in_addr));
              }

              if (server_family == AF_INET6) {
                memcpy(&connect.peer_data.ipv6_address, &listen_address, sizeof(struct in6_addr));
              }

              connect.peer_data.peer_listen_port = htons(l_port);

              // Create hash after filling in rest of message.
              unsigned char* connect_data;
              memcpy(&connect_data, &connect, sizeof(struct ConnectMessage));
              update_message_digest(connect.control_header.header, connect_data);

              if (client_list[i]->add_send_data((char *) &connect, sizeof(struct ConnectMessage)) != true) {
                std::cerr << "Failed to add send data to client!" << std::endl;
              }

            } else if (control_message.control_type == CONNECT_OK) {
              //Do Nothing
              std::cout << "Received Connect OK Message.\n";
            } else if (control_message.control_type == DISCONNECT) {
              //Disconnect
              std::cout << "Received Disconnect Message.\n";
            } else if (control_message.control_type == FIND_PEERS) {
              //Add find peers function
              std::cout << "Received Find Peers Message.\n";
            } else if (control_message.control_type == GOSSIP_PEERS) {
              //Add gossip peers function
              std::cout << "Received Gossip Peers Message.\n";
            } else {
              std::cout << "Something went very, very wrong.\n";
              std::cout << "Control Message Type: " << header.type << std::endl;
            }

          } else if (type == DATA_MSG){

            struct DataMessage data_message;
            std::cout << "Received Data Message.\n";
            parse_data_message(&data_message, scratch_buf);

          } else if (type == ERROR_MSG) {

            struct ErrorMessage error_message;
            std::cout << "Received Error Message.\n";
            parse_error_message(&error_message, scratch_buf);

          } else {
            std::cout << "Something went very, very wrong.\n";
            std::cout << "P2P Header Message Type: " << header.type << std::endl;
          }

          // Add the data we received from this client into the send_buffer
          // Next time through the while loop, this will be detected and the data
          // will get sent out.
          //client_list[i]->add_send_data(scratch_buf, bytes_to_process);
        }
      }
    }
  }
