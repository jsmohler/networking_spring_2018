#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/select.h>
#include <vector>
#include <ctype.h>
#include <sys/time.h>
#include <fcntl.h>

#define RECEIVE_BUF_SIZE 2048

/*
 * Print IP:PORT of client address to stdout
 * @param client_addr
 */
void   print_address_details(sockaddr_in *client_addr) {
  static char addrbuf[INET_ADDRSTRLEN];
  const char *ret;
  ret = inet_ntop(AF_INET, &client_addr->sin_addr, addrbuf, INET_ADDRSTRLEN);

  if (ret != NULL) {
    std::cout << addrbuf << ":" << ntohs(client_addr->sin_port) << std::endl;
  }

  return;
}

/**
 *
 * TCP server example. Reads in IP PORT
 * from the command line, and sends DATA via TCP to IP:PORT.
 *
 * e.g., ./tcpclient 127.0.0.1 8888
 *
 * @param argc count of arguments on the command line
 * @param argv array of command line arguments
 * @return 0 on success, non-zero if an error occurred
 */
int main(int argc, char *argv[]) {
  // Alias for argv[1] for convenience
  char *ip_string;
  // Alias for argv[2] for convenience
  char *port_string;

  // Port to send TCP data to. Need to convert from command line string to a number
  unsigned int port;
  // The socket used to receive data
  int tcp_socket;
  // Variable used to check return codes from various functions
  int ret;

  int client_socket;
  struct sockaddr_in client_addr;
  socklen_t client_addr_len;

  struct addrinfo hints;
  struct addrinfo *results;
  struct addrinfo *results_it;
  fd_set readset;
  fd_set writeset;
  fd_set exceptset;
  struct timeval timeout;


  // Note: this needs to be 3, because the program name counts as an argument!
  if (argc < 3) {
    std::cerr << "Please specify IP PORT as first two arguments." << std::endl;
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];

  // Create the TCP socket.
  // AF_INET is the address family used for IPv4 addresses
  // SOCK_STREAM indicates creation of a TCP socket
  tcp_socket = socket(AF_INET, SOCK_STREAM, 0);

  // Make sure socket was created successfully, or exit.
  if (tcp_socket == -1) {
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
  // Instead of using inet_pton, use getaddrinfo to convert.
  ret = getaddrinfo(ip_string, port_string, &hints, &results);

  if (ret != 0) {
    std::cerr << "Getaddrinfo failed with error " << ret << std::endl;
    perror("getaddrinfo");
    return 1;
  }

  // Check we have at least one result
  results_it = results;

  while (results_it != NULL) {
    std::cout << "Trying to bind to something?" << std::endl;
    ret = bind(tcp_socket, results_it->ai_addr, results_it->ai_addrlen);
    if (ret == 0) {
      break;
    }
    perror("bind");
    results_it = results_it->ai_next;
  }

  // Whatever happened, we need to free the address list.
  freeaddrinfo(results);

  // Check if connecting succeeded at all
  if (ret != 0) {
    std::cout << "Failed to bind to any addresses!" << std::endl;
    return 1;
  }

  // If we get here, the bind worked. Now listen.
  ret = listen(tcp_socket, 50);

  // Check if listen worked, clean up and exit if not.
  if (ret == -1) {
    std::cerr << "Failed to listen!" << std::endl;
    perror("listen");
    std::cerr << strerror(errno) << std::endl;
    close(tcp_socket);
    return 1;
  }

  std::vector<int> client_sockets;



  while(true) {
    int maxfd = tcp_socket;
    int max_client = client_socket;

    //zero out fd_sets
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    FD_ZERO(&exceptset);

    //set select lists
    FD_SET(tcp_socket, &readset);
    FD_SET(tcp_socket, &writeset);
    FD_SET(tcp_socket, &exceptset);

    for(int i = 0; i < client_sockets.size(); i++) {
      client_socket = client_sockets.at(i);

      //set select lists
      FD_SET(client_socket, &readset);
      FD_SET(client_socket, &writeset);
      FD_SET(client_socket, &exceptset);

      if (client_socket > max_client) {
        max_client = client_socket;
      }
    }

    //set timeout
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    ret = select(maxfd + 1, &readset, &writeset, &exceptset, &timeout);

    if (FD_ISSET(tcp_socket, &readset)) {
      client_addr_len = sizeof(struct sockaddr_in);
      client_socket = accept(tcp_socket, (struct sockaddr *) &client_addr, &client_addr_len);

      std::cout << "Accepted connection from : ";
      print_address_details(&client_addr);

      client_sockets.push_back(client_socket);
    }

    for(int i = 0; i < client_sockets.size(); i++) {
      client_socket = client_sockets.at(i);

      char recv_buf[RECEIVE_BUF_SIZE];
      std::cout << FD_ISSET(client_socket, &readset);
      if (FD_ISSET(client_socket, &readset)) {
        std::cout << "client in readset\n";
        ret = recv(client_socket, recv_buf, RECEIVE_BUF_SIZE - 1, 0);

        // Check if receive worked, clean up and exit if not.
        if (ret == -1) {
          std::cerr << "Failed to receive data!" << std::endl;
          perror("recv");
          std::cerr << strerror(errno) << std::endl;
          close(client_socket);
          close(tcp_socket);
          return 1;
        }

        std::cout << "Received " << ret << " bytes " << std::endl;
        recv_buf[ret] = '\0';

        std::cout << recv_buf << std::endl;
      }

      if (FD_ISSET(client_socket, &writeset)) {
        ret = send(client_socket, recv_buf, ret, 0);

        // Check if receive worked, clean up and exit if not.
        if (ret == -1) {
          std::cerr << "Failed to send data!" << std::endl;
          perror("send");
          std::cerr << strerror(errno) << std::endl;
          close(client_socket);
          close(tcp_socket);
          return 1;
        }

        std::cout << "Sent " << ret << " bytes " << std::endl;
      }
    }

  }



  close(tcp_socket);
  return 0;
}
