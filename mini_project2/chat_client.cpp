//Mini-project 2 by Jordan Mohler and Victoria Fernalld

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

#include "udp_chat.h"

// #include "udpserver.h"
std::string get_nickname() {
  std::string nickname;
  std::cout << "Enter chat nickname: ";
  std::getline(std::cin, nickname);
  return nickname;
}

std::string get_message() {
  std::string nickname;
  std::cout << "Enter chat message to send, or quit to quit: ";
  std::getline(std::cin, nickname);
  return nickname;
}

/**
 *
 * UDP chat client example. Reads in IP PORT
 * from the command line, and sends DATA via UDP to IP:PORT.
 *
 * e.g., ./udpchatclient 127.0.0.1 8888
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

  // Port to send UDP data to. Need to convert from command line string to a number
  unsigned int port;
  // The socket used to send UDP data on
  int udp_socket;
  // Variable used to check return codes from various functions
  int ret;
  // IPv4 structure representing and IP address and port of the destination
  struct sockaddr_in dest_addr;
  std::string nickname;
  char send_buffer[2048];

  // Set dest_addr to all zeroes, just to make sure it's not filled with junk
  // Note we could also make it a static variable, which will be zeroed before execution
  memset(&dest_addr, 0, sizeof(struct sockaddr_in));

  // Note: this needs to be 3, because the program name counts as an argument!
  if (argc < 3) {
    std::cerr << "Please specify IP PORT as first two arguments." << std::endl;
    return 1;
  }
  // Set up variables "aliases"
  ip_string = argv[1];
  port_string = argv[2];

  // Create the UDP socket.
  // AF_INET is the address family used for IPv4 addresses
  // SOCK_DGRAM indicates creation of a UDP socket
  udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

  // Make sure socket was created successfully, or exit.
  if (udp_socket == -1) {
    std::cerr << "Failed to create udp socket!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    return 1;
  }

  // inet_pton converts an ip address string (e.g., 1.2.3.4) into the 4 byte
  // equivalent required for using the address in code.
  // Note that because dest_addr is a sockaddr_in (again, IPv4) the 'sin_addr'
  // member of the struct is used for the IP
  ret = inet_pton(AF_INET, ip_string, (void *)&dest_addr.sin_addr);

  // Check whether the specified IP was parsed properly. If not, exit.
  if (ret == -1) {
    std::cerr << "Failed to parse IPv4 address!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  // Convert the port string into an unsigned integer.
  ret = sscanf(port_string, "%u", &port);
  // sscanf is called with one argument to convert, so the result should be 1
  // If not, exit.
  if (ret != 1) {
    std::cerr << "Failed to parse port!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  // Set the address family to AF_INET (IPv4)
  dest_addr.sin_family = AF_INET;
  // Set the destination port. Use htons (host to network short)
  // to ensure that the port is in big endian format
  dest_addr.sin_port = htons(port);

  nickname = get_nickname();

  // Send connect message
  ChatClientMessage connect_msg;
  connect_msg.type = htons(CLIENT_CONNECT);
  connect_msg.data_length = htons(0);     //message is 4 bytes

  ret = sendto(udp_socket, &connect_msg, 4, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

  if (ret == -1) {
    std::cerr << "Failed to parse port!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  // Send nickname message
  //make ChatClientMessage for sending nickname
  ChatClientMessage nickname_msg;
  nickname_msg.type = htons(CLIENT_SET_NICKNAME);
  nickname_msg.data_length = htons(nickname.length());

  //Copy CCM and nickname into buffer
  memcpy(send_buffer, &nickname_msg, sizeof(nickname_msg));
  memcpy(&send_buffer[sizeof(nickname_msg)], nickname.c_str(), nickname.length());

  ret = sendto(udp_socket, &send_buffer, sizeof(nickname_msg) + nickname.length(), 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

  //Send messages until client quits
  std::string next_message;
  next_message = get_message();

  //Contruct message struct
  ChatClientMessage msg;

  while (next_message != "quit") {
    msg.type = htons(CLIENT_SEND_MESSAGE);
    msg.data_length = htons(next_message.length());

    //Copy CCM and nickname into buffer
    memcpy(send_buffer, &msg, sizeof(msg));
    memcpy(&send_buffer[sizeof(msg)], next_message.c_str(), next_message.length());

    std::cout << "Sending message " << next_message.c_str() << std::endl;

    ret = sendto(udp_socket, send_buffer, sizeof(ChatClientMessage) + next_message.length(), 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

    // Check if sent the correct amount, clean up and exit if not.
    if (ret != sizeof(msg)+next_message.length()) {
      std::cerr << "Sent " << ret << " instead of " << sizeof(msg)+next_message.length() << "."  << std::endl;
      std::cerr << strerror(errno) << std::endl;
      close(udp_socket);
      return 1;
    }

    next_message = get_message();
  }

  // Send client disconnect message
  ChatClientMessage disconnect_msg;
  connect_msg.type = htons(CLIENT_DISCONNECT);
  connect_msg.data_length = htons(4);     //message is 4 bytes

  ret = sendto(udp_socket, &disconnect_msg, 4, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

  close(udp_socket);
  return 0;
}
