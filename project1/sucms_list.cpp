//Project 1 by Jordan Mohler

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
#include <openssl/md5.h>

#include "SUCMS.h"

std::string get_username() {
  std::string username;
  std::cout << "Enter username: ";
  std::getline(std::cin, username);
  return username;
}

std::string get_password() {
  std::string password;
  std::cout << "Enter password: ";
  std::getline(std::cin, password);
  //MD% and return
}

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
  char buf[MAX_SEGMENT_SIZE];

  // Set dest_addr to all zeroes, just to make sure it's not filled with junk
  // Note we could also make it a static variable, which will be zeroed before execution
  memset(&dest_addr, 0, sizeof(struct sockaddr_in));

  // Note: this needs to be 3, because the program name counts as an argument!
  if (argc < 5) {
    std::cerr << "Please specify IP PORT USERNAME PASSWORD as first four arguments." << std::endl;
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

  //username and password
  std::string username = argv[3];
  std::string pswd = argv[4];
  unsigned char password[16];

  MD5((const unsigned char*) pswd.c_str(), pswd.length(), password);

  //Build SUCMS Header + COMMAND_LIST + username
  struct SUCMSHeader header;
  header.sucms_msg_type = htons(MSG_COMMAND);
  header.sucms_msg_length = htons(sizeof(username) + sizeof(struct CommandMessage));

  struct CommandMessage list_command;

  list_command.username_len = htons(username.length());
  list_command.command = htons(COMMAND_LIST);

  for(int i = 0; i < 16; i++) {
    list_command.password_hash[i] = password[i];
  }

  //list_command.password_hash = htons(list_command.password_hash);

  memcpy(buf, &header, sizeof(struct SUCMSHeader));
  memcpy(&buf[sizeof(struct SUCMSHeader)], &list_command, sizeof(struct CommandMessage));
  memcpy(&buf[sizeof(struct SUCMSHeader)+sizeof(struct CommandMessage)], username.c_str(), username.length());

  int msg_size = sizeof(struct SUCMSHeader)+sizeof(struct CommandMessage)+ username.length();

  //Send SUCMS Header + COMMAND_LIST + username
  ret = sendto(udp_socket, &buf, msg_size, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

  // Check if sent the correct amount, clean up and exit if not.
  if (ret != msg_size) {
    std::cerr << "Sent " << ret << " instead of " << msg_size << "."  << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  //Receive response SUCMSHeader + CommandResponse
  struct sockaddr_in recv_addr;
  socklen_t recv_addr_len = sizeof(struct sockaddr_in);;
  ret = recvfrom(udp_socket, buf, MAX_SEGMENT_SIZE, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);

  //Parse response
  uint16_t response_type;
  memcpy(&response_type, &buf[0], 2);
  response_type = ntohs(response_type);

  uint16_t response_length;
  memcpy(&response_length, &buf[2], 2);
  response_length = ntohs(response_length);

  uint16_t response_code;
  memcpy(&response_code, &buf[4], 2);
  response_code = ntohs(response_code);

  uint16_t id;
  memcpy(&id, &buf[6], 2);
  id = ntohs(id);

  uint32_t data_size;
  memcpy(&data_size, &buf[8], 4);
  data_size = ntohs(data_size);

  uint16_t message_count;
  memcpy(&message_count, &buf[12], 2);
  message_count = ntohs(message_count);

  //Check if received the correct amount, clean up and exit if not.
  if (ret != response_length) {
    std::cerr << "Received " << ret << " instead of " << response_length << "."  << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  if (response_code == AUTH_OK){
    std::cout << "It worked!\n";
  } else if (response_code == AUTH_FAILED) {
    std::cout << "Booooo! Bad username/password\n";
  } else  {
    std::cout << "Something went very very wrong :(\n";
    std::cout << "Response Type: " << response_type << std::endl;
  }


}
