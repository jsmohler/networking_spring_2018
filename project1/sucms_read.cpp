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
#include <vector>

#include "SUCMS.h"

int build_command_message(int command, char* buf, std::string username, unsigned char* password, int size) {
  //Build SUCMS Header + COMMAND_LIST + username
  struct SUCMSHeader header;
  struct CommandMessage list_command;

  header.sucms_msg_type = htons(MSG_COMMAND);
  header.sucms_msg_length = htons(size);

  list_command.username_len = htons(username.length());
  list_command.command = htons(command);

  for(int i = 0; i < 16; i++) {
    list_command.password_hash[i] = password[i];
  }

  memcpy(buf, &header, sizeof(struct SUCMSHeader));
  memcpy(&buf[sizeof(struct SUCMSHeader)], &list_command, sizeof(struct CommandMessage));
  memcpy(&buf[sizeof(struct SUCMSHeader)+sizeof(struct CommandMessage)], username.c_str(), username.length());
  return 0;
}

int parse_response_header(char* buf, uint16_t *response_type, uint16_t *response_length, int index) {
  memcpy(response_type, &buf[index], 2);
  *response_type = ntohs(*response_type);

  memcpy(response_length, &buf[index+2], 2);
  *response_length = ntohs(*response_length);
  return 0;
}

int parse_command_response(char* buf, uint16_t *response_code, uint16_t *id, uint32_t *data_size, uint16_t *message_count, int index) {
  memcpy(response_code, &buf[index], 2);
  *response_code = ntohs(*response_code);

  memcpy(id, &buf[index+2], 2);
  *id = ntohs(*id);

  memcpy(data_size, &buf[index+4], 4);
  *data_size = ntohs(*data_size);

  memcpy(message_count, &buf[index+8], 2);
  *message_count = ntohs(*message_count);
  return 0;
}

int parse_file_data(char* buf, uint16_t *id, uint16_t *number, uint16_t *file_bytes, uint32_t *bytes_offset, int index){
  memcpy(id, &buf[index], 2);
  *id = ntohs(*id);

  memcpy(number, &buf[index+2], 2);
  *number = ntohs(*number);

  memcpy(file_bytes, &buf[index+4], 2);
  *file_bytes = ntohs(*file_bytes);

  memcpy(bytes_offset, &buf[index+6], 4);
  *bytes_offset = ntohs(*bytes_offset);
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
  if (argc < 3) {
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
  std::string username;
  std::cout << "Enter a username: \n";
  std::cin >> username;
  std::string pswd = argv[4];
  std::cout << "Enter a password: \n";
  std::cin >> pswd;
  std::string filename;
  std::cout << "Enter a filepath: \n";
  std::cin >> filename;
  unsigned char password[16];

  MD5((const unsigned char*) pswd.c_str(), pswd.length(), password);
  int msg_size = sizeof(struct SUCMSHeader) + sizeof(struct CommandMessage)+ username.length()+filename.length()+sizeof(struct SUCMSClientFileRWRequest);
  build_command_message(COMMAND_READ, buf, username, password, msg_size-sizeof(SUCMSHeader));

  //Send SUCMS Header + COMMAND_READ + username + SUCMSClientFileRWRequest + filename
  struct SUCMSClientFileRWRequest read_request;
  read_request.filename_length = htons(filename.length());
  read_request.result_id = 0;
  read_request.filesize_bytes = 0;

  memcpy(&buf[msg_size-sizeof(read_request)-filename.length()], &read_request, 8);
  memcpy(&buf[msg_size-filename.length()], filename.c_str(), filename.length());
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

  //Response variables
  uint16_t response_type;
  uint16_t response_length;
  uint16_t response_code;
  uint16_t id;
  uint32_t data_size;
  uint16_t message_count;
  uint16_t message_number;
  uint16_t file_bytes;
  uint32_t bytes_offset;

  parse_response_header(buf, &response_type, &response_length, 0);

  //Check if received the correct amount, clean up and exit if not.
  if (ret != response_length) {
    std::cerr << "Received " << ret << " instead of " << response_length << "."  << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  if (response_type == MSG_COMMAND_RESPONSE) {
    parse_command_response(buf, &response_code, &id, &data_size, &message_count, sizeof(struct SUCMSHeader));
    if (response_code == AUTH_OK){
      struct SUCMSClientGetResult result;
      result.command_type = htons(COMMAND_READ);
      msg_size = sizeof(struct SUCMSHeader) + sizeof(struct CommandMessage)+ username.length()+sizeof(struct SUCMSClientGetResult);

      std::string data;
      std::vector<void*> segments;
      message_number = 0;
      for (int i = 0; i < 5; i++) {
        result.result_id = htons(id);
        result.message_number = htons(i);

        //Send SUCMSHeader + CommandMessage + username + SUCMSClientGetResult
        build_command_message(COMMAND_CLIENT_GET_RESULT, buf, username, password, msg_size - sizeof(SUCMSHeader));

        memcpy(&buf[msg_size-sizeof(result)], &result, sizeof(result));

        //Send SUCMS Header + COMMAND_LIST + username + SUCMSClientMessage
        ret = sendto(udp_socket, &buf, msg_size, 0, (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

        // Check if sent the correct amount, clean up and exit if not.
        if (ret != msg_size) {
          std::cerr << "Sent " << ret << " instead of " << msg_size << "."  << std::endl;
          std::cerr << strerror(errno) << std::endl;
          close(udp_socket);
          return 1;
        }

        //Receive response SUCMSHeader + SUCMSFileDataResult + filedata
        ret = recvfrom(udp_socket, buf, MAX_SEGMENT_SIZE, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);
        parse_response_header(buf, &response_type, &response_length, 0);

        //Check if received the correct amount, clean up and exit if not.
        if (ret != response_length+sizeof(SUCMSHeader)) {
          std::cerr << "Received " << ret << " instead of " << response_length+sizeof(SUCMSHeader) << "."  << std::endl;
          std::cerr << strerror(errno) << std::endl;
          close(udp_socket);
          return 1;
        }

        if (response_type == MSG_FILE_DATA) {
          segments.push_back(buf);
          parse_file_data(buf, &id, &message_number, &file_bytes, &bytes_offset, sizeof(SUCMSHeader));

          std::string file_data = std::string(&buf[bytes_offset+10], &buf[bytes_offset+file_bytes+20]);
          data.append(file_data);
        } else {
          std::cout << "Something went very very wrong :(\n";
          std::cout << "Response Type: " << response_type << std::endl;
          parse_command_response(buf, &response_code, &id, &data_size, &message_count, sizeof(SUCMSHeader));
          std::cout << "Response Code: " << response_code << std::endl;
        }

      }

      std::cout << "Data: " << data << std::endl;

    } else if (response_code == AUTH_FAILED) {
      std::cout << "Received AUTH_FAILED from server.\n";
    } else if (response_code == NO_SUCH_FILE) {
      std::cout << "Received NO_SUCH_FILE from server.\n";
    } else {
      std::cout << "Something went very very wrong :(\n";
      std::cout << "Response Code: " << response_code << std::endl;
    }
  } else {
    std::cout << "Something went very very wrong :(\n";
    std::cout << "Response Type: " << response_type << std::endl;
  }

}
