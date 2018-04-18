//
//Mini-project 2 by Jordan Mohler and Victoria Fernalld
//
#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "udp_chat.h"

// #include "udpserver.h"

// Variable used to shut down the monitor when ctrl+c is pressed.
static bool stop = false;

// Handler for when ctrl+c is pressed.
// Just set the global 'stop' to true to shut down the server.
void handle_ctrl_c(int the_signal) {
  std::cout << "Handled sigint\n";
  stop = true;
}



/**
 * UDP chat monitor. Connects to a chat server and
 * simply prints out data to the client until it quits.
 *
 * e.g., ./udpchatmonitor 127.0.0.1 8888
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


  // Set dest_addr to all zeroes, just to make sure it's not filled with junk
  // Note we could also make it a static variable, which will be zeroed before execution
  memset(&dest_addr, 0, sizeof(struct sockaddr_in));

  struct sigaction ctrl_c_handler;
  ctrl_c_handler.sa_handler = handle_ctrl_c;
  sigemptyset(&ctrl_c_handler.sa_mask);
  ctrl_c_handler.sa_flags = 0;
  sigaction(SIGINT, &ctrl_c_handler, NULL);

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

  // First we will send a connect monitor message.
  ChatMonMsg connect = {
          htons(MON_CONNECT),
          htons(0),
          htons(0)
  };

  ret = sendto(udp_socket, &connect, sizeof(connect), 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

  // Check if send worked, clean up and exit if not.
  if (ret == -1) {
    std::cerr << "Failed to connect!" << std::endl;
    std::cerr << strerror(errno) << std::endl;
    close(udp_socket);
    return 1;
  }

  // After sending the connect monitor message, the monitor will just
  // sit and wait for messages to output. Easy peasy.
  struct sockaddr_in recv_addr;
  socklen_t recv_addr_len = sizeof(struct sockaddr_in);;
  char recv_buf[2048];
  uint16_t mon_type;
  uint16_t nickname_length;
  uint16_t data_len;


  while (stop == false) {
    //Receive message data from server
    ret = recvfrom(udp_socket, recv_buf, 2047, 0, (struct sockaddr *)&recv_addr, &recv_addr_len);

    //Get header information
    memcpy(&mon_type, &recv_buf[0], 2);
    memcpy(&nickname_length, &recv_buf[2], 2);
    memcpy(&data_len, &recv_buf[4], 2);
    mon_type = ntohs(mon_type);
    nickname_length = ntohs(nickname_length);
    data_len = ntohs(data_len);

    // Check if received the correct amount, clean up and exit if not.
    if (ret != 6+nickname_length+data_len && ret != -1) {
      std::cerr << "Received " << ret << " instead of " << sizeof(ChatMonMsg)+nickname_length+data_len << "."  << std::endl;
      std::cerr << strerror(errno) << std::endl;
      close(udp_socket);
      return 1;
    }

    if (ret != -1) {
      char nickname[nickname_length];
      for (int i = 0; i < nickname_length; i++) {
        nickname[i] = recv_buf[i+sizeof(ChatMonMsg)];
      }

      char message[data_len];
      for (int i = 0; i < data_len; i++) {
        message[i] = recv_buf[i+sizeof(ChatMonMsg)+nickname_length];
      }
      printf("%s said: %s\n", nickname, message);

      memset(nickname, 0, sizeof(nickname));
      memset(message, 0, sizeof(message));
    }
  }

  //Send disconnect message
  ChatMonMsg disconnect = {
          htons(MON_DISCONNECT),
          htons(0),
          htons(0)
  };

  ret = sendto(udp_socket, &disconnect, sizeof(disconnect), 0,
               (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

  // Be nice and inform the server that we're no longer listening.
  std::cout << "Shut down message sent to server, exiting!\n";

  close(udp_socket);
  return 0;
}
