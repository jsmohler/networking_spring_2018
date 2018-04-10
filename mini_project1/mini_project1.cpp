//============================================================================
// Name        : mini_project1.cpp
// Author      : Jordan Mohler
// Version     : 1
// Description : UDP Client Modifications
//============================================================================


#include <iostream>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <stdlib.h>
#include <sys/types.h>

using namespace std;

// #include "udpserver.h"

/**
 *
 * Dead simple UDP client example. Reads in IP PORT DATA
 * from the command line, and sends DATA via UDP to IP:PORT.
 *
 * e.g., ./udpclient 127.0.0.1 8888 this_is_some_data_to_send
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
    // Alias for argv[3] for convenience
    char *data_string;
    // Port to send UDP data to. Need to convert from command line string to a number
    unsigned int port;
    // The socket used to send UDP data on
    int udp_socket;
    // Variable used to check return codes from various functions
    int ret;
    // IPv4 structure representing and IP address and port of the destination
    struct sockaddr_in dest_addr;
    // Variable used to check amount of returned data
    int byte_count;
    //buffer for recv function
    char buf[2048];
    struct sockaddr_in addr;
    socklen_t fromlen = sizeof(struct sockaddr_in);


    // Set dest_addr to all zeroes, just to make sure it's not filled with junk
    // Note we could also make it a static variable, which will be zeroed before execution
    memset(&dest_addr, 0, sizeof(struct sockaddr_in));

    // Note: this needs to be 4, because the program name counts as an argument!
    if (argc < 4) {
        std::cerr << "Please specify IP PORT DATA as first three arguments." << std::endl;
        return 1;
    }
    // Set up variables "aliases"
    ip_string = argv[1];
    port_string = argv[2];
    data_string = argv[3];

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

    // Send the data to the destination.
    // Note 1: we are sending strlen(data_string) + 1 to include the null terminator
    // Note 2: we are casting dest_addr to a struct sockaddr because sendto uses the size
    //         and family to determine what type of address it is.
    // Note 3: the return value of sendto is the number of bytes sent
    ret = sendto(udp_socket, data_string, strlen(data_string) + 1, 0,
                 (struct sockaddr *)&dest_addr, sizeof(struct sockaddr_in));

    // Check if send worked, clean up and exit if not.
    if (ret == -1) {
        std::cerr << "Failed to send data!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    //std::cout << "Sent " << ret << " bytes out." << std::endl;

    /**
     * Code to receive response from the server goes here!
     * recv or recvfrom...
     */

    byte_count = recvfrom(udp_socket, buf, 2047, 0, (struct sockaddr *)&addr, &fromlen);

    // Check if receive worked, clean up and exit if not.
    if (byte_count == -1) {
        std::cerr << "Failed to receive data!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    struct ServerResponse {
        uint16_t type;
        uint16_t secret;
    };

    if (byte_count < sizeof(ServerResponse)) {
        std::cerr << "Failed to receive enough data!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    
    uint16_t type = buf[0] | uint16_t(buf[1]) << 8;
    uint16_t secret = buf[2] | uint16_t(buf[3]) << 8;

    type = ntohs(type);
    secret = ntohs(secret);

    if (type == 0) {
        cout << "Received ECHO response from server. Secret was " << secret << endl;
        cout << "Echoed string was: ";
        for (int i = sizeof(ServerResponse); i < byte_count; i++) {
            cout << buf[i];
        }
        cout << endl;
    } else if (type == 1) {
        cout << "Received EMPTY response from server. Secret was " << secret << endl;
    } else if (type == 2) {
        cout << "Received ERROR response from server. Secret was " << secret << endl;
        cout << "Error string was: ";
        for (int i = sizeof(ServerResponse); i < byte_count; i++) {
            cout << buf[i];
        }
        cout << endl;
    } else {
        std::cerr << "Response type unknown!" << std::endl;
        std::cerr << strerror(errno) << std::endl;
        close(udp_socket);
        return 1;
    }

    close(udp_socket);
    return 0;
}
