//
// Created by nate on 4/20/18.
//

#ifndef UDP_PROJECT1_SUCMS_H_H
#define UDP_PROJECT1_SUCMS_H_H

#include <stdint.h>

#define MAX_SEGMENT_SIZE 1400

// Header for every message sent between client and server.
struct SUCMSHeader {
    // Message type, one of SUCMSMessageTypes
    uint16_t sucms_msg_type;
    // Length of message (not including this header!)
    uint16_t sucms_msg_length;
} __attribute__ ((packed));

// Message types for client-server server-client messages
enum SUCMSMessageTypes {
    // A command, generally from client->server
    MSG_COMMAND = 50,
    // A command response, generally from server->client
    MSG_COMMAND_RESPONSE,
    // A list response, containing file list data
    MSG_LIST_RESPONSE,
    // File data, sent when transferring files
    MSG_FILE_DATA,
    // A file data response
    MSG_FILE_DATA_RESPONSE
};

// Every command message will have this structure
struct CommandMessage {
    // Length of username (string, no null terminator!)
    uint16_t username_len;
    // The actual command, a SUCMSCommands type
    uint16_t command;
    unsigned char password_hash[16];
} __attribute__ ((packed)); // username is appended after each CommandMessage

struct CommandResponse {
    // Brief code indicating whether the server accepted the command or not
    uint16_t command_response_code;
    // Result ID given by server so client can handle results
    uint16_t result_id;
    // Size of all data in response
    uint32_t message_data_size;
    // Number of response messages client should wait for
    uint16_t message_count;
} __attribute__ ((packed));  // username is appended after each CommandMessage

// Commands sent from client to server to ask the server to perform an action
enum SUCMSCommands {
    // Ask server to list files for a particular user
    COMMAND_LIST = 80,
    // Ask server to send back a file
    COMMAND_READ,
    // Ask server to create a file
    COMMAND_CREATE,
    // Ask server to delete a file
    COMMAND_DELETE,
    // Tell server to start sending results for a request
    COMMAND_CLIENT_GET_RESULT
};

// Response types for commands sent to the server
enum SUCMSCommandResponses {
    // Username/password check out, all is well
    AUTH_OK = 10,
    // Username or password are not correct
    AUTH_FAILED,
    // Username/password correct, but user does not have permission to perform the command
    ACCESS_DENIED,
    // Username/password correct, but the file requested (for read or delete) doesn't exist
    NO_SUCH_FILE,
    // Username/password correct, but the result ID specified by the client isn't recognized
    INVALID_RESULT_ID,
    INTERNAL_SERVER_ERROR,
    INVALID_CLIENT_MESSAGE
};

// Response types for commands sent to the server
enum SUCMSFileDataResponses {
    // Server received the chunk properly
    FILEDATA_OK = 20,
    FILEDATA_AUTH_FAILED,
    FILEDATA_INVALID_RESULT_ID,
    FILEDATA_INVALID_CHUNK,
    FILEDATA_SERVER_ERROR,
    FILEDATA_INVALID_CLIENT_MESSAGE
};

struct SUCMSFileDataResponse {
    uint16_t filedata_response_type;
    uint16_t message_number;
    uint16_t result_id;
    uint16_t unused;
};

struct SUCMSClientFileData {
    uint16_t username_len; // Length of username (follows this message)
    uint16_t result_id; // ID of file upload request given by server
    uint16_t filedata_length; // Actual length of file data that follows username
    uint16_t message_number; // Message number (0-N)
    uint32_t filedata_offset; // Offset to write to the file at
    unsigned char password_hash[32]; // File data is directly after FileData header
} __attribute__ ((packed));

struct SUCMSClientFileRWRequest {
    uint16_t filename_length; // Actual length of file data that follows username
    uint16_t result_id; // Result ID that the server sent to us
    uint32_t filesize_bytes; // Length of file, in bytes
} __attribute__ ((packed)); // Filename follows this packet

// Message sent after a client requests the server to list files or read a file.
// Then the server sends back a CommandResponse with a result ID (and AUTH_OK)
// Then the client tells the server it's ready to receive the results
// with this message. For a list response, the command_type should be COMMAND_LIST
// For a read response the command_type should be COMMAND_READ.
// For a list result the message number is not used (client should expect all
// message to be sent immediately). For a read result the client needs to explicitly
// request each chunk of the file.
struct SUCMSClientGetResult {
    uint16_t command_type;
    uint16_t result_id;
    uint16_t message_number;
} __attribute__ ((packed));


// Message from server->client containing the file list results
struct SUCMSFileListResult {
    uint16_t result_id; // Result ID of list request
    uint16_t message_number; // Message number (0-N)
} __attribute__ ((packed)); /* Fileinfo data follows, may be more than one */


// Actual data about a file, returned for a list request, sent to server
// as part of a write request
struct SUCMSFileInfo {
    uint16_t filename_len; // Length of filename string (in bytes, no null terminator!)
    uint16_t total_pieces; // Ignore this value for list request. Use for WRITE request.
    uint32_t filesize_bytes; // Length of file, in bytes
} __attribute__ ((packed));

struct SUCMSFileDataResult {
    uint16_t result_id; // Result ID
    uint16_t message_number; // Message number
    uint16_t file_bytes; // Number of bytes of file that follow
    uint32_t byte_offset; // Which byte of the file does the data start at
} __attribute__ ((packed)); // File bytes follow message

struct SUCMSFileData {
    uint16_t filedata_length;
} __attribute__ ((packed)); // Filedata follows this header

#endif //UDP_PROJECT1_SUCMS_H_H
