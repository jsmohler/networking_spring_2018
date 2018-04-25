//
// Created by Nathan Evans on 4/10/18.
//

#ifndef UDP_CHAT_UDP_CHAT_H
#define UDP_CHAT_UDP_CHAT_H

enum ChatMonType {
    MON_CONNECT,
    MON_DISCONNECT,
    MON_MESSAGE
};

// Message sent from the chat monitor to the server
// or from the server to the chat monitor
struct ChatMonMsg {
    uint16_t type; // A ChatMonType
    uint16_t nickname_len; // Length of optional nickname to send with message
    uint16_t data_len; // Length of string message data
};

// Types of messages sent from chat client to chat server
enum ChatClientType {
    CLIENT_CONNECT = 10,
    CLIENT_DISCONNECT,
    CLIENT_SET_NICKNAME,
    CLIENT_SEND_MESSAGE
};

struct ChatClientMessage {
    uint16_t type; // A ChatClientType
    uint16_t data_length; // If additional data belongs to message, how long is it?
};

#endif //UDP_CHAT_UDP_CHAT_H
