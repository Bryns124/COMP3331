// Sample network sockets code - UDP Client.
// Written for COMP3331 by Andrew Bennett, October 2019.
// ============================================================
// Modified by Wei Song (Tutor for COMP3331/9331), October 2021
// Modifications:
// - UDP --> TCP


#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdbool.h>

/*

A good reference for C sockets programming (esp. structs and syscalls):
https://beej.us/guide/bgnet/html/multi/index.html

And for information on C Threads:
https://www.gnu.org/software/libc/manual/html_node/ISO-C-Threads.html

One of the main structs used in this program is the "sockaddr_in" struct.
See: https://beej.us/guide/bgnet/html/multi/ipstructsdata.html#structs

struct sockaddr_in {
    short int          sin_family;  // Address family, AF_INET
    unsigned short int sin_port;    // Port number
    struct in_addr     sin_addr;    // Internet address
    unsigned char      sin_zero[8]; // Same size as struct sockaddr
};

*/


// Server host and port number are defined here for simple usage, but for some
// lab/assignment requires, they may need to be passed from command line parameter
// which should be obtained from the second parameter *argv[] of the main() function
#define SERVER_IP "127.0.0.1"

#define BUF_LEN 1024

// Get the "name" (IP address) of who we're communicating with.
char *get_name(struct sockaddr_in *sa, char *name);

// Populate a sockaddr_in struct with the specified IP / port to connect to.
void fill_sockaddr(struct sockaddr_in *sa, char *ip, int port);

// A wrapper function for fgets, similar to Python's built-in 'input' function.
void get_input(char *buf, char *msg);

void command_menu(int sock_fd);


int main(int argc, char *argv[]) {
    int server_port = atoi(argv[1]);
    int udp_port = atoi(argv[2]);

    // Array that we'll use to store the data we're sending / receiving.
    char buf[BUF_LEN] = {0};

    // Temporary array used to store the name of the client when printing.
    char name[BUF_LEN] = {0};

    // Create the client's socket.
    //
    // The first parameter indicates #the address family; in particular,
    // `AF_INET` indicates that the underlying network is using IPv4.
    //
    // The second parameter indicates that the socket is of type
    // SOCK_DGRAM, which means it is a UDP socket (rather than a TCP
    // socket, where we use SOCK_STREAM).
    //
    // This returns a file descriptor, which we'll use with our send /
    // recv functions later.
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    // A wrapper function for fgets, similar to Python's built-in
    // 'input' function.

    char username[BUF_LEN];
    get_input(username, "Username: ");
    while (1) {
        // Create the sockaddr that the client will use to send data to the
        // server.
        struct sockaddr_in sockaddr_to;
        fill_sockaddr(&sockaddr_to, SERVER_IP, server_port);

        // Now that we have a socket and a message, we send the message
        // through the socket to the server.
        //
        // Note the difference between UDP sendto() and TCP send() calls.
        // In TCP we do not need to attach the destination address to the
        // packet, while in UDP we explicilty specify the destination
        // address + port number for each message.
        int connection_result = connect(sock_fd, (struct sockaddr*)&sockaddr_to, sizeof(sockaddr_to));
        char password[BUF_LEN];
        char user_pass[BUF_LEN];
        get_input(password, "Password: ");
        sprintf(user_pass, "%s %s", username, password);
        
        int numbytes = send(sock_fd, user_pass, strlen(user_pass), 0);

        // Create the sockaddr that the client will use to receive data from
        // the server.
        struct sockaddr_in sockaddr_from;

        // We need to create a variable to store the length of the sockaddr
        // we're using here, which the recvfrom function can update if it
        // stores a different amount of information in the sockaddr.
        socklen_t from_len = sizeof(sockaddr_from);

        // Wait for the reply from the server.
        numbytes = recv(sock_fd, buf, BUF_LEN, 0);


        // Null-terminate the result, and remove the newline (if present).
        buf[numbytes] = '\0';
        buf[strcspn(buf, "\n")] = '\0';

        if (strcmp(buf, "Successful login") == 0) {
            int nl_udp_port = htonl(udp_port);
            send(sock_fd, &nl_udp_port, sizeof(int), 0);
            printf("Welcome to TOOM!\n");
            command_menu(sock_fd);
        }
        else {
            printf("Invalid Password. Please try again\n");
        }
    }
    return 0;
}

void command_menu(int sock_fd) {
    while (true) {
        char command[BUF_LEN];
        get_input(command, "Enter one of the following commands "
                "(BCM, ATU, SRB, SRM, RDM, OUT, UPD\n");
        send(sock_fd, command, strlen(command), 0);
        char server_response[BUF_LEN];
        memset(server_response, 0, strlen(server_response));
        recv(sock_fd, server_response, BUF_LEN, 0);
        printf("%s", server_response);
    }
}


// Wrapper function for fgets, similar to Python's built-in 'input'
// function.
void get_input(char *buf, char *msg) {
    printf("%s", msg);
    fgets(buf, BUF_LEN, stdin);
    buf[strcspn(buf, "\n")] = '\0'; // Remove the newline
}

// Populate a `sockaddr_in` struct with the IP / port to connect to.
void fill_sockaddr(struct sockaddr_in *sa, char *ip, int port) {

    // Set all of the memory in the sockaddr to 0.
    memset(sa, 0, sizeof(struct sockaddr_in));

    // IPv4.
    sa->sin_family = AF_INET;

    // We need to call `htons` (host to network short) to convert the
    // number from the "host" endianness (most likely little endian) to
    // big endian, also known as "network byte order".
    sa->sin_port = htons(port);
    sa->sin_addr.s_addr = inet_addr(SERVER_IP);
}

// Get the "name" (IP address) of who we're communicating with.
char *get_name(struct sockaddr_in *sa, char *name) {
    inet_ntop(sa->sin_family, &(sa->sin_addr), name, BUF_LEN);
    return name;
}