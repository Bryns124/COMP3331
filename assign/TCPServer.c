// NOTE: Used a lot of sample network sockets code.

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

// Server host and port number are defined here for simple usage, but for some
// lab/assignment requires, they may need to be passed from command line parameter
// which should be obtained from the second parameter *argv[] of the main() function
#define SERVER_IP "127.0.0.1"

// Buffer length for messages exchanged between client and server
// 1024 is a normal case, it can also be specified as 2048 or others according to requirements
#define BUFFER_LEN 1024

// Globals
int message_num = 0;
int num_active = 0;

struct st_client_threads {
    int client_socket;
    int max_num_logins;
    char *user;
    char *user_addr;
};

// Handler for the client thread.
void* client_thread_handler(void *info);

// Cleans out files and buffers.
void clean(char *message1, char *message2);

// Authenticate the user.
bool authenticate_user(char *login_input);

// Get timestamp.
char* get_timestamp();

// Log the user entering server.
void log_user(char *user, int udp_port, char *user_addr);

// Run through the input commands and loops
int run_commands(int client_socket, char* user, int udp_port);

// BCM command. Broadcasts a message
void BCM(int client_socket, char* user, char *arg);

// ATU command. Downloads the active users.
void ATU(int client_socket, char *user);


int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("===== Requires server port and number of failed attempts =====\n");
        return -1;
    }
    int client_size, client_sock;
    struct sockaddr_in server_addr, client_addr;
    char server_message[BUFFER_LEN], client_message[BUFFER_LEN];
    int server_port = atoi(argv[1]);

    clean(server_message, client_message);
    
    // Create server socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if(client_socket < 0){
        printf("===== Error while creating socket =====\n");
        return -1;
    }
    printf("===== Socket created successfully =====\n");
    
    // Set server port and IP:
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    
    // Bind to the set port and IP:
    if(bind(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        printf("===== Couldn't bind to the port =====\n");
        return -1;
    }
    printf("===== Done with binding =====\n");
    
    // Listen for clients:
    if(listen(client_socket, 5) < 0){
        printf("Error while listening\n");
        return -1;
    }
    printf("\nServer is running and listening for incoming connections.....\n");

    pthread_t client_thread;

    while (1) {
        // Accept an incoming connection:
        struct sockaddr_in client_addr;
        client_size = sizeof(client_addr);
        client_sock = accept(client_socket, (struct sockaddr*)&client_addr, &client_size);
        
        if (client_sock < 0){
            printf("===== Can't accept =====\n");
            return -1;
        }

        printf("===== Client connected at IP: %s and port: %i =====\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        // Create separate thread for each client
        int max_num_logins = atoi(argv[2]);
        struct st_client_threads *new_client_thread = malloc(sizeof(struct st_client_threads));
        new_client_thread->client_socket = client_sock;
        new_client_thread->max_num_logins = atoi(argv[2]);
        new_client_thread->user_addr = inet_ntoa(client_addr.sin_addr);

        pthread_create(&client_thread, NULL, client_thread_handler, new_client_thread);
    }
    return 0;
}

// Handler for the client thread.
void* client_thread_handler(void* client_thread_params) {
    struct st_client_threads *thread_params = (struct st_client_threads*)client_thread_params;
    // Receive client's message
    char server_message[BUFFER_LEN], client_message[BUFFER_LEN];
    int clientAlive = 1;

    while (clientAlive) {
        // Clean buffers:
        memset(server_message, '\0', sizeof(server_message));
        memset(client_message, '\0', sizeof(client_message));

        int ret = recv(thread_params->client_socket, client_message, sizeof(client_message), 0);
        if (ret == 0) {
            clientAlive = 0;
            printf("===== Client disconnected, its socket descriptor is %d ...\n =====", thread_params->client_socket);
            free(thread_params);
            return NULL;
        }
        else if (ret < 0){
            printf("===== Couldn't receive =====\n");
            free(thread_params);
            return NULL;
        }
        printf("[recv] Msg from client: %s\n", client_message);

        // Respond to clinet,
        if (authenticate_user(client_message)) {
            strcpy(server_message, "Can login\n");
            if (send(thread_params->client_socket, server_message, strlen(server_message), 0) < 0) {
                free(thread_params);
                return NULL;
            }

            int udp_port_H;
            recv(thread_params->client_socket, &udp_port_H, sizeof(int), 0);
            udp_port_H = ntohl(udp_port_H);

            num_active++;
            log_user(client_message, udp_port_H, thread_params->user_addr);

            char *user = client_message;
            clientAlive = run_commands(thread_params->client_socket, user, udp_port_H);
        }
        else {
            strcpy(server_message, "Cannot login\n");
            if (send(thread_params->client_socket, server_message, strlen(server_message), 0) < 0) {
                free(thread_params);
                return NULL;
            }
        }
    }
    free(thread_params);
    return NULL;
}

// Clean out files and buffers.
void clean(char *message1, char *message2) {
    FILE *userlog = fopen("userlog.txt", "w"); 
    FILE *messagelog = fopen("messagelog.txt", "w");
    fclose(userlog);
    fclose(messagelog);
    memset(message1, '\0', sizeof(message1));
    memset(message2, '\0', sizeof(message2));
}

// Authenticate the user.
bool authenticate_user(char *login_input) {
    FILE *read_cred = fopen("credentials.txt", "a");
    char login[BUFFER_LEN];
    while (fgets(login, 128, read_cred)) {
        login[strcspn(login, "\n")] = '\0';
        if (!strcmp(login, login_input)) {
            return true;
        }
    }
    fclose(read_cred);
    return false;
}

// Get timestamp.
char *get_timestamp() {
    time_t timeval = time(NULL);
    struct tm *ltime = localtime(&timeval);
    char *timestamp = malloc(64);
    strftime(timestamp, 64, "%d %b %Y %H:%M:%S", ltime);
    return timestamp;
}

// Log the user entering server.
void log_user(char *login, int udp_port, char* user_addr) {
    char *timestamp = get_timestamp();
    char *user = strtok(login, " ");

    FILE *append_userlog = fopen("userlog.txt", "a");
    fseek(append_userlog, -1, SEEK_END);
    fprintf(append_userlog, "%d; %s; %s; %s; %d\n", num_active, timestamp, user, user_addr, udp_port);
    free(timestamp);
    fclose(append_userlog);
}

// Run through the input commands and loops
int run_commands(int client_socket, char* user, int udp_port) {
    while (1) {
        char client_message[BUFFER_LEN];
        memset(client_message, '\0', sizeof(client_message));
        int received = recv(client_socket, client_message, sizeof(client_message), 0);
        if (!received) {
            printf("===== Client has been disconnected. Socket was: %d \n =====", client_socket);
            return 0;
        }
        char *command_input = strtok(client_message, " ");
        if (strcmp(command_input, "BCM") == 0 && strcmp(&client_message[4], "") != 0) {
            BCM(client_socket, user, &client_message[4]);
        }
        else if (strcmp(command_input, "ATU") == 0 && strcmp(&client_message[4], "") == 0) {
            ATU(client_socket, user);
        }
        else {
            char *error_message = "Error. Invalid command!\n";
            send(client_socket, error_message, sizeof(error_message), 0);
        }
    }
}

// BCM command. Broadcasts a message
void BCM(int client_socket, char *user, char *arg) {
    FILE *append_message = fopen("messagelog.txt", "a");
    char *timestamp = get_timestamp();
    char server_message[BUFFER_LEN];
    message_num++;
    fprintf(append_message, "%d; %s; %s; %s\n", message_num, timestamp, user, arg);
    fclose(append_message);
    printf("%s broadcasted BCM #%d \"%s\" at %s.\n" ,user, message_num, arg, timestamp);
    sprintf(server_message, "Broadcast message, #%d broadcast at %s.\n" ,message_num, timestamp);      
    send(client_socket, server_message, sizeof(server_message), 0);
    free(timestamp);
}

// ATU command. Download the active users.
void ATU(int client_socket, char *user) {
    FILE *read_userlog = fopen("userlog.txt", "r");
    char log[BUFFER_LEN], server_message[BUFFER_LEN], buffer[BUFFER_LEN];
    memset(server_message, 0, sizeof(server_message));
    while (fgets(log, BUFFER_LEN, read_userlog)) {
        log[strcspn(log, "\n")] = '\0';
        char *user = strtok(NULL, ";");
        if (!strcmp(&user[1], user)) {
            continue;
        }
        char *addr = strtok(NULL, ";");
        char *udp_port = strtok(NULL, ";");
        char *timestamp = strtok(NULL, ";") ;
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "%s, %s, %s, active since %s.\n", &user[1], &addr[1], &udp_port[1], &timestamp[1]);
        strcat(server_message, buffer);
    }
    if (strcmp(server_message, "")) {
        send(client_socket, server_message, sizeof(server_message), 0);
    }
    else {
        char *no_other_users = "No other active user.\n";
        send(client_socket, no_other_users, sizeof(no_other_users), 0);
    }
    fclose(read_userlog);
}

// Wrapper function for fgets, similar to Python's built-in 'input'
// function.
void get_input (char *buf, char *msg) {
    printf("%s", msg);
    fgets(buf, BUFFER_LEN, stdin);
    buf[strcspn(buf, "\n")] = '\0'; // Remove the newline
}