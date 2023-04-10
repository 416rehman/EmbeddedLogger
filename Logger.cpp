
#include <sys/socket.h>
#include <netinet/in.h>
#include <mutex>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include "Logger.h"

// global variable to hold the mutex used by this logger to protect any shared resources.
pthread_mutex_t g_mutex;
// global variable to hold the thread id of the receive thread.
pthread_t g_receive_thread_id;
// Holds the address of the server to send the logs to.
struct sockaddr_in g_server{};
// Holds the file descriptor of the socket used to send the logs to the server.
int g_fd = -1;
// global flag to indicate if the logger is running.
bool g_is_running = true;
// global variable to hold the log level filter for the logger. All messages with a level less than this will be ignored and not logged to the server.
LOG_LEVEL g_logLevel = DEBUG;

/**
 * The receive thread is waiting for any commands from the server. So far there is only one command from the server: “Set Log Level=<level>”. The receive thread will
accept the file descriptor as an argument.
run in an endless loop via an is_running flag.
apply mutexing to any shared resources used within the recvfrom() function.
ensure the recvfrom() function is non-blocking with a sleep of 1 second if nothing is received.
act on the command “Set Log Level=<level>” from the server to overwrite the filter log severity.
 */
void* ReceiveThread(void* arg) {
    // Get the file descriptor from the argument.
    int fd = *(int*)arg;

    // Set the receive timeout to 1 second.
    struct timeval tv{};    // create the time value struct
    tv.tv_sec = 1;        // set the seconds to 1
    tv.tv_usec = 0;       // set the microseconds to 0
    // Set the Receive Timeout to the time value struct we just created.
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Run in an endless loop.
    while (g_is_running) {
        // Receive the command from the server.
        char buffer[256];   // Buffer to hold the command (max size is 256 bytes).
        struct sockaddr_in sender;  // socket address struct to hold the address of the sender. (in this case the server).
        socklen_t server_len = sizeof(sender);  // The size of the sender struct.
        // Receive the command from the server. This will modify the server struct to hold the address of the server.
        int bytes_received = recvfrom(fd, buffer, sizeof(buffer), MSG_DONTWAIT, (struct sockaddr*)&sender, &server_len);
        if (bytes_received > 0) {
            // Null-terminate the received message.
            buffer[bytes_received] = '\0';

            // Check if the received message is a "Set Log Level" command.
            const char* prefix = "Set Log Level=";
            if (strncmp(buffer, prefix, strlen(prefix)) == 0) { // if the received message starts with "Set Log Level="
                // Extract the new log level from the message.
                int level = atoi(buffer + strlen(prefix));  // convert all the characters after "Set Log Level=" to an integer.

                // Check if the level is valid.
                if (level < DEBUG || level > CRITICAL) {    // if the level is not valid
                    level = DEBUG;  // set the level to DEBUG.
                }
                // Lock the mutex since we are going to modify the log level.
                pthread_mutex_lock(&g_mutex);
                // Set the new log level to the one we extracted from the message sent by the server.
                SetLogLevel((LOG_LEVEL)level);
                // Unlock the mutex. We are done modifying the log level.
                pthread_mutex_unlock(&g_mutex);
            }
        }
    }

    return nullptr;
}

/**
 * Does the following:
 * create a non-blocking socket for UDP communications (AF_INET, SOCK_DGRAM).
    Set the address and port of the server.
    Create a mutex to protect any shared resources.
    Start the receive thread and pass the file descriptor to it.
 * @param ip The IP address of the Log Server.
 * @param port The port of the Log Server.
 * @return
 */
int InitializeLog(const char* ip, int port) {
    // check if mutex is initialized, if not, initialize it.
    if (!g_mutex.__data.__lock) {   // if the mutex is not initialized
        // Initialize the mutex that will be used to protect any shared resources.
        if (pthread_mutex_init(&g_mutex, NULL) != 0) {
            perror("Error Initializing mutex"); // print our own error message.
            std::cerr << strerror(errno) << std::endl;  // print the actual error message.
            return -1;  // return -1 to indicate an error.
        }
    }

    // Lock the mutex since we are going to access shared resources after this in this function. (The global variables)
    pthread_mutex_lock(&g_mutex);

    // Check if the logger is already initialized.
    if (g_fd > 0) { // if the file descriptor is greater than 0, then the logger is already initialized and we should not initialize it again.
        std::cerr << "Logger is already initialized on %s:%d" << inet_ntoa(g_server.sin_addr) << ntohs(g_server.sin_port) << std::endl;
        pthread_mutex_unlock(&g_mutex); // Unlock the mutex since we are done accessing shared resources.
        return -1;  // return -1 to indicate an error.
    }

    // Create a socket for UDP communications.
    g_fd = socket(AF_INET, SOCK_DGRAM, 0);

    // Check if the socket was created successfully.
    if (g_fd < 0) { // if the file descriptor returned is less than 0, then the socket was not created successfully.
        perror("Error creating socket");    // print our own error message.
        std::cerr << strerror(errno) << std::endl;  // print the actual error message.
        pthread_mutex_unlock(&g_mutex); // Unlock the mutex since we are done accessing shared resources.
        return -1;  // return -1 to indicate an error.
    }

    // Set the address and port of the server.;
    g_server.sin_family = AF_INET;  // set the address family to IPv4.
    g_server.sin_port = htons(port);    // convert the port to network byte order and set it.
    g_server.sin_addr.s_addr = inet_addr(ip);   // convert the IP address to network byte order and set it.

    // Unlock the mutex. We are done modifying the shared resources.
    pthread_mutex_unlock(&g_mutex);

    // Start the receive thread and pass the file descriptor to it.
    if (pthread_create(&g_receive_thread_id, NULL, ReceiveThread, &g_fd) != 0) {
        perror("Error creating thread");    // print our own error message.
        std::cerr << strerror(errno) << std::endl;  // print the actual error message.
        return -1;  // return -1 to indicate an error.
    }

    return 0;   // return 0 to indicate success.
}

/**
 * Sets the log level.
 * @param level
 */
void SetLogLevel(LOG_LEVEL level) {
    // Set the log level.
    g_logLevel = level;
}

/**
 * does the following:
 * compare the severity of the log to the filter log severity. The log will be thrown away if its severity is lower than the filter log severity.
create a timestamp to be added to the log message. Code for creating the log message will look something like:
time_t now = time(0);
char *dt = ctime(&now);
memset(buf, 0, BUF_LEN);
char levelStr[][16]={"DEBUG", "WARNING", "ERROR", "CRITICAL"};
len = sprintf(buf, "%s %s %s:%s:%d %s\n", dt, levelStr[level], file, func, line, message)+1;
buf[len-1]='\0';
apply mutexing to any shared resources used within the Log() function.
The message will be sent to the server via UDP sendto().
 * @param level
 * @param prog
 * @param func
 * @param line
 * @param message
 */
void Log(LOG_LEVEL level, const char *prog, const char *func, int line, const char *message) {
    // Lock the mutex since we are going to access shared resources (g_logLevel, g_fd, g_server).
    pthread_mutex_lock(&g_mutex);
    // Check if the log level is less than the filter log level. If so, ignore the log.
    if (level < g_logLevel) {
        pthread_mutex_unlock(&g_mutex); // Unlock the mutex since we are done accessing the log level.
        return;
    }

    // Create a timestamp to be added to the log message.
    time_t now = time(0);
    char *dt = ctime(&now);

    // Create the log message.
    char buf[256];  // create a buffer to hold the log message. The buffer will be 256 bytes long.
    // an array of strings to convert the passed in log level to a string representation.
    char levelStr[][16]={"DEBUG", "WARNING", "ERROR", "CRITICAL"};
    // create the log message and store it in the buffer.
    int len = sprintf(buf, "%s %s %s:%s:%d %s\n", dt, levelStr[level], prog, func, line, message)+1;
    // Null-terminate the log message.
    buf[len-1]='\0';

    // Send the log message to the server.
    sendto(g_fd, buf, len, 0, (struct sockaddr *)&g_server, sizeof(g_server));

    // Unlock the mutex. We are done accessing the file descriptor.
    pthread_mutex_unlock(&g_mutex);
}

void ExitLog() {
    // Lock the mutex since we are going to access shared resources (g_fd, g_receive_thread_id).
    pthread_mutex_lock(&g_mutex);

    // Close the socket.
    close(g_fd);

    // Unlock the mutex. We are done accessing the file descriptor.
    pthread_mutex_unlock(&g_mutex);

    // Wait for the receive thread to exit.
    pthread_join(g_receive_thread_id, NULL);

    // Destroy the mutex.
    pthread_mutex_destroy(&g_mutex);
}

