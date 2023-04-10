#include <csignal>
#include <sys/socket.h>
#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <vector>

// Statics
// Buffer size for the UDP socket
#define BUF_LEN 1024

// Global variable to control the flow of the program.
bool g_isRunning = true;
// File descriptor for the UDP socket
int g_UDPSocketFD;
// Socket address struct for this server
struct sockaddr_in g_serverAddr, g_remoteAddr;
// Mutex for shared resources
pthread_mutex_t g_mutex;
// Receive thread
pthread_t receiveThread;
// Log level filter. The server will only log messages with a level equal to or greater than this value.
int g_logLevel = 0; // 0 = DEBUG, 1 = WARNING, 2 = ERROR, 3 = CRITICAL
// Everytime we receive a message from a client we check if we have seen this client before, if not we add it to the list. We can then use this list to send messages to all clients.
std::vector<struct sockaddr_in> g_clientList;
// Path to the server log file
char LOG_FILE_PATH[] = "server.log";


// Signal handler for SIGINT
void sigHandler(int sig) {
    switch(sig) {
        case SIGINT:
            g_isRunning=false;
            break;
    }
}

void* receiveThreadFunc(void* arg) {
    // convert the void pointer arg to an int
    int serverFd = *(int*)arg;
    // open the server log file for write only with permissions rw-rw-rw-
    int g_logFileFd = open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (g_logFileFd < 0) {
        std::cerr << strerror(errno) << std::endl;
        return nullptr;
    }

    // run in an endless while loop via an is_running flag.
    while (g_isRunning) {
        char rcvBuffer[BUF_LEN];  // Buffer to hold the received data from the remote
        memset(rcvBuffer, 0, BUF_LEN);    // zero out the buffer.

        struct sockaddr_in senderAddr; // remote address struct - used to store the address of the remote host that sent the data.
        socklen_t addrlen = sizeof(senderAddr); // size of the remote address struct.

        // ensure the recvfrom() function is non-blocking with a sleep of 1 second if nothing is received.
        int recvlen = recvfrom(serverFd, rcvBuffer, BUF_LEN, MSG_DONTWAIT, (struct sockaddr *)&senderAddr, &addrlen);
        if (recvlen > 0) {  // if recvlen > 0, then data was received.
            // apply mutexing to any shared resources used within the recvfrom() function.
            pthread_mutex_lock(&g_mutex);

            // check if we have seen this client before
            bool seenBefore = false;
            for (auto &clientAddr : g_clientList) {
                if (clientAddr.sin_addr.s_addr == senderAddr.sin_addr.s_addr && clientAddr.sin_port == senderAddr.sin_port) {
                    seenBefore = true;
                    break;
                }
            }

            // if this is a new client, add it to the client list
            if (!seenBefore) {
                g_clientList.push_back(senderAddr);
            }

            // take any content from recvfrom() and write to the server log file.
            write(g_logFileFd, rcvBuffer, recvlen);

            // unlock the mutex
            pthread_mutex_unlock(&g_mutex);
        } else {
            sleep(1);   // sleep for 1 second if no data was received.
        }
    }

    // lock the mutex
    pthread_mutex_lock(&g_mutex);
    // close the log file
    close(g_logFileFd);
    // unlock the mutex
    pthread_mutex_unlock(&g_mutex);

    return nullptr;
}

/**
 * Usage
 * ./server [options]
 * Options:
 * -p <port>   Port to listen on
 * -h          Display this help message
 * -f <level>  Set the log level filter
 * -o <file>   Set the log file path
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[]) {
    // Parse command line arguments
    int port = 0;
    int opt;
    while ((opt = getopt(argc, argv, "p:hf:o:")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
                std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
                std::cout << "Options:" << std::endl;
                std::cout << "-p <port>   Port to listen on" << std::endl;
                std::cout << "-h          Display this help message" << std::endl;
                std::cout << "-f <level>  Set the log level filter" << std::endl;
                std::cout << "-o <file>   Set the log file path" << std::endl;
                return 0;
            case 'f':
                g_logLevel = atoi(optarg);
                break;
            case 'o':
                strcpy(LOG_FILE_PATH, optarg);
                break;
            default:
                std::cerr << "Invalid argument: " << opt << std::endl;
                return 1;
        }
    }

    // Register shutdown handler
    signal(SIGINT, sigHandler);

    // Create UDP socket
    g_UDPSocketFD = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_UDPSocketFD < 0) {
        std::cerr << strerror(errno) << std::endl;
        return 1;
    }

    // Bind socket to IP address and available port
    memset(&g_serverAddr, 0, sizeof(g_serverAddr)); // zero out the server struct.
    g_serverAddr.sin_family = AF_INET;    // set the address family to IPv4.
    g_serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); // bind to any available IP address
    g_serverAddr.sin_port =  htons(port);
    if (bind(g_UDPSocketFD, (struct sockaddr *)&g_serverAddr, sizeof(g_serverAddr)) < 0) {
        std::cerr << strerror(errno) << std::endl;
        return 1;
    }

    // Get socket address information
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(g_UDPSocketFD, (struct sockaddr *)&sin, &len) == -1) {
        std::cerr << "Error getting socket address information\n";
        return 1;
    }
    std::cout << "Server listening on port " << ntohs(sin.sin_port) << std::endl;
    std::cout << "Server listening on IP address " << inet_ntoa(sin.sin_addr) << std::endl;


    // Initialize mutex
    pthread_mutex_init(&g_mutex, NULL);

    // Start receive thread
    pthread_create(&receiveThread, NULL, receiveThreadFunc, &g_UDPSocketFD);

    // User menu
    while (g_isRunning) {
        // Print menu
        std::cout << "1. Set the log level" << std::endl;
        std::cout << "2. Dump the log file here" << std::endl;
        std::cout << "0. Shut down" << std::endl;
        std::cout << "Enter your choice: ";

        int choice;
        std::cin >> choice;
        std::cin.ignore();  // Ignore newline character

        std::cout << "You entered: " << choice << std::endl;
        switch (choice) {
            case 1: {   // Set log level
                std::cout << "Enter log level (0-3): ";

                int level;
                std::cin >> level;
                std::cin.ignore();  // Ignore newline character

                if (level < 0 || level > 3) {
                    std::cerr << "Invalid log level" << std::endl;
                    std::cerr << "Valid log levels are 0 (Debug), 1 (Warning), 2 (Error), and 3 (Critical)" << std::endl;
                    break;
                }

                // Lock mutex since we are accessing a shared resource
                pthread_mutex_lock(&g_mutex);
                g_logLevel = level;  // Set the log level
                pthread_mutex_unlock(&g_mutex); // Unlock mutex

                std::cout << "Log level set to " << level << std::endl;

                // Send log level to anyone listening
                char buf[BUF_LEN];  // Buffer to hold the message
                memset(buf, 0, BUF_LEN);    // Zero out the buffer
                int msgLength = sprintf(buf, "Set Log Level=%d", level) + 1; // Format the message and get the length

                struct sockaddr_in clientAddr;
                socklen_t addrLen = sizeof(clientAddr);
                clientAddr.sin_family = AF_INET;
                clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);
                clientAddr.sin_port = htons(0);

                // Send the message to all clients
                for (auto &clientAddr : g_clientList) {
                    if (sendto(g_UDPSocketFD, buf, msgLength, 0, (struct sockaddr *)&clientAddr, addrLen) < 0) {
                        std::cerr << strerror(errno) << std::endl;
                    }
                }

                break;
            }
            case 2: {   // Dump log file
                // Open log file for read only
                FILE* dumpLogFile = fopen("server.log", "r");
                if (dumpLogFile == NULL) {
                    std::cerr << strerror(errno) << std::endl;
                    break;
                }

                // Read the log file and print it to the screen
                char buf[BUF_LEN];
                while (fgets(buf, BUF_LEN, dumpLogFile) != NULL) {
                    std::cout << buf;
                }

                // Close the log file
                fclose(dumpLogFile);

                // Wait for user to press a key
                std::cout << "Press any key to continue...";
                std::cin.get(); // Wait for user to press a key
                break;
            }
            case 0: {   // Shut down
                // lock mutex since we are accessing a shared resource
                pthread_mutex_lock(&g_mutex);
                g_isRunning = false;    // Set the running flag to false
                pthread_mutex_unlock(&g_mutex); // unlock mutex
                break;
            }
            default: {
                std::cerr << "Invalid choice" << std::endl;
                break;
            }
        }
    }
    // At this point the g_isRunning flag is false, so the server is shutting down

    // Join the receive thread to the main thread so it doesn't shut down before the receive thread does
    pthread_join(receiveThread, NULL);

    // Close the socket
    close(g_UDPSocketFD);

    // Destroy mutex
    pthread_mutex_destroy(&g_mutex);

    return 0;
}