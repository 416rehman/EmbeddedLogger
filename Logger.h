#ifndef EMBEDDED_LOGGER_H
#define EMBEDDED_LOGGER_H

typedef enum LOG_LEVEL
{
    DEBUG,
    WARNING,
    ERROR,
    CRITICAL
} LOG_LEVEL;

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
int InitializeLog(const char* ip, int port);

/**
 * Sets the log level.
 * @param level
 */
void SetLogLevel(LOG_LEVEL level);
/**
 * Logs a message to the server.
 * @param level The level of the message.
 * @param prog The name of the program.
 * @param func The name of the function.
 * @param line The line number.
 * @param message The message to log.
 */
void Log(LOG_LEVEL level, const char *prog, const char *func, int line, const char *message);

/**
 * Stops the receive thread, closes the socket and stops logging.
 */
void ExitLog();

#endif //EMBEDDED_LOGGER_H
