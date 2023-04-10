# Embedded Logger

A threaded logger meant to be embedded in C++ source code, that can be used to log messages to a central server.

## Build
Build the server binary with `make`. The server binary will receive messages from the embedded logger and write them to a `server.log` file in the current directory.

## Usage
The embedded logger is meant to be used in C++ source code. The logger is thread-safe, so it can be used from multiple threads.

Run the server binary in the background
```bash
./LogServer
```
For options, run `./LogServer -h`

```c++
// Example.cpp
#include "Logger.h"

int main() {
    InitializeLog("0.0.0.0", 5000) // Initialize the logger by connecting to the server's IP and port
    SetLogLevel(LogLevel::DEBUG) // Set the log level to DEBUG. All messages with a level greater than or equal to DEBUG will be logged.
    Log(LogLevel::DEBUG, __FILE__, __func__, __LINE__, "This is a debug message") // Log a message with the DEBUG level. The server will receive and write this message to the log file (default: server.log)
    ExitLog() // Exit the logger. This will close the connection to the server.
}
```