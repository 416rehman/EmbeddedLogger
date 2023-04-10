CC=g++
CFLAGS=-I
CFLAGS+=-Wall
FILES=LogServer.cpp
LIBS=-lpthread
OUTPUT=LogServer

all: clean logserver

logserver: $(FILES)
	$(CC) $(CFLAGS) $^ -o $(OUTPUT) $(LIBS)

clean:
	rm -f *.o $(OUTPUT)