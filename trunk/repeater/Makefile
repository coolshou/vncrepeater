
ifeq ($(CFG),debug)
CFLAGS= -g -Wall -D_DEBUG 
else
CFLAGS=-Wall
endif

LDFLAGS=-lpthread -lrt

repeater: repeater.o config.o slots.o mutex.o thread.o sockets.o vncauth.o d3des.o
	g++ $(CFLAGS) $(LDFLAGS) -o repeater repeater.o config.o slots.o mutex.o thread.o sockets.o vncauth.o d3des.o
	
repeater.o: repeater.cpp
	g++ $(CFLAGS) -c repeater.cpp

config.o: config.cpp
	g++ $(CFLAGS) -c config.cpp
	
slots.o: slots.cpp
	g++ $(CFLAGS) -c slots.cpp
	
mutex.o: mutex.cpp
	g++ $(CFLAGS) -c mutex.cpp
	
thread.o: thread.cpp
	g++ $(CFLAGS) -c thread.cpp
	
sockets.o: sockets.cpp
	g++ $(CFLAGS) -c sockets.cpp

vncauth.o: vncauth.cpp
	g++ $(CFLAGS) -c vncauth.cpp

d3des.o: d3des.cpp
	g++ $(CFLAGS) -c d3des.cpp

clean:
	rm -f *.o repeater
