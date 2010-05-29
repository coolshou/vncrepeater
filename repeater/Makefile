CFLAGS=-Wall
LDFLAGS=-lpthread

repeater: repeater.o config.o slots.o sockets.o vncauth.o d3des.o
	g++ $(CFLAGS) $(LDFLAGS) -o repeater repeater.o config.o slots.o sockets.o vncauth.o d3des.o
	
repeater.o: repeater.cpp
	g++ $(CFLAGS) -c repeater.cpp

config.o: config.cpp
	g++ $(CFLAGS) -c config.cpp
	
slots.o: slots.cpp
	g++ $(CFLAGS) -c slots.cpp
	
sockets.o: sockets.cpp
	g++ $(CFLAGS) -c sockets.cpp

vncauth.o: vncauth.cpp
	g++ $(CFLAGS) -c vncauth.cpp

d3des.o: d3des.cpp
	g++ $(CFLAGS) -c d3des.cpp

clean:
	rm -f *.o repeater