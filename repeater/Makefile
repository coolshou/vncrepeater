
CC = g++
CCFLAGS = -Wall
LDFLAGS = -pthread -lrt
PROGNAME = repeater

MODULES = repeater.o config.o slots.o mutex.o thread.o sockets.o vncauth.o d3des.o

all: release

##########
# Builds #
##########

release: CCFLAGS += -O2 -DNDEBUG
release: BUILD = Debug
release: $(MODULES)
	$(CC) $(CCFLAGS) $(LDFLAGS) -o $(PROGNAME) $(MODULES) -lrt
	
debug: CCFLAGS += -g -D_DEBUG
debug: BUILD = Release
debug: $(MODULES)
	$(CC) $(CCFLAGS) $(LDFLAGS) -o $(PROGNAME) $(MODULES)

###################
# Process modules #
###################

%.o: %.cpp	
	$(CC) $(CCFLAGS) -c $< -o $@

clean:
	rm -f *.o repeater
