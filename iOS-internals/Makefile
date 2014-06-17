CC=gcc
LIBS=-lncurses
PROG=lsock

all: intel arm 
	lipo -create -arch armv7 $(PROG).arm -arch x86_64 $(PROG).x86  -output $(PROG)

#  Not all lipo versions support -arch arm64.. but it's fine, since arm64 can also do armv7
#  -arch arm64 $(PROG).arm64 -output $(PROG)
	
intel:
	$(CC) -Wall $(PROG).c -o $(PROG).x86 $(LIBS) -mmacosx-version-min=10.6 -g2

arm:
	gcc-iphone armv7 $(PROG).c -o $(PROG).arm $(LIBS)

arm64:
	gcc-iphone arm64 $(PROG).c -o $(PROG).arm64 $(LIBS)


backup:
	tar cvf ~/lsock.tar lsock.c lsock.h Makefile lsock.x86 lsock.arm lsock 78
