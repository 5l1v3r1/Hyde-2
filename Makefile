C=gcc
CFLAGS=-W -Wall -Wextra -O2 -fstack-protector-all
DFLAGS=-D_FORTIFY_SOURCE=2
LDFLAGS=-Wl,-z,relro,-z,now -lpthread
DIR=src/
DIROUT=bin/

hyde: $(DIR)hyde.c 
	$(CC) $(CFLAGS) $(DFLAGS) -o $(DIROUT)hyde $(DIR)*.c  $(LDFLAGS) 

clean:
	rm -f *.o bin/hyde

