#include <limits.h>
#include <ctype.h>
#include <stdio.h>    
#include <stdlib.h> 
#include <string.h>    
#include <unistd.h>    
#include <sys/time.h>    
#include "raw_socket.h"
#include "mem_ops.h"


bool is_valid_int(const char *s);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
