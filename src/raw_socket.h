#include <limits.h>
#include <ctype.h>
#include <stdio.h>    
#include <stdlib.h> 
#include <string.h>    
#include <unistd.h>    
#include <sys/time.h>    
// socks
#include <netdb.h>      
#include <sys/socket.h>    
#include <arpa/inet.h>    
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>  
#include <stdbool.h>
//#include "validate.h"
#include "mem_ops.h"
#include <pthread.h>


in_addr_t RandomIp();     
//function from my Brother I4K the master of wizards
//from Orion-Socket API
int orion_getHostByName(const char* name, char* buffer);
void *fazerpacote(void *arg);
