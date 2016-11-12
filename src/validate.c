#include "validate.h"

bool is_valid_int(const char *s)
{

	if(strnlen(s,9)>8)
		return false;

	long long temp = 0;
	bool negative = false;

	if (*s != '\0' && (*s == '-' || *s == '+'))
        	negative = *s++ == '-';
    	

    	while (*s != '\0')
    	{
        	if (!isdigit((unsigned char)*s))
            		return false;
        

        	temp = 10 * temp + (*s - '0');

       	 	if ((!negative && temp > INT_MAX) || (negative && -temp < INT_MIN))
            		return false;
        
        	++s;
 	}   

	return true;
}

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
