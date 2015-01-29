//
//  PortScanner.cpp
//  PortScanner
//
//  Created by Harsh Pathak on 11/10/13.
//  Copyright (c) 2013 Harsh Pathak. All rights reserved.
//

#define _BSD_SOURCE
#include <iostream>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sstream>
#include <string>
#include <cstdio> 
#include <cstdlib>
#include <vector>
#include <sstream>
#include <netinet/udp.h>
#include <sys/time.h>
#include <queue>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <iterator>
#include <arpa/inet.h>
#include <fstream>
#include <netdb.h>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdexcept>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <bits/ioctls.h>
#include <netinet/ether.h>
#include <poll.h>
#include <pthread.h>
#include <iomanip>
#include <ifaddrs.h>
#include <math.h>
#include <cmath>

#include "PortScanner.h"
#include "Scanner_lib.h"
#include "MultiThread.h"


using namespace std;

sockaddr_in ipv4_address;
string ipv4_string;
Task t2;
std::queue<Task> t1;
unsigned char *qname;
vector<Report>report;
Report *status_report=new Report;
PortScanner p1;

pthread_mutex_t scan_mutex;
pthread_mutex_t result_mutex;

double PortScanner::get_time()
{
    struct timeval t;
    gettimeofday(&t, NULL);
    double d = t.tv_sec + (double) t.tv_usec/1000000;
    return d;
}

//This one just gets the service names for reserved ports 0-1024. By default this is going to print results as per
//netdb.h header and the /etc/services file on the local machine.

void PortScanner::port_services(int port)
{
    struct servent *serv_name;
    char protocol[4] = "TCP";
    
    //Here we need to do htons. else it prints out wrong results as port number changes due to byte order changes
    
    short serv_port = htons(port);
    
    serv_name = getservbyport(serv_port, protocol);
    if ( serv_name == NULL)
    {
      serv_name = getservbyport(serv_port, "UDP");
      if (serv_name == NULL)
          status_report->version = "unknown";
       else
        {
            std::string appln_name=serv_name->s_name;
            status_report->version = appln_name;
        }
        
    }
    else
    {
        std::string appln_name=serv_name->s_name;
        status_report->version = appln_name;
        
    }

}

void* start_scans(void *dumb)
{


    Task t3;
    pthread_mutex_lock(&scan_mutex);
    while(!t1.empty())
    {
        

        t3 = t1.front();
        t1.pop();
        
        if(t3.scan_type=="UDP")
            p1.udp_scan((t3.ip_address).c_str(), t3.port);
        else
        {
            p1.tcp_scan((t3.ip_address).c_str(), t3.port, t3.scan_type);
         
        }
        
        
        if ( t3.port == atoi("80"))
            p1.service_scan((t3.ip_address).c_str(), "80");
        else if ( t3.port == atoi("143"))
            p1.service_scan((t3.ip_address).c_str(), "143");
        else if ( t3.port == atoi("43"))
            p1.service_scan((t3.ip_address).c_str(), "43");
        else if ( t3.port == atoi("24"))
            p1.service_scan((t3.ip_address).c_str(), "24");
        else if ( t3.port == atoi("22"))
            p1.service_scan((t3.ip_address).c_str(), "22");
        else if ( t3.port == atoi("110"))
            p1.service_scan((t3.ip_address).c_str(), "110");
     if ( (t3.port >=0 && t3.port <= 1024) && t3.port != 22 && t3.port != 24 && t3.port != 43 && t3.port != 80 && t3.port != 110 && t3.port != 143 )
            p1.port_services(t3.port);

        report.push_back(*status_report);
    }

    pthread_mutex_unlock(&scan_mutex);
    
    return 0; //as good as pthread_exit
}


int PortScanner::time_remaining(time_t start_time)  /*remaining time waiting for a response */
{
    /*get current time and subtract */
    
    time_t current_time = 0, remain;
    current_time = time(NULL);
    remain = current_time - start_time;
    return (int)remain;
    
}

void PortScanner::create_ip_header(iphdr *iph, unsigned long source, unsigned long destination, unsigned int length, unsigned short protocol)
{

   
    iph->frag_off = 0;         /* fragmentation not required */
    iph->ttl = 255;            /* maximum limit on number of hops */
    iph->protocol = protocol;  /* Next layer protocol. Can be 1 (ICMP), 6 (TCP) or 17 (UDP) */
    iph->check = 0;            /* Kernel always sets the IPv4 checksum */
    iph->saddr = source;       /* self explanatory :P */
    iph->daddr = destination;
    iph->ihl = 5;              /* Header length. 4 times this is 20 bytes. Mac value is 15 */
    iph->version = 4;          /* IPv4 used */
    iph->tos = 0;              /* Type of service. 0=> Routine. Kernel might replace this with DSCP/ECN :(.  */
    iph->tot_len = length;     /* Total length of the datagram */
    iph->id = htons (14118);   /* Identification. We dont want to fragment. But kernel will fragment if we go above
                                      MTU. Not clear about this*/

}


//Use the built-in TCP header structure from ip.h and populate accordingly. Using the simpler Linux format here

void PortScanner::create_tcp_header(tcphdr *tcp_header, iphdr *ip_header, unsigned int source_port, unsigned int destination_port, u_int8_t flags)
{

//  cout<<"           k: "<<k<<endl;
    tcp_header->ack= flags & TH_ACK ? 1 : 0;     /* Flags here are set as per our type of scan. We just conditionalize*/
    tcp_header->urg= flags & TH_URG ? 1 : 0;
    tcp_header->fin= flags & TH_FIN ? 1 : 0;
    tcp_header->syn= flags & TH_SYN ? 1 : 0;
    tcp_header->rst= flags & TH_RST ? 1 : 0;
    tcp_header->psh= flags & TH_PUSH ? 1 : 0;
    tcp_header->window = htons (65535);         /* Maximum size */
    tcp_header->urg_ptr = 0;
    tcp_header->source = source_port;
    tcp_header->dest = destination_port;
    tcp_header->seq = htonl(random());                 /*Random sequence number. Might try using self defined method */
    tcp_header->ack_seq = 0;
    tcp_header->doff = sizeof(tcphdr) / 4 ;
  
    //Checksum here is over the whole datagram i.e total_length field - 4*header_length.
    
    tcp_header->check = generate_tcp_checksum(ip_header, tcp_header, (ip_header->tot_len-(ip_header->ihl*4)));
    
}

void PortScanner::create_udp_header(udphdr* udp_header, iphdr *ip_header, unsigned short source_port, unsigned short dest_port)
{
    
    //Populate the UDP header here manually. Used for UDP scans
    udp_header->source=source_port;
    udp_header->dest=dest_port;
    udp_header->len = htons(sizeof(udphdr));

    //I believe UDP checksum is not required. But still added , not sure about it.
    udp_header->check = 0;
    
    //udp_header->check = generate_udp_checksum(ip_header, udp_header, (ip_header->tot_len-(ip_header->ihl*4)));
    
}

string PortScanner::get_source_ip(sockaddr_in &source)
{
    
    char buffer[INET_ADDRSTRLEN]; //Store the IP address
    memset(&source, 0, sizeof(source));
    void * temp_ipv4_address = NULL;
    //TODO: Need to handle loopback addresses here
    //implementation as per getifaddr() man page.
    
    ifaddrs *interface_addr = NULL, *ifa= NULL;
    
    if(getifaddrs(&interface_addr) == -1 )
    {
        perror("\n Error in getifaddr function call \n");
    }
    
    /*Iterate over the linked list */
   
    for ( ifa = interface_addr; ifa != NULL; ifa=ifa->ifa_next)
    {
        if ((ifa->ifa_addr->sa_family == AF_INET) && (strcmp(ifa->ifa_name,"eth0")==0))
         { 

            temp_ipv4_address = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            //Convert network-to-presentation
            inet_ntop(AF_INET, temp_ipv4_address, buffer, INET_ADDRSTRLEN);
        
            ipv4_string = buffer;  //Buffer has the "presentation" address
            
        }
        
    }
    //cleanup
    freeifaddrs(interface_addr);
    
    //Populate source. c_str to convert to c style pointer
    if(inet_aton(ipv4_string.c_str(), &source.sin_addr) == 0)
    {
        perror("\n inet_aton function call failed \n");
    }
    
    
    return ipv4_string;
}



void PortScanner::tcp_scan(const char * dest, unsigned int d_port, string s_type)
{
    
    /* Performs the required TCP scan based on type. Flags are set accordingly */
    /* First find whom are we connecting to */
    
    iphdr *iph = NULL;
    tcphdr *tcp_header = NULL;
     
    //cout<<"check :"<<status_report[c].check<<endl;
    //implementation and options used as per getaddrinfo() man page.
    
    int status=0;
    addrinfo *list_pointer = NULL,hints;
    sockaddr_in source  ,destination ;
    string source_host;
    timeval time_val;
    time_val.tv_sec = 5;
    time_val.tv_usec =0;
    


    memset(&source,0, sizeof(source));
    memset(&destination,0, sizeof(destination));

    status_report->destination_port = d_port;
    status_report->destination_host = dest;
    status_report->scan_type = s_type;
    
    memset(&hints,0, sizeof(addrinfo));
    hints.ai_family=AF_INET;  //Only IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME ; //First attribute in list is the host name

    //Main task. Populate dest.
    if ((status = getaddrinfo (dest, NULL, &hints, &list_pointer)) != 0) {
        perror("\n getaddrinfo() call failed. Check options set \n");
    }
    
    in_port_t source_port = getpid() % 65536;   //A little buggy
    status_report->source_port = source_port;
    
    memcpy(&destination, (sockaddr_in *) list_pointer->ai_addr, list_pointer->ai_addrlen);
     


    destination.sin_port = htons(d_port);
    source_host = get_source_ip(source);
    
    u_int8_t flags = 0;
    if(s_type == "SYN")
    {

        flags |= TH_SYN;
    }
    else if(s_type == "ACK")
    {
        flags |= TH_ACK;
    }
    else if(s_type == "NULL")
    {
        flags = 0;
    }
    else if(s_type == "FIN")
    {
     
        flags |= TH_FIN;
    }
    else if(s_type == "XMAS")
    {
        flags |= TH_FIN;
        flags |= TH_PUSH;
        flags |= TH_URG;
    }
 

freeaddrinfo(list_pointer);

    

    
 /*-------------------------------------SCAN SETUP COMPLETE--------------------------------------*/
 /* Start the scan */
    
    //Create raw socket
    
    int write_sock, read_sock;
    int buffer_size = 60*1024;  //Size large enough so that we dont have problems receving large no of packets
    char final_header[4096];

    write_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if ( write_sock == -1 )
    {
        perror("\n Raw socket creation failed \n");
        
    }
    
    //This socket is for reading only IP frames. Newer version uses AF_PACKET
    read_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    
    if(read_sock == -1)
    {
        perror("\n raw socket creation for reading datalink frames failed \n");
    }
    
    //set socket options

    int option = 1;
    const int *temp_val = &option;


    if (setsockopt (write_sock, IPPROTO_IP, IP_HDRINCL, temp_val, sizeof (option)) < 0)
      {
        cout<<"Error setting IP_HDRINCL";
         exit(0);
       }
    
  
    if(setsockopt(read_sock, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&time_val, sizeof(timeval)) != 0)
    {
        perror("\n Setting socket options failed \n");
    }
    

    iph = (iphdr *) final_header;
    create_ip_header(iph,source.sin_addr.s_addr , destination.sin_addr.s_addr, sizeof(iphdr)+ sizeof(tcphdr), IPPROTO_TCP);
    tcp_header = (tcphdr*)(final_header + sizeof(iphdr));
    create_tcp_header(tcp_header, iph, source_port, destination.sin_port, flags);


    ssize_t sent_bytes;
    ssize_t data_read ; 
    char read_buffer[60*1024] = {0};
    time_t timer;
    int t, count=0;


    //time to send
do{

    sent_bytes = sendto(write_sock, final_header, sizeof(tcphdr) + sizeof(iphdr), 0, (sockaddr *)&destination, sizeof(destination));
    time(&timer);
    count++;
    if(sent_bytes < 0)
    {
        perror("\n sendto() function call failed, Check arguments \n");
    }
   
    ssize_t received_bytes;
    usleep(10);
    socklen_t dsize = sizeof(destination);
    received_bytes=recv(read_sock, read_buffer , sizeof(read_buffer), 0);
    //received_bytes = polling_read(read_sock, 0, (sockaddr*) &destination, &dsize , read_buffer,1000, 5);
    iphdr* read_iphdr = (iphdr*) read_buffer;
   
    tcphdr* read_tcphdr = (tcphdr*)(read_buffer + (int)read_iphdr->ihl*4); 
   
    if( received_bytes < 0 )
      {
            perror("\n\t recvfrom() failed. Error in reading \n");
     }
   
    
    else if(received_bytes >0 )
    {
         if(read_tcphdr->syn==0 && read_tcphdr->rst==0)
        {

        
        }
        if(count>4)
        {
         break;
        }
    }

    t=time_remaining(timer);
    //cout<<t<<endl;
    
   }while(t<5); 

    /*First typecast to IP then check source and protocol type. No magic numbers */
    
   // iphdr* read_iphdr = (iphdr*) read_buffer;
   
    /*need to check for source authentication */
    
 iphdr* read_iphdr = (iphdr*) read_buffer;
   
    tcphdr* read_tcphdr = (tcphdr*)(read_buffer + (int)read_iphdr->ihl*4);
       
    
    if ( read_iphdr->protocol==IPPROTO_TCP )
    {
     //   tcphdr* read_tcphdr = (tcphdr*)(read_buffer + (int)read_iphdr->ihl*4);
    /*        cout<<"SYN :"<<read_tcphdr->syn<<endl;
        cout<<"rst :"<<read_tcphdr->rst<<endl;
        cout<<"ack :"<<read_tcphdr->ack<<endl;
  */
        if(s_type=="SYN")
        {
            if(read_tcphdr->syn==1)
                {
                    
                    status_report->status= "OPEN";
            

                }
            else if(read_tcphdr->rst==1)
            {
                //cout<<"close";
                status_report->status="CLOSED";
            }
            else if (count >1)
            {
                
                status_report->status= "CLOSED";
            }
            else
            {
                status_report->status="";
            }

        }
        else if(s_type=="NULL")
        {
            if(read_tcphdr->rst==1)
            {
                status_report->status= "CLOSED";
            }
            else
            {
                status_report->status="OPEN|FILTERED";
            }

        }
        else if(s_type=="FIN")
        {
            if(read_tcphdr->rst==1)
            {
                status_report->status="CLOSED";
            }
            else
            {
                status_report->status="OPEN|FILTERED";
            }

        }
        

        else if(s_type=="XMAS")
        {
            
            if(read_tcphdr->rst==1)
            {
                status_report->status="CLOSED";

            }
            else
            {
                status_report->status="OPEN|FILTERED";
            }  
        }
        else if(s_type=="ACK")
        {
             if(read_tcphdr->rst==1)
            {
                status_report->status="UNFILTERED";
            }
            else
            {
                status_report->status="FILTERED";
            }  

       

        
       
       }
   

          tcp_header = NULL;
         read_tcphdr = NULL;
         iph=NULL;
    if ( read_iphdr->protocol==IPPROTO_ICMP)
    {
        
        icmphdr* read_icmphdr = (icmphdr*)(read_buffer + (int)read_iphdr->ihl*4);
        if(read_icmphdr->type == 3 && (read_icmphdr->code == 1||read_icmphdr->code == 2||read_icmphdr->code == 3||read_icmphdr->code == 9||read_icmphdr->code == 10||read_icmphdr->code == 13))
            status_report->status= "FILTERED";
        else
            status_report->status= "UNFILTERED";
        read_icmphdr = NULL;
    }

   read_iphdr = NULL;
    dest = NULL;

   } //End TCP scan function
}


   /************ UDP Scan function ****************/

/*UDP scan function. Just send ip+udp headers. If we get ICMP response, port closed
 Else we need to send port specific message and check. As of now we just mark port as 
 OPEN | FILTERED */
 
void PortScanner::udp_scan(const char* dest , unsigned int d_port)
{
    /*UDP scan starts here. IPPROTO_UDP. Check ICMP responses */
    
    int status=0;
    addrinfo *list_pointer = NULL,hints;
    sockaddr_in source,destination;
    string source_host;
    timeval time_val;
    time_val.tv_sec = 5;
    time_val.tv_usec =0;
    char read_buffer[4096] = {0};
    char buf[65536];
    char dns_buffer[65536];
    iphdr *iph;
    
    /* DNS query variables */
    /*--------------------------------------*/
    struct dns_header *dns = NULL;
    struct question *qinfo = NULL;
    dns = (struct dns_header *)&dns_buffer[sizeof(struct ip) + sizeof(struct udphdr)];
    unsigned char dns_host[] = "www.facebook.com";
    
    
    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;
    
    //point to the query portion
    qname = (unsigned char*)&dns_buffer[sizeof(struct dns_header) + sizeof(struct iphdr) + sizeof(struct udphdr)];
    dns_format_convert(qname , dns_host);
    qinfo = (struct question*) &dns_buffer[sizeof(struct dns_header) + (strlen((const char*)qname) + 1) + sizeof(struct iphdr) + sizeof(struct udphdr)]; //fill it
    qinfo->qtype = htons(1); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)
    
    /*-------------------------*/
    
    status_report->destination_port = d_port;
    status_report->destination_host = dest;
    status_report->scan_type = "UDP";
    
    
    
    memset(&hints,0, sizeof(addrinfo));
    hints.ai_family=AF_INET;  //Only IPv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = hints.ai_flags | AI_CANONNAME ; //First attribute in list is the host name
    

    //Main task. Populate dest.
    if ((status = getaddrinfo (dest, NULL, &hints, &list_pointer)) != 0) {
        perror("\n getaddrinfo() call failed. Check options set \n");
    }
    
    
    in_port_t source_port = getpid() % 65536;   //A little buggy
    status_report->source_port = source_port;
    
    memcpy(&destination, (sockaddr_in *) list_pointer->ai_addr, list_pointer->ai_addrlen);
    
    destination.sin_port = htons(d_port);
    source_host = get_source_ip(source);
    
   // cout<<"Source is :"<<source_host<<endl;
    
    int write_sock, read_sock;
    int buffer_size = 60*1024;
    //=======================
    char final_header[4096];
    //========================
    
    if((write_sock = socket(AF_INET,SOCK_RAW, IPPROTO_UDP)) < 0 )
    {
        perror("\n\t Socket creation failed \n");
        exit(1);
    }

    if((read_sock = socket(AF_INET,SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("n\t ICMP socket creation failed \n");
        exit(1);
    }
    
    
    int option = 1;
    const int *temp_val = &option;
    
    
    if (setsockopt (write_sock, IPPROTO_IP, IP_HDRINCL, temp_val, sizeof (option)) < 0)
    {
        cout<<"Error setting IP_HDRINCL";
        exit(0);
        
    }
    
    
    if(setsockopt(read_sock, SOL_SOCKET, SO_RCVTIMEO, (timeval *)&time_val, sizeof(timeval)) != 0)
    {
        perror("\n Setting socket options failed \n");
    }

    /* ----- DNS query part -------*/
    
    
    if ( d_port == 53 )
    {
        
        iph = (iphdr *) dns_buffer;
        create_ip_header(iph,source.sin_addr.s_addr , destination.sin_addr.s_addr, sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_header) + (strlen((const char*)qname)+1) + sizeof(struct question), IPPROTO_UDP);
        
        udphdr *udp_header = (udphdr*)(dns_buffer + sizeof(iphdr));
        create_udp_header(udp_header, iph, source_port, destination.sin_port);
    }
    
    else
    {
      iph = (iphdr *) final_header;
      create_ip_header(iph,source.sin_addr.s_addr , destination.sin_addr.s_addr, sizeof(iphdr)+ sizeof(udphdr), IPPROTO_UDP);

      udphdr *udp_header = (udphdr*)(final_header + sizeof(iphdr));
      create_udp_header(udp_header, iph, source_port, destination.sin_port);
    }
    
      ssize_t sent_bytes;
      time_t timer;
      int t, count=0;


    do{
        
        if( d_port == 53 )
         sent_bytes = sendto(write_sock, dns_buffer, iph->tot_len, 0, (sockaddr *)&destination, sizeof(destination));
        else
            sent_bytes = sendto(write_sock, final_header, sizeof(udphdr) + sizeof(iphdr), 0, (sockaddr *)&destination, sizeof(destination));
       
        
       time(&timer);
      count++;
   
    if(sent_bytes < 0)
    {
        perror("\n sendto() function call failed, Check arguments \n");
        exit(1);
    }

    ssize_t data_read ; 
    //data_read = MultiThread::polling_read(read_sock, 0, (sockaddr *)&destination, sizeof(destination), read_buffer, sizeof(read_buffer),500);
    sleep(2);

    ssize_t received_bytes=recv(read_sock, read_buffer , sizeof(read_buffer), 0);
    if(received_bytes < 0 )
       {
        status_report->protocol = IPPROTO_UDP;
        status_report->status = "OPEN|FILTERED";
       }
       else
        {
          break;
        }
        
     t=time_remaining(timer);
        
    }
    while(t<5);
    
    iphdr* read_iphdr = (iphdr*) read_buffer;
    
    if ( read_iphdr->protocol==IPPROTO_ICMP )
    {
        /* Got ICMP desitnation unreachable response */
        
        icmphdr* read_icmphdr = (icmphdr*)(read_buffer + (int)read_iphdr->ihl*4);
        /* Check if type matches */
        
        if((read_icmphdr->type == ICMP_UNREACH) && (read_icmphdr->code == ICMP_UNREACH_PORT))
        {
            status_report->protocol = IPPROTO_UDP;
            status_report->status = "CLOSED";
            
        }

    }
    
    if ( read_iphdr->protocol==IPPROTO_UDP)
    {
        cout<<"Got a udp packet "<<endl;
        
    }


} //End of UDP scan method



void PortScanner::service_scan(const char* dest_host, const char* service)
{
    /* using connect here */
    /*addrinfo has the servce argument which can be specified easily. Hence using that here */

    int ssock;
    ssize_t bytes_recvd;
    char request_msg[100];
    addrinfo hints,*servinfo, *it;
    int r_value;
    char recv_buffer[2000];
    /* Timeout when we dont get a response */
    timeval time_value;
    time_value.tv_sec = 5; // block recv for 5 sec only
    time_value.tv_usec = 0;
    
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET ; //ipv4 only
    hints.ai_socktype = SOCK_STREAM;
    
    
    if((r_value = getaddrinfo(dest_host,service, &hints, &servinfo)) != 0)
        
    {
        fprintf(stderr, "getaddrinfo() failed %s \n", gai_strerror(r_value));
        exit(1);
        
    }
    
    /*Iterate and get the first address */
    /* TODO: need to make nonblocking and set timer */
    
    for (it = servinfo; it != NULL; it=it->ai_next)
    {
        if((ssock = socket(it->ai_family, it->ai_socktype, it->ai_protocol)) == -1 )
        {
            perror("\n\t socket call failed \n");
            
        }
        
        /*make socket understand the timeout logic */
        
        if(setsockopt(ssock, SOL_SOCKET, SO_RCVTIMEO, (char *)&time_value, sizeof(struct timeval)))
        {
            perror("\n\t error setting socket options \n");
            exit(1);
        }
        
        /*
         Giving some error while setting the flags. damn !
        int flags = fcntl(ssock, F_GETFL, NULL);
        fcntl(ssock, F_SETFL, flags | O_NONBLOCK);
         */
        
        if(connect(ssock, it->ai_addr, it->ai_addrlen) == -1 )
        {
            perror("\n\t connect() call failed \n");
        }
        
        /* got connection */
        break;
    }
    
    
    if ( it == NULL)
    {
        cout<<" Error getting address "<<endl;
        
    }
    
    freeaddrinfo(servinfo);
        
 
    /*** HTTP Check ****/
    
    if ( service == "80")
    {
        strcpy(request_msg, "HEAD / HTTP/1.0 \r\n\r\n");  //First line has the version. 1.0 does not required host, 1.1 does
        
        if ( send(ssock, request_msg, strlen(request_msg),0) == -1 )
        {
            perror("\n\t\t send() failed \n");
            exit(1);
        }
        
        if( bytes_recvd = recv(ssock,recv_buffer, 2000,0) == -1 ) //We actually just want some lines
        {
            perror("\n\t\t recv() failed \n");
            exit(1);
        }
        
        std::string http_response = recv_buffer;
        std::string http_version = http_response.substr(5,3);
        std::string http_final = "HTTP " + http_version;
        if( http_version != "1.0" && http_version != "1.1")
        {
            cout << "Cannot determine HTTP version. BAD request perhaps " <<endl;

        }
            else
            status_report->version=http_final ;
}
    
    
    /*******WHOIS port check ******/
    if ( service == "43")
    {
        strcpy(request_msg, "example.com \r\n");  //names are reverse, can try com.
        
        if ( send(ssock, request_msg, strlen(request_msg),0) == -1 )
        {
            perror("\n\t\t send() failed \n");
            exit(1);
        }
        
        if( bytes_recvd = recv(ssock,recv_buffer, 5000,0) == -1 ) //We actually just want some lines
        {
            perror("\n\t\t recv() failed \n");
            exit(1);
        }
        
        char *resp = strstr(recv_buffer, "Whois Server Version ");
        if( resp != NULL)
        {
           resp = resp +21; 
           std::string who = resp;
           std::string ver = who.substr(0,5);
           status_report->version= "WHOIS v" + ver ;

         }
        else
            status_report->version="WHOIS not running";

}
    
   /********POP server check********/
    
    if ( service == "110")
    {
        strcpy(request_msg, "UIDL \r\n");
        if ( send(ssock, request_msg, strlen(request_msg),0) == -1 )
        {
            perror("\n\t\t send() failed \n");
            exit(1);
        }
        
        if( bytes_recvd = recv(ssock,recv_buffer, 5000,0) == -1 ) //We actually just want some lines
        {
            perror("\n\t\t recv() failed \n");
            exit(1);
        }
        
        char *resp = strstr(recv_buffer, "Dovecot");
        if ( resp == NULL)
            resp = strstr(recv_buffer,"UIDL");
        
        if(resp !=NULL)
            status_report->version= "POP Version 3";
        else
             status_report->version= "POP Version 2";
        
}


    /*****IMAP Server check*******/
    
    if ( service == "143")
    {
        //removed as per vlads suggestion
        
        
        //Removed as per vlads suggestion
        
        /*if ( send(ssock, request_msg, strlen(request_msg),0) == -1 )
        {
            perror("\n\t\t send() failed \n");
            exit(1);
        }*/
        
        if( bytes_recvd = recv(ssock,recv_buffer, 5000,0) == -1 ) //We actually just want some lines
        {
            perror("\n\t\t recv() failed \n");
            exit(1);
        }
        
        char *resp = strstr(recv_buffer, "Dovecot");
        if ( resp == NULL)
            cout << " IMAP service not running"<<endl;
        
        
        std::string imap_resp = recv_buffer;
        std::string imap_version = imap_resp.substr(17,5);
         status_report->version= imap_version;
        
        
}

    /**Mailserver check **/
    
    if ( service == "24")
    {
        //strcpy(request_msg, "EHLO mailserver.sample.com \r\n");
     
        //removed as per Vlads suggestion
        /*
        if ( send(ssock, request_msg, strlen(request_msg),0) == -1 )
        {
            perror("\n\t\t send() failed \n");
            exit(1);
        }
         */
        
        if( bytes_recvd = recv(ssock,recv_buffer, 5000,0) == -1 ) //We actually just want some lines
        {
            perror("\n\t\t recv() failed \n");
            exit(1);
        }
        
        char *resp = strstr(recv_buffer, "P538");
        if( resp != NULL)
        {
            std::string mail = resp;
            std::string new_mail = mail.substr(1,13);
            status_report->version = new_mail + " mail server";
            
        }
        
    }
    
    /** SSH check **/
    
    if ( service == "22")
    {
        strcpy(request_msg, "ssh \r\n");
        
        if ( send(ssock, request_msg, strlen(request_msg),0) == -1 )
        {
            perror("\n\t\t send() failed \n");
            exit(1);
        }
        
        if( bytes_recvd = recv(ssock,recv_buffer, 5000,0) == -1 ) //We actually just want some lines
        {
            perror("\n\t\t recv() failed \n");
            exit(1);
        }
        
        std::string ssh_response = recv_buffer;
        std::string ssh_version = ssh_response.substr(4,3);
        if( ssh_version != "2.0")
        {
            cout << "Cannot determine SSH version" <<endl;
            
        }
        else
           status_report->version= "SSH " + ssh_version + " Secure Shell";
        
    }

}


int main(int argc, char ** argv)
{
ArgumentParsing a;
a.parsing_args(argc,argv);
string scantype;
int port,i,j,k,l;
vector<Report>::iterator it;
    
int noOfIp=a.portNo.size()*a.scanlist.size();

pthread_mutex_init(&scan_mutex, NULL);
pthread_mutex_init(&result_mutex, NULL);

number_of_threads = atoi((a.speedup).c_str());
//cout<<"no of threads :"<<number_of_threads<<endl;
pthread_t thread[number_of_threads];

Report r1;
int *dummy;


//port_services((a.ipAddress[i]).c_str(),port);
    

double time_start = p1.get_time();
    
    for(i=0;i<a.ipAddress.size();i++)
    {
        for(j=0;j<a.portNo.size();j++)
        {
            for(k=0;k<a.scanlist.size();k++)
            {
                t2.ip_address=a.ipAddress[i];
                t2.port=atoi(a.portNo[j].c_str());
                t2.scan_type=a.scanlist[k];
                t1.push(t2);
                
            }
        }
    }
    
  /*-----------If no speedup given -------------*/
    if(number_of_threads == 0)
    {
        for(i=0;i<a.ipAddress.size();i++)
        {
            for(j=0;j<a.portNo.size();j++)
            {
                for(k=0;k<a.scanlist.size();k++)
                {
                    
                    scantype=a.scanlist[k];
                    port = atoi(a.portNo[j].c_str());
                    if(scantype=="UDP")
                    {
                        p1.udp_scan((a.ipAddress[i]).c_str(),port);
                    }
                    else
                    {
                        p1.tcp_scan((a.ipAddress[i]).c_str(),port,scantype);
                    }
                
                    
                    //status_report[i].version="";
                    if ( port == atoi("80"))
                        p1.service_scan((a.ipAddress[i]).c_str(), "80");
                    else if ( port == atoi("143"))
                        p1.service_scan((a.ipAddress[i]).c_str(), "143");
                    else if ( port == atoi("43"))
                        p1.service_scan((a.ipAddress[i]).c_str(), "43");
                    else if ( port == atoi("24"))
                        p1.service_scan((a.ipAddress[i]).c_str(), "24");
                    else if ( port == atoi("22"))
                        p1.service_scan((a.ipAddress[i]).c_str(), "22");
                    else if ( port == atoi("110"))
                        p1.service_scan((a.ipAddress[i]).c_str(), "110");
                
                    
                    if ( (port >=0 && port <= 1024) && port != 22 && port != 24 && port != 43 && port != 80 && port != 110 && port != 143 )
                        p1.port_services(port);
                    
                    report.push_back(*status_report);
                    
                }
            }
        }
}
    
    
    
    
  else
  {
     for( int t=0; t<number_of_threads; t++)
      {
         pthread_create(&thread[t],NULL,start_scans,(void *)&dummy);

    }
    
    for (int t=0 ;t<number_of_threads; t++)
    {
        pthread_join(thread[t],NULL);
    }
      
  }
    

     for ( it = report.begin(); it != report.end(); ++it ) {
        it->store_output();
              }   
    double time_end = p1.get_time();
    cout << "Scanning...."<<endl;
    cout << endl;
    cout << endl;
    cout << "Scan took :"<< abs(time_end - time_start)<<endl;
    cout << endl;
    cout << endl;
    for(i=0;i<a.ipAddress.size();i++)
    {
        //status_report->print_output(2);
        cout<<endl;
        cout<<"IP Address :"<<a.ipAddress[i]<<endl<<endl;
        
        cout<<"OPEN Ports :"<<endl<<endl;
        cout<<"------------------------------------------------------------------------------------------------------------------------"<<endl;
        cout<<setw(11)<<"Port"<<setw(30)<<"Service Name"<<setw(35)<<"Results"<<setw(37)<<"Conclusion"<<endl;
        cout<<"------------------------------------------------------------------------------------------------------------------------"<<endl;
        int count=0;
        
        r1.print_output(0,a.ipAddress[i]);              
    cout<<endl;
    cout<<endl;
    cout<<"Closed/Filtered/Unfiltered Ports:"<<endl<<endl;
    cout<<"----------------------------------------------------------------------------------------------------------------------"<<endl;
    cout<<setw(10)<<"Port "<<setw(37)<<"Service Name "<<setw(30)<<"Results"<<setw(34)<<"Conclusion"<<endl;
    cout<<"-----------------------------------------------------------------------------------------------------------------------"<<endl<<endl;
    
     r1.print_output(1,a.ipAddress[i]);
    r1.print_output(2,a.ipAddress[i]); 
        pthread_mutex_destroy(&scan_mutex);
        pthread_mutex_destroy(&result_mutex);
    
    status_report = NULL;

    }

    
}
