//
//  Scanner_lib.h
//  PortScanner
//
//  Created by Harsh Pathak on 11/11/13.
//  Copyright (c) 2013 Harsh Pathak. All rights reserved.
//

#ifndef __PortScanner__Scanner_lib__
#define __PortScanner__Scanner_lib__

#include <iostream>

#endif /* defined(__PortScanner__Scanner_lib__) */

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <stdexcept>
#include <cstring>
#include <pthread.h>
#include <iostream>
#include <vector>
#include <sys/types.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
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
#include <algorithm>
#include <iterator>
#include <arpa/inet.h>
#include <fstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdexcept>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;





class ArgumentParsing
{
public:
    int c,p;
    string port,ip,prefix,speedup,filename,scan;
    string segment;
    size_t pos1, pos2;
    string character1;
    string character2;
    sockaddr_in test;
    sockaddr_in test6;
    
    
    
    
    vector<string> portNo;
    vector<string> portRange;
    vector<string> scanlist;
    vector<string> ip_prefix;
    vector<string> ipAddress;
    
    void validate_ip(string ip);
    void readFile(string file);
    void calculate_prefix(string pre);
    void parsing_args(int argc, char ** argv);
    ArgumentParsing();
    vector<string> &split(const string &s, char delim, vector<string> &elems) {
        stringstream ss(s);
        string item;
        while (getline(ss, item, delim)) {
            elems.push_back(item);
        }
        return elems;
    }
    vector<string> split(const string &s, char delim) {
        vector<string> elems;
        split(s, delim, elems);
        return elems;
    }
    
};


    //functions for tcp checksums. Need to check something called psedu_header in tcp
    
    unsigned short generate_tcp_checksum(iphdr *ip_header, tcphdr *tcp_header, u_int16_t length);
    unsigned short generate_udp_checksum(iphdr *ip_header, udphdr *udp_header, u_int16_t length);
    unsigned short csum(unsigned short *pointer , int bytes );
    
    //random number for the sequence number in tcp
     void dns_format_convert(unsigned char* dns,unsigned char* host);
    unsigned int generate_random_number(unsigned int modulus);
    
    //pseudo header structure
    
    struct tcp_pseudo_header
    {
        
        u_int32_t source_address;
        u_int32_t destination_address;
        u_int8_t  reserved;
        u_int8_t  protocol;
        u_int16_t tcp_segment_length;
    };
 
  
        struct udp_pseudo_header
    {
        
        u_int32_t source_address;
        u_int32_t destination_address;
        u_int8_t  reserved;
        u_int8_t  protocol;
        u_int16_t udp_segment_length;
    };
    

