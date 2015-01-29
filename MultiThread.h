//
//  MultiThread.h
//  PortScanner
//
//  Created by Harsh Pathak on 11/23/13.
//  Copyright (c) 2013 Harsh Pathak. All rights reserved.
//

#ifndef __PortScanner__MultiThread__
#define __PortScanner__MultiThread__

#include <iostream>
#include <sys/socket.h>
#include <pthread.h>

using namespace std;
int number_of_threads;

pthread_t t_id;

class Task
{
    
public:
    string ip_address;
    int port;
    string scan_type;

    //Task();
    //Task(std::string, int, string);
    
};


    ssize_t polling_read(int sockfd, int flags, struct sockaddr *address, unsigned long address_len, void * read_buffer, size_t read_length, int time );

    void* start_scans (void *dummy);


#endif /* defined(__PortScanner__MultiThread__) */
