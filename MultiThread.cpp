//
//  MultiThread.cpp
//  PortScanner
//
//  Created by Harsh Pathak on 11/23/13.
//  Copyright (c) 2013 Harsh Pathak. All rights reserved.
//

#include <cmath>
#include <stdio.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <iostream>




using namespace std;

namespace MultiThread
{

    ssize_t polling_read(int sockfd, int flags, sockaddr *address, unsigned long address_len, void * read_buffer, size_t read_length, int time )
    {
        
        /* Using poll() for i/o multiplexing.*/
        int n_events;
        ssize_t bytes_read = 0;
        pollfd nfds;
        nfds.events = POLLIN; /* only interested in reading */
        nfds.revents = 0; /* event that actually occured */
        
        /* get current flags before setting */
        int current_flags = fcntl(sockfd,F_GETFL);
        fcntl(sockfd,F_SETFL, current_flags | O_NONBLOCK );
        
        n_events = poll(&nfds,1,time); /*poll the socket here. Just one */
        
        
        /*check number of events occured. Less than zero case can be ignored since its either a timeout or call fail */
        
        cout << n_events << endl;
        if(n_events == 0)
        {
            
            /*check if event occured */
            if (nfds.events == POLLIN)
            {
                
                bytes_read=recv(sockfd, read_buffer, read_length , flags);
                /*event occured , reset flags */
                fcntl(sockfd, F_SETFL, current_flags);
            }
            
        }
        cout << " Data read is " << bytes_read << endl;
        return bytes_read;
    }
    
    

}





