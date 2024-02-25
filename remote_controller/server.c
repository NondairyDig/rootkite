#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h> // inet_addr
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 63888
#define MAX_THREADS 50
#define BUFFER_SIZE 1024
#define CDEV_DEVICE "controller"

int main(int argc, char const *argv[])
{
	int server_main_socket;
	struct sockaddr_in server_addr, cliaddr;
	char buffer[BUFFER_SIZE];

	socklen_t addr_size;

	if ( (server_main_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
		perror("socket creation failed");
		exit(EXIT_FAILURE);
	}
	server_addr.sin_addr.s_addr = INADDR_ANY; // can use inet_aton("<addr>", &server_addr.sin_addr.s_addr)
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);

	/* Bind the socket to the
	   address and port number. */
	// Bind the socket with the server address
	if ( bind(server_main_socket, (const struct sockaddr *)&server_addr,
			sizeof(server_addr)) < 0 )
	{
		perror("bind failed");
		exit(EXIT_FAILURE);
	}

	int len, n;
	while (1) {
		len = sizeof(cliaddr);
		if((n = recvfrom(server_main_socket, buffer, BUFFER_SIZE, 0,
						 (struct sockaddr *) &cliaddr, &len)) < 0){
 			printf("\n\nrecvfrom() failed with error code : %d" , n);
		}
	
    	int fd, len;
    	if ((fd = open("/dev/" CDEV_DEVICE, O_RDWR)) == -1) {
    	    perror("/dev/" CDEV_DEVICE);
    	    exit(1);
    	}

    	if (write(fd, buffer, strlen(buffer)+1) == -1)
    	    perror("write()");
    	else
    	    printf("Executed: \"%s\".\n", buffer);


    	if ((close(fd)) == -1) {
    	    perror("close()");
    	    exit(1);
    	}
	}
	return 0;
}
