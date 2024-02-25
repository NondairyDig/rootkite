#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <unistd.h>

#include <pthread.h>
#include <semaphore.h>


#define BUFFER_SIZE 1024
#define PORT 63888
#define ADDRESS "127.0.0.1"

void* client_thread(void* choice)
{
	int network_socket;

	network_socket = socket(AF_INET,
							SOCK_DGRAM, 0);

	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	inet_aton(ADDRESS, (struct in_addr *)&server_address.sin_addr.s_addr);
	server_address.sin_port = htons(PORT);

	sendto(network_socket, (char *)choice,
		BUFFER_SIZE, 0, (struct sockaddr *) &server_address, sizeof(server_address));

	close(network_socket);
	pthread_exit(NULL);

	return 0;
}


int main(int argc, char const *argv[])
{
	int len;
	if (argc != 2) {
        printf("Usage: %s <string>\n", argv[0]);
        exit(0);
    }

    if ((len = strlen(argv[1]) + 1) > 512) {
        printf("ERROR: String too long\n");
        exit(0);
    }

	char choice[BUFFER_SIZE];
	//fgets(choice, BUFFER_SIZE, stdin);
	strcpy(choice, argv[1]);
	pthread_t tid;
	
	pthread_create(&tid, NULL,
		client_thread,
		(void *)choice);

	pthread_join(tid, NULL);
}
