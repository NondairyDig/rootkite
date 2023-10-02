#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <arpa/inet.h> // inet_addr

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 63888
#define MAX_THREADS 50
#define BUFFER_SIZE 1024
#define CDEV_DEVICE "controller"


// Semaphore variables
sem_t x;
pthread_t threads[100];

// Reader Function
void* reader(void *new_socket)
{
	char choice[BUFFER_SIZE];
	/*Lock the semaphore*/
	sem_wait(&x);
	recv(*(int *)new_socket,
		&choice, BUFFER_SIZE, 0);
	
    int fd, len;
    if ((fd = open("/dev/" CDEV_DEVICE, O_RDWR)) == -1) {
        perror("/dev/" CDEV_DEVICE);
        exit(1);
    }

    if (write(fd, choice, strlen(choice)+1) == -1)
        perror("write()");
    else
        printf("Executed: \"%s\".\n", choice);


    if ((close(fd)) == -1) {
        perror("close()");
        exit(1);
    }
	/* Unlock the semaphore*/	
	sem_post(&x);

	pthread_exit(NULL);
}


int main(int argc, char const *argv[])
{
	int server_main_socket, new_socket;
	struct sockaddr_in server_addr;
	struct sockaddr_storage buffer;

	socklen_t addr_size;
	sem_init(&x, 0, 1);

	server_main_socket = socket(AF_INET, SOCK_STREAM, 0);
	server_addr.sin_addr.s_addr = INADDR_ANY; // can use inet_aton("<addr>", &server_addr.sin_addr.s_addr)
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(PORT);

	/* Bind the socket to the
	   address and port number. */
	bind(server_main_socket,
		(struct sockaddr*)&server_addr,
		sizeof(server_addr));

    /* transform the socket to listen 
       limit to 50 requests
    */
	if (listen(server_main_socket, MAX_THREADS) == 0)
		printf("Listening\n");
	else
		printf("Error\n");


	int i = 0;

	while (1) {
		addr_size = sizeof(buffer);
		new_socket = accept(server_main_socket,
						(struct sockaddr*)&buffer,
						&addr_size);

		if (pthread_create(&threads[i++], NULL,
						reader, (void *)&new_socket) != 0)
			printf("Failed to create thread\n");

		if (i >= MAX_THREADS) {
			i = 0;

			while (i < MAX_THREADS) {
				/* Suspend execution of
				   the calling thread
				   until the target
				   thread terminates */
				pthread_join(threads[i++],
							NULL);
			}

			i = 0;
		}
	}

	return 0;
}
