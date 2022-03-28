#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <thread>
#include <string>
int socket_fd;
const int one = 1;
int init_fd(const int listen_port,const int backlog) {
	socket_fd = socket(AF_INET6,SOCK_STREAM,0);
	if (socket_fd < 0) return socket_fd;
	int error;
	error = setsockopt(socket_fd,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(int));
	if (error) return error;
	struct sockaddr_in6 server_sockaddr;
	server_sockaddr.sin6_family = AF_INET6;
	server_sockaddr.sin6_port = htons(listen_port);
	server_sockaddr.sin6_addr = in6addr_any;
	error = bind(socket_fd,(struct sockaddr* )&server_sockaddr,sizeof(server_sockaddr));
	if (error == -1) return error;
	error = listen(socket_fd,backlog);
	if (error == -1) return error;
	
	return 0;
}
void forward(const int fd_x,const int fd_y) {//fd_x->fd_y
	const int buf_sz = 2048;
	char buf[buf_sz];
	ssize_t sz;
	while ((sz = recv(fd_x,buf,buf_sz,0)) > 0) {
		if (send(fd_y,buf,sz,0) < 0) break;
	}
	close(fd_x);
	close(fd_y);
}
void client_socket(const int client_fd,sockaddr_in6 destaddr) {
	int new_socket = socket(AF_INET6,SOCK_STREAM,0);
	if (connect(new_socket,(sockaddr*)&destaddr,sizeof(struct sockaddr_in6))) {
		printf("[ERROR] Destnation socket failed.\n");
		close(new_socket);
		close(new_socket);
	}
	else {
		printf("[INFO] Destnation socket connected.\n");
		std::thread tx(forward,new_socket,client_fd);
		std::thread rx(forward,client_fd,new_socket);
		tx.join();
		rx.join();
		printf("[INFO] Connection Closed.\n");
	}
}
void accept_client() {
	struct sockaddr_in6 clientaddr,myaddr,destaddr;
	struct sockaddr_in destaddr_v4;
	socklen_t addrlen = sizeof(struct sockaddr_in6);
	socklen_t addrlen_v4 = sizeof(struct sockaddr_in6);
	int client_fd = accept(socket_fd,(struct sockaddr*)&clientaddr,&addrlen);
	if (client_fd == -1) {
		printf("[ERROR] accept return %d:",client_fd);
		perror("");
		printf("\n");
		close(socket_fd);
		exit(1);
		return;
	}
	int error;
	error = getsockname(client_fd, (struct sockaddr*)&myaddr,&addrlen);
	if (error) {
		printf("[ERROR] getsockname return %d\n",error);
		perror("");
		printf("\n");
		return;
	}
	if IN6_IS_ADDR_V4MAPPED(&myaddr.sin6_addr) {
		error = getsockopt(client_fd, SOL_IP, SO_ORIGINAL_DST,&destaddr_v4,&addrlen_v4);
		inet_pton(AF_INET6, "0000:0000:0000:0000:0000:FFFF:0000:0000", &destaddr.sin6_addr);
		destaddr.sin6_port = destaddr_v4.sin_port;
		memcpy(destaddr.sin6_addr.s6_addr + 12, &destaddr_v4.sin_addr, 4);
	} else {
		error = getsockopt(client_fd, SOL_IPV6, SO_ORIGINAL_DST,&destaddr,&addrlen);
	}
	if (error) {
		printf("[ERROR] getsockopt return %d:",error);
		perror("");
		printf("\n");
		return;
	}
	char clientip[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(clientaddr.sin6_addr), clientip, INET6_ADDRSTRLEN);
	char myip[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(myaddr.sin6_addr), myip, INET6_ADDRSTRLEN);
	char dstip[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, &(destaddr.sin6_addr), dstip, INET6_ADDRSTRLEN);
	if (myaddr.sin6_port == destaddr.sin6_port) {
		//to avoid fork bomb, so you should bind to an uncommon port.
		printf("[ERROR] Self loop detected %s:%d -> %s:%d -> %s:%d\n",
			clientip,ntohs(clientaddr.sin6_port),
			myip,ntohs(myaddr.sin6_port),
			dstip,ntohs(destaddr.sin6_port)
		);
		close(client_fd);
	}
	else {
		printf("[INFO] Client from %s:%d -> %s:%d -> %s:%d\n",
			clientip,ntohs(clientaddr.sin6_port),
			myip,ntohs(myaddr.sin6_port),
			dstip,ntohs(destaddr.sin6_port)
		);
		std::thread t(client_socket,client_fd,destaddr);
		t.detach();
	}
}
void signnal_process(sig_t s){
	printf("[ERROR] caught signal %d\n",s);
	close(socket_fd);
	exit(1); 
}
int main(int argc,char *argv[]) {
	int listen_port = 12345;
	for (int i=0;i<argc;i++) {
		if (std::string(argv[i]) == "-l") {
			if (i + 1 < argc && atoi(argv[i+1]) > 0 && atoi(argv[i+1]) < 65536) {
				listen_port = atoi(argv[i+1]);
			} 
		}
	}
	if (init_fd(listen_port,1024)) {
		perror("[ERROR] listen failed:");
		return -1;
	}
	printf("[INFO] Listening port %d\n",listen_port);
	signal(SIGINT,(__sighandler_t)signnal_process);
	while (1) accept_client();
	return 0;
}
