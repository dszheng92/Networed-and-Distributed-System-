#include "gbn.h"

state_t s;

volatile sig_atomic_t print_flag = false;

void timeout_handler(int signum) {
	printf("FUNCTION: timeout_handler()...\n");
	print_flag = true;
}

void reset_timeout()
{
	print_flag = false;
}

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

uint16_t checksum_header(gbnhdr *header)
{
    int nwords = (sizeof(header->type) + sizeof(header->seqnum) + sizeof(header->data))/sizeof(uint16_t);
    uint16_t buf_array[nwords];
    buf_array[0] = ((uint16_t)header->type << 8) + (uint16_t)header->seqnum;
    int byte_index;
	for (byte_index = 1; byte_index <= sizeof(header->data); byte_index++){
		int word_index = (byte_index + 1) / 2;
		if (byte_index % 2 == 1){
			buf_array[word_index] = header->data[byte_index-1]<<8;
		} else {
			buf_array[word_index] += header->data[byte_index - 1];
		}

	}
    uint16_t *buf = buf_array;
	return checksum(buf,nwords);
}

void make_header(int type, uint8_t sequence_num, gbnhdr *header)
{
	memset(header->data, '\0', sizeof(header->data));
	header->type = type;
	header->seqnum = sequence_num;
	header->checksum = checksum_header(header); /* initial checksum*/
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	printf("FUNCTION: gbn_send()...%d\n",len);
	gbnhdr *data_packet = malloc(sizeof(*data_packet));
	gbnhdr *ack_packet = malloc(sizeof(*ack_packet));
	int attempts = 0, i = 0, j = 0;
	struct  sockaddr from;
	socklen_t from_len = sizeof(from);
	socklen_t server_len = sizeof(s.addr);
	while(i<len){
		/* i, the length of file already sent */
		/* j, in this round of window, how many packets is sent*/
		int unack_counter = 0;
		switch(s.state){
			case ESTABLISHED:
				for(j=0;j<s.window_size;j++){
					if((len-i-(DATALEN-2)*j)>0){
						size_t data_length;
						/* 2, the number of bytes used in DATA packet to represent the DATA LENGTH*/
						if(len-i-(DATALEN-2)*j<DATALEN-2){
							data_length = len - i - (DATALEN-2)*j;
						} else{
							data_length = DATALEN-2;
						}
						make_header(DATA,s.seqnum+(uint8_t)j,data_packet);
						memcpy(data_packet->data,(uint16_t *)&data_length,2);
						memcpy(data_packet->data+2, buf+i+(DATALEN-2)*j,data_length);
						data_packet->checksum = checksum_header(data_packet);
						if(attempts<MAX_ATTEMPTS){
							int res = sendto(sockfd,data_packet, sizeof(*data_packet), 0, &s.addr, server_len);
							if(res==-1){
								printf("ERROR: Unable to send data.\n");
								s.state = CLOSED;
								return -1;
							}
						}else{
							printf("ERROR: Reached max attempts. Closing connection...\n");
							s.state = CLOSED;
							return -1;
						}
						printf("SUCCESS: Data sent. %d\n",data_length);
						unack_counter++;
					}
				}
				attempts++;
				size_t ack_counter = 0;
				int unack_counter2 = unack_counter;
				for(j = 0; j<unack_counter2;j+=ack_counter){
					if(maybe_recvfrom(sockfd, ack_packet, sizeof(*ack_packet), 0, &from, &from_len) != -1) {
						if(ack_packet->type == DATAACK && ack_packet->checksum == checksum_header(ack_packet)){
							printf("SUCCESS: DATAACK received.\n");
							ack_counter = 0;
							int diff = ((int)ack_packet->seqnum-(int)s.seqnum);
							if(diff>=0) ack_counter = (size_t)(diff);
							else ack_counter = (size_t)(diff+256);
							unack_counter -= ack_counter;
							s.seqnum = ack_packet->seqnum;
							size_t ack_len = (DATALEN-2)*ack_counter;
							if(i+ack_len<len){
								i+=ack_len;
							}else{
								i = len;
							}
							if(s.window_size<4){
								s.window_size *= 2;
								printf("INFO: window_size switch from slow mode to moderate or moderate to fast, now is %d\n", s.window_size);
							}
							if(unack_counter==0) alarm(0);
							else alarm(TIMEOUT);
						} else if(ack_packet->type==FIN&&ack_packet->checksum==checksum_header(ack_packet)){
							attempts = 0;
							s.state = FIN_RCVD;
							alarm(0);
							break;
						}
					}else{
						printf("ERROR: Unable to receive a ack.\n");
						if(errno==EINTR){
							/* If time out, switch to the slow mode*/
                            if (s.window_size > 1) {
                                s.window_size = 1;
                                printf("INFO: Window size become slow mode\n");
                            }
						} else{
							s.state = CLOSED;
							return -1;
						}
					}
				}
				break;
			case CLOSED:
				gbn_close(sockfd);
				break;
			case SYN_RCVD:
				gbn_close(sockfd);
				break;
			default:break;
		}
	}
	free(data_packet);
	free(ack_packet);
	return s.state == ESTABLISHED?len:-1;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
	printf("FUNCTION: gbn_recv()...\n");
	gbnhdr *data_packet = malloc(sizeof(*data_packet));
	gbnhdr *ack_packet = malloc(sizeof(*ack_packet));
	int received = 0, data_len = 0;
	struct  sockaddr from;
	socklen_t from_len = sizeof(from);
	socklen_t server_len = sizeof(s.addr);
	while(s.state == ESTABLISHED&&received==0){
		printf("INFO: Keep reading data until no more new data to be received.\n");
		if(maybe_recvfrom(sockfd, data_packet, sizeof(*data_packet), 0, &from, &from_len) != -1){
			printf("SUCCESS: Received a packet.\n");
            if(data_packet->type == FIN && data_packet->checksum == checksum_header(data_packet)){
                printf("SUCCESS: Received a valid FIN packet.\n");
                s.state = FIN_RCVD;
                /*in case of overflow (uint8_t)*/
                s.seqnum = data_packet->seqnum + (uint8_t)1;
            }else if(data_packet->type == DATA && data_packet->checksum == checksum_header(data_packet)){
            	printf("SUCCESS: Receiving a valid DATA packet\n");
            	if(data_packet->seqnum == s.seqnum){
            		printf("SUCCESS: DATA packet has the correct sequence number. ");
            		s.seqnum = data_packet->seqnum+(uint8_t)1;
            		memcpy(&data_len,data_packet->data,2);
            		memcpy(buf,data_packet->data+2,data_len);
            		printf("Receive data %d\n",data_len);
            		make_header(DATAACK,s.seqnum,ack_packet);
            		received = 1;
            	}else{
            		printf("INFO: DATA packet has the incorrect sequence number.\n");
            		make_header(DATAACK,s.seqnum,ack_packet);
            	}
            	if(sendto(sockfd,ack_packet, sizeof(*ack_packet), 0, &s.addr, server_len) == -1) {
            		printf("ERROR: Unable to send ACK packet.\n");
                     s.state = CLOSED;
                     break;
            	}else{
            		printf("SUCCESS: Sent duplicate ACK packet.\n");
            	}
            }
		} else{
			printf("ERROR: Unable to receive a packet.\n");
			if(errno!=EINTR){
				printf("ERROR: Other reasons than timeout.\n");
				s.state = CLOSED;
			}
		}
	}
	free(data_packet);
	free(ack_packet);
	switch (s.state){
        case CLOSED: return 0;
        case ESTABLISHED: return data_len;
        default: return -1;
    }
}

int gbn_close(int sockfd){
	printf("FUNCTION: gbn_close()...\n");
	
	gbnhdr *send_fin = malloc(sizeof(*send_fin));
	gbnhdr *send_fin_ack = malloc(sizeof(*send_fin_ack));
	gbnhdr *recv_fin = malloc(sizeof(*recv_fin));
	gbnhdr *recv_fin_ack = malloc(sizeof(*recv_fin_ack));
	struct  sockaddr from;
	socklen_t from_len = sizeof(from);
	socklen_t server_len = sizeof(s.addr);
	int attempts = 0;
	while(s.state!=CLOSED){
		switch(s.state){
			case ESTABLISHED:
				make_header(FIN,s.seqnum,send_fin);
				if(attempts<=MAX_ATTEMPTS){
					int res = sendto(sockfd, send_fin, sizeof(*send_fin), 0, &s.addr, server_len);
					if(res==-1){
						printf("ERROR: Fail to send fin\n");
						s.state = CLOSED;
						break;
					}
					printf("SUCCESS: Send fin success\n");
					attempts++;
					alarm(TIMEOUT);
				}else{
					printf("ERROR: Reached max attempts, set state to closed.\n");
					s.state = CLOSED;
					alarm(0);
					break;
				}
				if(recvfrom(sockfd, send_fin_ack, sizeof(*send_fin_ack), 0, &from, &from_len) != -1) {
					 if(send_fin_ack->type == FINACK && send_fin_ack->checksum == checksum_header(send_fin_ack)){
                        printf("SUCCESS: Recieved SEND_FIN_ACK packet...\n");
                        if(recv_fin_ack->type== FINACK && recv_fin_ack->checksum == checksum_header(recv_fin_ack)){
                        	s.state = CLOSED;
                        	return close(sockfd);
                        } else{
                        	printf("INFO: Waiting for RECV_FIN.\n");
                        	s.state = FIN_SENT;
                        	break;
                        }
                    }
				} else{
					if(errno != EINTR){
						printf("ERROR: Some unknow problems !");
						s.state = CLOSED;
                        return -1;
					}
				}
				break;
			case FIN_SENT:
				if (recvfrom(sockfd, recv_fin, sizeof(*recv_fin), 0, &from, &from_len) != -1) {
                    if (recv_fin->type == FIN && recv_fin->checksum == checksum_header(recv_fin)) {
                        printf("SUCCESS: RECV_FIN received.\n");
                        s.seqnum = recv_fin->seqnum + (uint8_t) 1;
                        s.state = FIN_RCVD;
                    }
                } else {
                    if (errno != EINTR) {
                        printf("ERROR: Fail to receive RECV_FIN.\n");
                        s.state = CLOSED;
                        return -1;
                    }
                }
				break;
			case FIN_RCVD:
				make_header(FINACK, s.seqnum, recv_fin_ack);
                if (sendto(sockfd, recv_fin_ack, sizeof(*recv_fin_ack), 0, &s.addr, server_len) != -1) {
                    printf("SUCCESS: RECV_FIN_ACK sent.\n");
                    alarm(0);
                    if (send_fin_ack->type == FINACK && send_fin_ack->checksum == checksum_header(send_fin_ack)) {
                        s.state = CLOSED;
                    } else {
                        s.state = ESTABLISHED;
                    }
                } else {
                    printf("ERROR: Fail to send RECV_FIN_ACK.\n");
                    s.state = CLOSED;
                    return -1;
                }
				break;
			default:break;
		}
	}
	free(send_fin);
	free(send_fin_ack);
	free(recv_fin);
	free(recv_fin_ack);
	return s.state == CLOSED ? close(sockfd) : -1;
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
	printf("FUNCTION: gbn_connect()...\n");

	/* If connection is broken*/
	if (sockfd < 0) return -1;

	s.state = SYN_SENT;

	/* syn, syn_ack, and ack_packet are used in the 3-way handshake*/
	gbnhdr *syn = malloc(sizeof(*syn));
	gbnhdr *syn_ack = malloc(sizeof(*syn_ack));
	gbnhdr *ack_pkt = malloc(sizeof(*ack_pkt));
	
	make_header(SYN, s.seqnum, syn);
	
	memset(syn_ack->data, '\0', sizeof(syn_ack->data));
	struct sockaddr from;
    socklen_t from_len = sizeof(from);

    ack_pkt->type = DATAACK;
	memset(ack_pkt->data, '\0', sizeof(ack_pkt->data));

	int attempts = 0;
	while(s.state != CLOSED && s.state != ESTABLISHED){
		/* send SYN */
		if (s.state == SYN_SENT && attempts <= MAX_ATTEMPTS) {
			int res = sendto(sockfd, syn, sizeof(*syn), 0, server, socklen);
			if(res == -1){
				printf("ERROR: Unable to send SYNC.\n");
				s.state = CLOSED;
				break;
			} else{
				printf("SUCCESS: Sent SYNC.\n");
				/*timeout setting for SYN, signal SIGALRM sent to the process*/
				alarm(TIMEOUT);
                attempts++;
			}
		} else{
			if(attempts>MAX_ATTEMPTS) {
				printf("ERROR: Reached max attempts. Closing connection...\n");
			} else{
				printf("ERROR: SYN error, resetting state to CLOSED.\n");
			}
			s.state = CLOSED;
			break;
		}

		/* receive ACK */
		if(recvfrom(sockfd, syn_ack, sizeof(*syn_ack), 0, &from, &from_len) != -1 ){
			printf("SUCCESS: Received SYNACK...\n");
			if (syn_ack->type == SYNACK && syn_ack->checksum == checksum_header(syn_ack)) {
                printf("SUCCESS: Received valid SYNACK\n");
                s.seqnum = syn_ack->seqnum;
                s.addr = *server;
                make_header(DATAACK, syn_ack->seqnum, ack_pkt);

                /*can not send ACK*/
                if (sendto(sockfd, ack_pkt, sizeof(*ack_pkt), 0, server,socklen) == -1) {
                    printf("ERROR: Unable to send ACK.\n");
                    s.state = CLOSED;
                    break;
                }

                printf("SUCCESS: DATAACK sent.\n");
                s.state = ESTABLISHED;
            }
		}else{
			reset_timeout();
			/* if error is not interrupted system call*/
			if(errno != EINTR){
				printf("ERROR: Receiving SYNACK.\n");
				s.state = CLOSED;
				break;
			}
		}
	}
	free(syn);
    free(syn_ack);
    free(ack_pkt);
	return (s.state == ESTABLISHED)? 0 : -1;
}

int gbn_listen(int sockfd, int backlog){
	printf("FUNCTION: gbn_listen()...\n");
	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
	printf("FUNCTION: gbn_bind()...\n");
	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
	printf("FUNCTION: gbn_socket()...\n");

	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	s = *(state_t*)malloc(sizeof(s));
	s.seqnum = (uint8_t)rand();
	s.window_size = 1;
	/* when accepting SIGALRM signal, apply timeout_handler function to deal with it*/
	signal(SIGALRM, timeout_handler);
	/* The siginterrupt() function is used to change the restart behavior when a function is interrupted by the specified signal.*/
	siginterrupt(SIGALRM, 1);

	return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
	printf("FUNCTION: gbn_accept()...\n");

	s.state = CLOSED;
	gbnhdr *syn = malloc(sizeof(*syn));
	gbnhdr *syn_ack = malloc(sizeof(*syn_ack));
	gbnhdr *ack_pkt = malloc(sizeof(*ack_pkt));
	int attempts = 0;
	while(s.state != ESTABLISHED){
		switch (s.state) {
			case CLOSED:
				printf("STATE: CLOSED.\n");
				if (recvfrom(sockfd, syn, sizeof(*syn), 0, client, socklen) != -1) {
                    if (syn->type == SYN && syn->checksum == checksum_header(syn)) {
                        printf("SUCCESS: Received SYN.\n");
                        s.state = SYN_RCVD;
                        s.seqnum = syn->seqnum + (uint8_t) 1;
                    }else {
                        printf("ERROR: Received invalid SYN.\n");
                        s.state = CLOSED;
                    }
                } else {
                    printf("ERROR: Unable to receive SYN.\n");
                    s.state = CLOSED;
                    return -1;
                }
				break;
			case SYN_RCVD:
				printf("STATE: SYN_RCVD.\n");
				make_header(SYNACK,s.seqnum,syn_ack);
				if(attempts>MAX_ATTEMPTS){
					printf("ERROR:Reached max attempts. Closing coonection...\n");
					errno = 0;
					s.state = CLOSED;
					return -1;
				}else if(sendto(sockfd,syn_ack,sizeof(*syn_ack),0,client,*socklen)==-1){
					printf("ERROR: Unable to send the SYNACK. Closing connecion...");
					s.state = CLOSED;
					return -1;
				}else{
					printf("SUCCESS: Sent SYNACK.\n");
					alarm(TIMEOUT);
					attempts++;
					if(recvfrom(sockfd,ack_pkt,sizeof(*ack_pkt),0,client,socklen)==-1){
						if(errno!=EINTR){
							printf("ERROR: Unable to receive ACK.\n");
							s.state = CLOSED;
							return -1;
						}
					} else if(ack_pkt->type==DATAACK&&ack_pkt->checksum==checksum_header(ack_pkt)){
						printf("SUCCESS: Accepted a valid ACK packet.\n");
						s.state = ESTABLISHED;
						s.addr = *client;
						printf("STATE: ESTABLISHED.\n");
					} else {
						printf("ERROR: \n");
					}
				}
				break;
			default:break;
		}
	}
	free(syn);
    free(syn_ack);
    free(ack_pkt);
	return s.state==ESTABLISHED?sockfd:-1;
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}
