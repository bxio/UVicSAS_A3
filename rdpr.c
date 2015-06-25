/*Colum McClay V00745851 RDP receiver program.
Some code taken from sws.c from lab given code
Timer code obtained from StackOverflow
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>


#define MAXBUFLEN 1024
#define TIMEOUT 1 //second

#define SPACE 5
int winsize = 5120;



//struct will keep stats for transfer
struct Info {
    int total_bytes_rcv;
    int unique_bytes_rcv;
    int total_packets_rcv;
    int unique_packets_rcv;
    int syn_rcv;
    int fin_rcv;
    int rst_rcv;
    int ack_sent;
    int rst_sent;
};

//increases ack no
void increaAck(int * num,int size){
    //must also add wrap around max int
    *num+=size;
}


//set all values in struct to default
void assignDef(struct Info *c){
    c->total_bytes_rcv =0;
    c->unique_bytes_rcv =0;
    c->total_packets_rcv =0;
    c->unique_packets_rcv =0;
    c->syn_rcv =0;
    c->fin_rcv =0;
    c->rst_rcv =0;
    c->ack_sent =0;
    c->rst_sent =0;
}


//function determines packet type by appropriate returning values
int isA(char * a){

    char tr[10];
    strncpy(tr,a,8);
    //printf("Header part:\n%s\n\n",tr);


    if(strncmp(tr,"361\nSYN\n",8)==0){
        //printf("Found SYN\n");
        return 1;
    }
    if(strncmp(tr,"361\nACK\n",8)==0){
        //printf("Found ACK\n");
        return 2;
    }
    if(strncmp(tr,"361\nDAT\n",8)==0){
        //printf("Found DAT\n");
        return 3;
    }
    if(strncmp(tr,"361\nFIN\n",8)==0){
        //printf("Found FIN\n");
        return 4;
    }
    else{
        //printf("Found RST\n");
        return 5;
    }


}

//returns the sequence number of a packet
//verified
//g=1 for seq
//
int getSeqNo(char * a, int g){
	//printf("Extracting from..:\n%s\n\n-------\n",a);
	int loc_start =0;
	int counted = 0;
	int n;
	if(g==1){
		n=2;
	}
	if(g==2){
		n=4;
	}

	while(counted != n){
		if(a[loc_start] == '\n'){
			counted+=1;
		}
		loc_start+=1;
	}
	int loc_end = loc_start;
	while(a[loc_end] != '\n'){
		loc_end+=1;
	}
	int i;
	char seq_abc[15];
	int to=0;
	for(i=loc_start;i<loc_end;i++){
		seq_abc[to]=a[i];
		to+=1;
	}
	seq_abc[to] = '\0';
	int seq_123 = atoi(seq_abc);
	return seq_123;
}

//returns ACK/Winsz from given packet
// b=1 for ACK
// b=2 for winsz
// b=3 for seq
int get(char * a, int b){
	//printf("Extracting from..:\n%s\n\n-------\n",a);
	int loc_start =0;
	int counted = 0;
	int r;
	if (b==1){
		r=3;
	}
	if(b==2){
		r=5;
	}
	if(b==3){
		r=2;	
	}
	while(counted != r){
		if(a[loc_start] == '\n'){
			counted+=1;
		}
		loc_start+=1;
	}
	int loc_end = loc_start;
	while(a[loc_end] != '\n'){
		loc_end+=1;
	}
	int i;
	char seq_abc[15];
	int to=0;
	for(i=loc_start;i<loc_end;i++){
		seq_abc[to]=a[i];
		to+=1;
	}
	seq_abc[to] = '\0';
	int seq_123 = atoi(seq_abc);
	//printf("get(): %d\n",seq_123);
	return seq_123;
}

//print out event (in or outgoing packet)
//flow: 1= sending, 2 = recving
//t: 1 = dupl , 2 =not dupl
void printEvent(int flow, int t, char * packet,char * packtype,char * dip, char * dpt){
	
	char outgo [100];
	char*sip="192.168.1.100";
	char*spt="45678";
	time_t current_time;
	current_time=time(NULL);
	char * c_time_string = ctime(&current_time);

	struct timeval tv;
	gettimeofday(&tv,NULL);
	

	int k;
	for(k=11;k<19;k++){
		printf("%c",c_time_string[k]);
	}
	printf(":%06ld",tv.tv_usec);

	if(flow == 1){ //event is outgoing packet
		int ack = get(packet,1);
		int wins = get(packet,2);
		if(t==1){//event is duplicate packet
			sprintf(outgo," S %s:%s %s:%s %s %d %d\n",sip,spt,dip,dpt,packtype,ack,wins);
			printf("%s",outgo);
			return;
		}

		if(t==2){// event is not a duplicate packet
			sprintf(outgo," s %s:%s %s:%s %s %d %d\n",sip,spt,dip,dpt,packtype,ack,wins);
			printf("%s",outgo);
			return;
		}
	}

	if( flow == 2 ){ //event is incoming packet
		int seq = get(packet,3);
		int leng = strlen(packet);
		if(t==1){//event is duplicate packet
			sprintf(outgo," R %s:%s %s:%s %s %d %d\n",sip,spt,dip,dpt,packtype,seq,leng);
			printf("%s",outgo);
			return;
		}
		if(t==2){
			sprintf(outgo," r %s:%s %s:%s %s %d %d\n",sip,spt,dip,dpt,packtype,seq,leng);
			printf("%s",outgo);
			return;
		}
	}
}


//returns packet with an ack no and type
//function verified
char * makePack(int ackno,int kind){
	char * rtpk = (char *) malloc(30*sizeof(char));
	char * magic = "361\n";
	char * type;
	if(kind==1){
		type = "ACK\n";
	}else if(kind==2){
		type = "RST\n";
	}
	char * seqno ="0\n";
	char * nl ="\n";
	char * length = "0\n";
	sprintf(rtpk,"%s%s%s%d\n%s%d%s",magic,type,seqno,ackno,length,winsize,nl);
	strcat(rtpk,"\0");
	return rtpk;
}


//establishes by waiting for SYN packet from sender. Returns SENDER seq #
//verified
int estConn( struct sockaddr_in *cli_addr,int sockfd,struct Info *c,char * dip, char * dpt){
	//printf("Waiting for sender....\n");
	char buffer[MAXBUFLEN];
	socklen_t cli_len = sizeof(*cli_addr);
	int verify = recvfrom(sockfd, buffer, MAXBUFLEN-1 , 0,(struct sockaddr *)&*cli_addr, &cli_len);
	if(verify==-1){
		printf("error on recvfrom()\nExit..\n");
		exit(1);
	}
	buffer[verify] = '\0';

	int type = isA(buffer);
	if(type == 1){ //got syn
		printEvent(2,2,buffer,"SYN",dip,dpt);
		c->syn_rcv+=1;
		c->total_bytes_rcv+=strlen(buffer);
		c->unique_bytes_rcv+=strlen(buffer);
		c->total_packets_rcv+=1;
		c->unique_packets_rcv+=1;
	}
	else{
		return -1;
	}

	int s_seq = getSeqNo(buffer,1) + strlen(buffer);
	char * tosend = makePack(s_seq,1);
	//printf("tosend:\n%s\n",tosend);

	int charsent;
	if ((charsent = sendto(sockfd, tosend, strlen(tosend), 0,(struct sockaddr *)&*cli_addr, cli_len) == -1)) {
		perror("sws: error in sendto()");
		exit(1);
    }

	printEvent(1,2,tosend,"ACK",dip,dpt);
	c->ack_sent+=1;
	free(tosend);
	return s_seq;

}

//function checks if incoming packet is already in buffer
//verified
int checkSpace(int seq,char ** space,int *loc){
	int k;
	for(k=0;k<5;k++){
        if(loc[k]==0){
            continue;
        }
		if( seq ==  getSeqNo(space[k],1)){
			return 1;
		}
	}

	return 0;

}

//send packet with ACK no	
//int corr is for printEv purposes only.
//corr: 1= dupl, 2= not dupl
void sendACK(int last_cons_seq,struct sockaddr_in * cli_addr, int sockfd,char*dip,char*dpt,int corr){

    char * pack = makePack(last_cons_seq,1);

    socklen_t cli_len = sizeof(*cli_addr);
    int charsent;
    if ((charsent = sendto(sockfd, pack, strlen(pack), 0,(struct sockaddr *)&*cli_addr, cli_len) == -1)) {
        perror("sws: error in sendto()");
        exit(1);
    }

	if(corr==2){
		printEvent(1,2,pack,"ACK",dip,dpt);
	}
	if(corr==1){
		printEvent(1,1,pack,"ACK",dip,dpt);
	}
	
	
    free(pack);
}


//function takes packet and places it into appl. "buffer"
//packets that come here cannot be consumed yet since their seq no is past a hole. Stored into space[][] instead
//if space[][] is full, return 0
//verified
void putInSpace(char * pack, char ** space, int * fill){
    int i;
    int catch=0;
    for(i=0;i<SPACE;i++){
        if(fill[i]==0){
            catch=1;
            break;
        }
    }
    if(catch==1){
        strcpy(space[i],pack);
        fill[i]=1;
        winsize-=MAXBUFLEN;
    }
}


//function takes packet, strips header and writes to file fp
//verified
void addToOut(char * a, FILE *fp){
    int loc_start =0;
    int counted = 0;
    while(loc_start<strlen(a)){
        if(a[loc_start] == '\n' && a[loc_start-1]=='\n'){
            break;
        }
        loc_start+=1;
    }
    loc_start+=1;
    char c = a[loc_start];
    while(c!='\0'){
        fputc(c,fp);
        loc_start+=1;
        c=a[loc_start];
    }

}


void reestConn(struct sockaddr_in *cli_addr,int sockfd,struct Info *c,int seq_no){

}
//checks if consecutive packet is contained in space[][]
//if it is, output it to file
void moveOutSpace(char ** space,int compare,int *fill,int * new_latest_consec_seq,int spot,FILE *fp,\
		struct Info *c,char * dip,char*dpt,int sockfd,struct sockaddr_in *cli_addr,int * flag){
    int i;
	if(fill[spot] == 0){ //if nothing in spot, dont check it
		return;
	}

	

	i=get(space[spot],3);

	if(compare > i){
		fill[spot]=0;
		winsize+=MAXBUFLEN;
	}

	if( compare == i ){
		*new_latest_consec_seq += strlen(space[spot]);
		addToOut(space[spot],fp);
		*flag=1;
		fill[spot]=0;
		winsize+=MAXBUFLEN;
		sendACK(*new_latest_consec_seq,cli_addr,sockfd,dip,dpt,1);
		c->ack_sent+=1;
	}

}
void printstat(struct Info *c){
    printf("total bytes rcv    = %d\n",c->total_bytes_rcv);
    printf("Unique bytes rcv   = %d\n",c->unique_bytes_rcv);
    printf("Total packets rcv  = %d\n",c->total_packets_rcv);
    printf("Unique packets rcv = %d\n",c->unique_packets_rcv);
    printf("SYN rcv  = %d\n",c->syn_rcv);
    printf("FIN rcv  = %d\n",c->fin_rcv);
    printf("RST rcv  = %d\n",c->rst_rcv);
    printf("ACK sent = %d\n",c->ack_sent);
    printf("RST sent = %d\n",c->rst_sent);
}

void printspace(char ** space){
	int i;
	for(i=0;i<5;i++){
		printf("SPACE[%d]\n%s--------------------------\n",i,space[i]);
	}

}





//_______________________________________________MAIN________________________________________________________________


int main(int argc, char* argv[]){

	struct timeval start=(struct timeval){0};
	struct timeval end = (struct timeval){0};

	gettimeofday(&start,NULL);

    int sockfd, portno;
    socklen_t serv_len;
    int receive_space = 250;
	int ackno;

    //file in will be added in here
    char * file_in = (char *) malloc(receive_space * sizeof(char));
	if(file_in == NULL){
		printf("error on malloc\n");
		exit(1);
	}
    struct sockaddr_in serv_addr, cli_addr;
    int numbytes;

    //verify cmd line params..
    if (argc < 3) {
        printf( "Usage: <ip> <port> <output file>\n");
        fprintf(stderr,"ERROR, no port provided. Graceful exit...\n");
        return -1;
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
        perror("sws: error on socket(), Graceful exit..");
        return -1;
    }




	printf("RECEIVER PRGM\n");


    //configure connection
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(argv[2]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(portno);

	char * dip =argv[1];
	char * dpt =argv[2];
	char * sip;
	char * spt;


    int optval = 1;
    if ( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval) < 0 ) {
        perror("sws: error on set socket option!");
        return -1;
    }


    if (bind(sockfd, (struct sockaddr *) &serv_addr,
        sizeof(serv_addr)) < 0){
        close(sockfd);
        perror("sws: error on binding! Graceful exit...");
        return -1;
    }

	struct Info stat;
    assignDef(&stat);

	int last_cons_seq = estConn(&serv_addr,sockfd,&stat,dip,dpt);
	if(last_cons_seq == -1){
		printf("Could not establish connection...exit\n");
		exit(1);
	}
	

	char ** space = (char **) malloc(SPACE*sizeof(char*)); //will contain packets received PAST sequence "hole"

	if(space == NULL){
		printf("Error on malloc..\nExit..\n");
		exit(1);
	}

	int h;
	for(h=0;h<SPACE;h++){
		space[h] = (char *) malloc(MAXBUFLEN*sizeof(char));
		if(space[h] == NULL){
			printf("Error on malloc..\nExit..\n");
			exit(1);
		}
	}

	int spaceFill[5]={0,0,0,0,0}; //boolean array to contain fill of space[i]

    char * in_pack = (char *) malloc(MAXBUFLEN * sizeof(char)); //incoming packet goes in here
    if(in_pack == NULL){
        printf("Error on malloc..\nExit..\n");
        exit(1);
    }


    FILE *fp = fopen(argv[3],"a"); //create file

    struct timeval timeout = (struct timeval){0};
    timeout.tv_sec=TIMEOUT;
    timeout.tv_usec= 0;

	serv_len = sizeof(serv_addr);
    int retval;
    fd_set readfds;
    int times = 0;
    int verify;
    int pktype;
    int recv_seq;
    int ackback;
	int last_read_from_space=0;

	while(1){
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
        timeout.tv_sec=TIMEOUT;

		retval=select(sockfd+1, &readfds, NULL, NULL, &timeout);
        if(retval==-1){
            printf("Select error\nExit\n");
            exit(1);
        }

        if(retval ==0){ //select() timeout
            times+=1;
			printf("timeout\n");
            sendACK(last_cons_seq,&serv_addr,sockfd,dip,dpt,1);
            stat.ack_sent+=1;
            if(times==5){
                printf("Connection unreliable\nExit\n");
                exit(1);
            }
            continue;
        }

        times=0;
		
        verify = recvfrom(sockfd, in_pack, MAXBUFLEN-1 , 0,(struct sockaddr *)&serv_addr, &serv_len);
        if(verify==-1){
            printf("error on recvfrom()\nExit..\n");
            exit(1);
        }
        in_pack[verify] = '\0';

        int pktype=isA(in_pack);

        if(pktype == 3){ //if (packet==DATA)
            recv_seq = getSeqNo(in_pack,1);
			

            if(recv_seq < last_cons_seq || checkSpace(recv_seq,space,spaceFill)){
				//printf("Already rcv this one.. \n");
				printEvent(2,1,in_pack,"DAT",dip,dpt);
                sendACK(last_cons_seq,&serv_addr,sockfd,dip,dpt,1);

                stat.ack_sent+=1;
				stat.total_bytes_rcv+=strlen(in_pack);
				stat.total_packets_rcv+=1;
				
				
					
            }


            if(recv_seq == last_cons_seq && last_read_from_space == 0){
                //we have received a 'good' consecutive packet
				//printf("Good packet! ");
				printEvent(2,2,in_pack,"DAT",dip,dpt);
                addToOut(in_pack,fp);
                last_cons_seq += strlen(in_pack);
                sendACK(last_cons_seq,&serv_addr,sockfd,dip,dpt,2);

                stat.unique_packets_rcv+=1;
				stat.total_packets_rcv+=1;
                stat.ack_sent+=1;
				stat.unique_bytes_rcv+=strlen(in_pack);
				stat.total_bytes_rcv+=strlen(in_pack);
				
            }


            else{ //we have received a packet past a hole
				//printf("Recvd after a hole.. \n");
				printEvent(2,2,in_pack,"DAT",dip,dpt);
                putInSpace(in_pack,space,spaceFill);
                sendACK(last_cons_seq,&serv_addr,sockfd,dip,dpt,2);

                stat.ack_sent+=1;
				stat.unique_bytes_rcv+=strlen(in_pack);
				stat.total_bytes_rcv+=strlen(in_pack);
				stat.unique_packets_rcv+=1;
				stat.total_packets_rcv+=1;

            }

			last_read_from_space = 0;
        }

        //all packets in space[][] be sent to file if they are rightly sequenced
	
        moveOutSpace(space,last_cons_seq,spaceFill,&last_cons_seq,0,fp,&stat,dip,dpt,sockfd,&serv_addr,&last_read_from_space);
        moveOutSpace(space,last_cons_seq,spaceFill,&last_cons_seq,1,fp,&stat,dip,dpt,sockfd,&serv_addr,&last_read_from_space);
        moveOutSpace(space,last_cons_seq,spaceFill,&last_cons_seq,2,fp,&stat,dip,dpt,sockfd,&serv_addr,&last_read_from_space);
        moveOutSpace(space,last_cons_seq,spaceFill,&last_cons_seq,3,fp,&stat,dip,dpt,sockfd,&serv_addr,&last_read_from_space);
        moveOutSpace(space,last_cons_seq,spaceFill,&last_cons_seq,4,fp,&stat,dip,dpt,sockfd,&serv_addr,&last_read_from_space);

        if(pktype == 1){ //if (packet == SYN)
			printEvent(2,2,in_pack,"SYN",dip,dpt);

			stat.unique_bytes_rcv+=strlen(in_pack);
			stat.total_bytes_rcv+=strlen(in_pack);
			stat.unique_packets_rcv+=1;
			stat.total_packets_rcv+=1;
			stat.syn_rcv+=1;

            reestConn(&serv_addr,sockfd,&stat,0);
			last_cons_seq += strlen(in_pack);
            continue;
        }

        if(pktype == 4){ //if (packet == FIN)
			printEvent(2,2,in_pack,"FIN",dip,dpt);

			stat.unique_bytes_rcv+=strlen(in_pack);
			stat.total_bytes_rcv+=strlen(in_pack);
			stat.unique_packets_rcv+=1;
			stat.total_packets_rcv+=1;
			stat.fin_rcv+=1;

			last_cons_seq += strlen(in_pack);
            sendACK(last_cons_seq,&serv_addr,sockfd,dip,dpt,2);
            stat.ack_sent+=1;
            break;
        }
    }


		printf("\n");
		printstat(&stat);
		printf("\n");
		//print timer
        free(in_pack);
        int y;
        for(y=0;y<5;y++){
            free(space[y]);
        }
        free(space);
        fclose(fp);

	gettimeofday(&end,NULL);

	double et = end.tv_usec - start.tv_usec;
	et/=1000000;
	et= et + (end.tv_sec - start.tv_sec);

	printf("\nExecution time = %fs\n",et); 
		



}



