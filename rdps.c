/* Colum McClay V00745851 - certain parts of code obtained from lab code: Thanks to Boyang Yu . */
/* Obtained time and date C function code from wikipedia*/


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
#include <math.h>

#define MAXBUFLEN 1024
#define HEADERSIZE 29
#define TIMEOUT 1
#define RETRY 3

//NEED TO SET TIMER FOR ENTIRE FILE TRNSFER



//struct of this type will contain transfer statistics
struct Info {
    int total_bytes_sent;
    int unique_bytes_sent;
    int total_packets_sent;
    int unique_packets;
    int syn_sent;
    int fin_sent;
    int rst_sent;
    int ack_received;
    int rst_received;
};




//set all values in struct to default
void assignDef(struct Info *c){
    c->total_bytes_sent =0;
    c->unique_bytes_sent =0;
    c->total_packets_sent =0;
    c->unique_packets =0;
    c->syn_sent =0;
    c->fin_sent =0;
    c->rst_sent =0;
    c->ack_received =0;
    c->rst_received =0;
}


void printStats(struct Info *c){
	printf("Total bytes sent   = %d\n",c->total_bytes_sent);
	printf("Unique bytes sent  = %d\n",c->unique_bytes_sent);	
	printf("Total packets sent = %d\n",c->total_packets_sent);
	printf("Uniqe packets sent = %d\n",c->unique_packets);
	printf("SYN sent = %d\n",c->syn_sent);
	printf("FIN sent = %d\n",c->fin_sent);
	printf("RST sent = %d\n",c->rst_sent);
	printf("ACK rcv  = %d\n",c->ack_received);
	printf("RST rcv  = %d\n",c->rst_received);
}



void increaSeq(int * num,int size){
    //must also add wrap around max int
    *num+=size;
}

char * returnPack(int *seq, FILE *fp, int type, int *chars_taken,int *last_sig,int *last_ack_val){
		
    char * magic = "361\n"; //magic type
    char * type_f;
    if(type==1){
        type_f = "DAT\n"; //packet type
    }else if(type==2){
        type_f = "SYN\n";
    }else if (type==3){
        type_f = "ACK\n";
    }else if(type==4){
        type_f = "FIN\n";
    }
    int payload;

    if(type!=1){
        payload =0; //payload
    }

    //sequence number = seq from parameters

    char * ackno = "0\n"; //ackno
    char * winsz = "0\n"; //winsz
    char * last = "\n";   //last line of packet

    char * content = (char *)malloc(sizeof(char)*MAXBUFLEN); //payload preparation in here

    if(content == NULL){
        printf("error on malloc..\n Program exit.\n");
        exit(1);
    }

    if(type==1){// if we are making data packet, prepare the data in here
        int i;
        int onfirst=1;
        int c;
        char * t;
        t=(char *)&c;
        for(i=0;i<MAXBUFLEN-HEADERSIZE;i++){
            c = fgetc(fp);
            if(c==EOF){
				*last_sig=1; //signal for last data packet prep
                break;
            }
            if(onfirst==1){
                strcpy(content,t);
                onfirst=0;
            }
            else{
                strcat(content,t);
            }
        }
        payload = strlen(content);
        *chars_taken = *chars_taken+payload;
    }

    char * header = (char *)malloc(sizeof(char)*MAXBUFLEN); //header preparation in here
    sprintf(header,"%s%s%d\n%s%d\n%s%s",magic,type_f,*seq,ackno,payload,winsz,last);



    if(type==1){
        strcat(header,content);
    }
	

	strcat(header,"\0");
    int pksize = strlen(header);
    increaSeq(seq,pksize);

	if(*last_sig==1){ //last expected data ACK has this value
		*last_ack_val = *seq;	//if we ever recv this ACK, we know that it is the last ACK of the DATA packets
	}

    return header;
}

//function determines input packet type by returning appropriate values
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
    if(strncmp(tr,"361\nRST\n",8)==0){
        //printf("Found RST\n");
        return 5;
    }
	else{
		return 0;
	}


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
void printEvent(int flow, int t, char * packet,char * packtype,char * sip, char * spt, char * rip, char * rpt){
	
	char outgo [100];

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
		int seq = get(packet,3);
		int leng = strlen(packet);
		if(t==1){//event is duplicate packet
			sprintf(outgo," S %s:%s %s:%s %s %d %d\n",sip,spt,rip,rpt,packtype,seq,leng);
			printf("%s",outgo);
			return;
		}

		if(t==2){// event is not a duplicate packet
			sprintf(outgo," s %s:%s %s:%s %s %d %d\n",sip,spt,rip,rpt,packtype,seq,leng);
			printf("%s",outgo);
			return;
		}
	}

	if( flow == 2 ){ //event is incoming packet
		int ack = get(packet,1);
		int wins = get(packet,2);
		if(t==1){//event is duplicate packet
			sprintf(outgo," R %s:%s %s:%s %s %d %d\n",sip,spt,rip,rpt,packtype,ack,wins);
			printf("%s",outgo);
			return;
		}
		if(t==2){
			sprintf(outgo," r %s:%s %s:%s %s %d %d\n",sip,spt,rip,rpt,packtype,ack,wins);
			printf("%s",outgo);
			return;
		}
	}
}


//function in charge of establishing connection with receiver. Has timeout.
int estConn(int * seq, struct Info *c, struct sockaddr_in cli_addr,int sockfd,int*winz,char*sip, char* spt, char* rip, char*rpt, int* last_sig, int * last_ack_val, int * most_rec_ack ){

    char * synpack = (char *) malloc(MAXBUFLEN * sizeof(char));
    FILE *redun1;
    int redun2;
    synpack = returnPack(seq,redun1,2,&redun2,last_sig,last_ack_val);

    struct timeval timer=(struct timeval){0};
    timer.tv_sec=TIMEOUT;
    timer.tv_usec= 0;

    int charsent;
    socklen_t cli_len = sizeof(cli_addr);

    fd_set readfds;
    /*FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
	*/


    int retval;
    int i;
	int count=0;

	char * buffer= (char*)malloc(MAXBUFLEN*sizeof(char)); //gona receive stuff into here

	

	printEvent(1,2,synpack,"SYN",sip,spt,rip,rpt);	
	
    for(i=1;i<=RETRY;i++){

		if ((charsent = sendto(sockfd, synpack, strlen(synpack), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
       		perror("sws: error in sendto()");
        	exit(1);
   		}

			
		c->syn_sent+=1;
		c->unique_bytes_sent+=strlen(synpack);
		c->total_bytes_sent+=strlen(synpack);
		c->total_packets_sent+=1;
		c->unique_packets+=1;

		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);

        retval = select(sockfd+1, &readfds, NULL, NULL, &timer);

		timer.tv_sec=1;

        if(retval==-1){
           	printf("select() error...\nExit\n");
           	exit(1);
        }
        if(retval==0){
           	printf("retrying...%d\n",i);
			printEvent(1,1,synpack,"SYN",sip,spt,rip,rpt);
	
			c->total_bytes_sent+=strlen(synpack);
			c->total_packets_sent+=1;
			c->syn_sent+=1;

            if(i==RETRY){
            	printf("Connection attempts timed out...\nExit\n");
              	exit(1);
            }
            continue;
       	}
        else{
            break;
       	}
   	}

    	int numbytes;
    	


    if ((numbytes = recvfrom(sockfd, buffer, MAXBUFLEN-1 , 0,(struct sockaddr *)&cli_addr, &cli_len)) == -1) {
        perror("sws: error on recvfrom()!");
        return -1;
    }


    int is = isA(buffer);
    
   	if(is == 2){ //success!  
		printEvent(2,2,buffer,"ACK",sip,spt,rip,rpt);
		int gotAck = get(buffer,1);
		*most_rec_ack=gotAck;
		c->ack_received+=1;
		*winz = get(buffer,2); 
		free(buffer);
		free(synpack);

		if(gotAck == *seq){ //check that ACK matches
			//printf("ACK OK!\n");
        	return 1;
		}
		else{
			//printf("ACK response does not match!\n");
			return 0;
		}
    	
   	}


}

//fills array in main containg packets to be sent or that have not yet been ACKed
void filltosend(char ** tosend, int * loc1,int * loc2, int* loc3, int* loc4,int *loc5,int *seq,FILE *fp,int *chars_taken,int *status1,int * status2, int * status3, int *status4, int * status5,int * last_sig,int* last_ack_val){	
	

	if(*loc1 == 0){
		//printf("371\n");
		char * put1 = returnPack(seq, fp, 1,chars_taken,last_sig,last_ack_val);
		//printf("\nputting in location 0:\n%s",put1);
		strcpy(tosend[0],put1);
		free(put1);
		*loc1=1;
		*status1=1;
		if(*last_sig==1){
			return;
		}
	}
	
	if(*loc2 == 0){
		//printf("381\n");
		char * put2 = returnPack(seq, fp, 1,chars_taken,last_sig,last_ack_val);
		//printf("\nputting in location 1:\n%s",put2);
		strcpy(tosend[1],put2);
		free(put2);
		*loc2=1;
		*status2=1;
		if(*last_sig==1){
			return;
		}
	}

	if(*loc3 == 0){
		//printf("391\n");
		char * put3 = returnPack(seq, fp, 1,chars_taken,last_sig,last_ack_val);
		//printf("\nputting in location 2:\n%s",put3);
		strcpy(tosend[2],put3);
		free(put3);
		*loc3=1;
		*status3=1;
		if(*last_sig==1){
			return;
		}
	}
	
	if(*loc4 == 0){
		//printf("401\n");
		char * put4 = returnPack(seq, fp, 1,chars_taken,last_sig,last_ack_val);
		//printf("\nputting in location 3:\n%s",put4);
		strcpy(tosend[3],put4);
		free(put4);
		*loc4=1;
		*status4=1;
		if(*last_sig==1){
			return;
		}
	}

	if(*loc5 == 0){
		//printf("411\n");
		char * put5 = returnPack(seq, fp, 1,chars_taken,last_sig,last_ack_val);
		//printf("\nputting in location 4:\n%s",put5);
		strcpy(tosend[4],put5);
		free(put5);
		*loc5=1;
		*status5=1;
		if(*last_sig==1){
			return;
		}
	}
}
	

//function sends packets to receiver
void sndpackets(char ** tosend,struct Info *c,int can_send,struct sockaddr_in cli_addr,int sockfd,int* status1,int* status2,int* status3,int* status4,int* status5,char * sip,char* spt,char* rip,char*rpt){

	socklen_t cli_len = sizeof(cli_addr);
	int charsent;

	if(*status1==1){
		if ((charsent = sendto(sockfd, tosend[0], strlen(tosend[0]), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
			perror("sws: error in sendto()");
			exit(1);
    	}
		printEvent(1,2,tosend[0],"DAT",sip,spt,rip,rpt);
		*status1=2;
		c->total_bytes_sent+=strlen(tosend[0]);
		c->total_packets_sent+=1;
		c->unique_packets+=1;
		c->unique_bytes_sent+=strlen(tosend[0]);
	}

	if(*status2==1){
		if ((charsent = sendto(sockfd, tosend[1], strlen(tosend[1]), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
			perror("sws: error in sendto()");
			exit(1);
    	}
		printEvent(1,2,tosend[1],"DAT",sip,spt,rip,rpt);
		*status2=2;
		c->total_bytes_sent+=strlen(tosend[1]);
		c->total_packets_sent+=1;
		c->unique_packets+=1;
		c->unique_bytes_sent+=strlen(tosend[1]);
	}

	if(*status3==1){
		if ((charsent = sendto(sockfd, tosend[2], strlen(tosend[2]), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
			perror("sws: error in sendto()");
			exit(1);
    	}
		printEvent(1,2,tosend[1],"DAT",sip,spt,rip,rpt);
		*status3=2;
		c->total_bytes_sent+=strlen(tosend[2]);
		c->total_packets_sent+=1;
		c->unique_packets+=1;
		c->unique_bytes_sent+=strlen(tosend[2]);

	}

	if(*status4==1){
		if ((charsent = sendto(sockfd, tosend[3], strlen(tosend[3]), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
			perror("sws: error in sendto()");
			exit(1);
    	}
		printEvent(1,2,tosend[3],"DAT",sip,spt,rip,rpt);
		*status4=2;
		c->total_bytes_sent+=strlen(tosend[3]);
		c->total_packets_sent+=1;
		c->unique_packets+=1;
		c->unique_bytes_sent+=strlen(tosend[3]);
	}

	if(*status5==1){
		if ((charsent = sendto(sockfd, tosend[4], strlen(tosend[4]), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
			perror("sws: error in sendto()");
			exit(1);
    	}
		printEvent(1,2,tosend[4],"DAT",sip,spt,rip,rpt);
		*status5=2;
		c->total_bytes_sent+=strlen(tosend[4]);
		c->total_packets_sent+=1;
		c->unique_packets+=1;
		c->unique_bytes_sent+=strlen(tosend[4]);
	}

}	

//function responsibles for dealing with time outs. Resends last non-ACKed packet to attempt transfer resume.
void resend(int most_r, char ** tosend,struct Info *c,int can_send,struct sockaddr_in cli_addr, \
					int sockfd,char * sip,char* spt,char* rip,char *rpt,int*loc1,int*loc2,int*loc3,int*loc4,int*loc5){
	
	int found=0;
	int curr_ack;
	int loc=0;
	char abc_ack [12];
	char cmp [12];


	int i;
	for(i=0;i<5;i++){ 
		if(i==0 && *loc1==0){ //if nothing in loc1 continue..
			continue;
		}
		if(i==1 && *loc2==0){ 
			continue;
		}
		if(i==2 && *loc3==0){
			continue;
		}
		if(i==3 && *loc4==0){ 
			continue;
		}
		if(i==4 && *loc5==0){ 
			continue;
		}
		
		if(get(tosend[i],3)<=most_r){
			break;
		}
	}

	
	int charsent;
	socklen_t cli_len = sizeof(cli_addr);


    if ((charsent = sendto(sockfd, tosend[i], strlen(tosend[i]), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
        perror("sws: error in sendto()");
        exit(1);
    }

	printEvent(1,1,tosend[i],"DAT",sip,spt,rip,rpt);
	c->total_bytes_sent+=strlen(tosend[i]);
	c->total_packets_sent+=1;	

}




//clears tosend[] of ACKed packets, and updates status variables
void clearTosend(char **tosend,int most_recent_ACK,int *loc1,int* loc2, int *loc3, int* loc4,int* loc5){

	int curr_seq;

	if(*loc1 == 1){
		curr_seq = get(tosend[0],3);
		if(curr_seq < most_recent_ACK ){
			//printf("[0] Removing %d\n",curr_seq);
			*loc1 = 0;
		}
	}

	if(*loc2 == 1){
		curr_seq = get(tosend[1],3);
		if(curr_seq < most_recent_ACK && *loc2 == 1){	
			//printf("[1] Removing %d\n",curr_seq);
			*loc2 = 0;
		}
	}

	if(*loc3 == 1){
		curr_seq = get(tosend[2],3);
		if(curr_seq < most_recent_ACK && *loc3 == 1){
			//printf("[2] Removing %d\n",curr_seq);
			*loc3 = 0;
		}
	}

	if(*loc4 == 1){
		curr_seq = get(tosend[3],3);
		if(curr_seq < most_recent_ACK && *loc4 == 1){
			//printf("[3] Removing %d\n",curr_seq);
			*loc4 = 0;
		}
	}


	if(*loc5 == 1){
		curr_seq = get(tosend[4],3);
		if(curr_seq < most_recent_ACK && *loc5 == 1){
			//printf("[4] Removing %d\n",curr_seq);
			*loc5 = 0;	
		}	
	}		
}

//function called when duplicate ACK has been detected.
//function looks at "ackno" parameter, and sends the packet containing that same sequence number
void dupAckSendData(char ** tosend, int ackno, int sockfd,struct sockaddr_in cli_addr,struct Info *c, \
							char *sip,char*spt,char*rip,char*rpt,int *loc1,int*loc2,int*loc3,int*loc4,int*loc5){
	int i;
	int compare;

	for(i=0;i<5;i++){
		if(i==0 && *loc1==0){ //if nothing in loc1 continue..
			continue;
		}
		if(i==1 && *loc2==0){ 
			continue;
		}
		if(i==2 && *loc3==0){
			continue;
		}
		if(i==3 && *loc4==0){ 
			continue;
		}
		if(i==4 && *loc5==0){ 
			continue;
		}
		
		compare = get(tosend[i],3);
		if(compare == ackno){;
			break;
		}	
	}


	socklen_t cli_len = sizeof(cli_addr);

	int charsent;
	if ((charsent = sendto(sockfd, tosend[i], strlen(tosend[i]), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
		perror("sws: error in sendto()");
		exit(1);
    }
	
	printEvent(1,1,tosend[i],"DAT",sip,spt,rip,rpt);
	c->total_bytes_sent+=strlen(tosend[i]);
	c->total_packets_sent+=1;
	
}

int finAndAck(int* seq_no, struct Info *c,struct sockaddr_in cli_addr, \
						 int sockfd,char * sip,char* spt,char*rip,char* rpt, int * last_sig, int* last_ack_val){
	char * finpack = (char *) malloc(MAXBUFLEN * sizeof(char));
    FILE *redun1;
    int redun2;
    finpack = returnPack(seq_no,redun1,4,&redun2,last_sig,last_ack_val);

    struct timeval timer= (struct timeval){0};
    timer.tv_sec=TIMEOUT;
    timer.tv_usec= 0;

    int charsent;
    socklen_t cli_len = sizeof(cli_addr);

	int count=0;
	int flag=0;

	//SENT FIN PACK

    if ((charsent = sendto(sockfd, finpack, strlen(finpack), 0,(struct sockaddr *)&cli_addr, cli_len) == -1)) {
       	perror("sws: error in sendto()");
       	exit(1);
   	}

	printEvent(1,2,finpack,"FIN",sip,spt,rip,rpt);
	c->fin_sent+=1;
	c->unique_bytes_sent+=strlen(finpack);
	c->total_bytes_sent+=strlen(finpack);
	c->unique_packets+=1;
	c->total_packets_sent+=1;
		
	
		

	//*seq_no+=strlen(finpack);
	//dont increase seq no since no packet will be sent after this one
	//also seqn_no used to compare returning packet
	

    fd_set readfds;
	int retval;
	int i;
	for(i=0;i<RETRY;i++){
    	FD_ZERO(&readfds);
    	FD_SET(sockfd, &readfds);
		
		timer.tv_sec=TIMEOUT;		
		retval = select(sockfd+1, &readfds, NULL, NULL, &timer);
		timer.tv_sec=1;

		if(retval == -1){
			printf("Error on select()..\nExit\n");
			exit(1);
		}
	
		if(retval == 0){
			continue;
		}

		else{
			break;
		}
	
	}

		
	//packet recieved
	

	int numbytes;
   	char * buffer= (char*)malloc(MAXBUFLEN*sizeof(char));
	
    if ((numbytes = recvfrom(sockfd, buffer, MAXBUFLEN-1 , 0,(struct sockaddr *)&cli_addr, &cli_len)) == -1) {
      	perror("sws: error on recvfrom()!");
       	return -1;
    }
	

	int ty = isA(buffer);
	
	free(buffer);
	free(finpack);

	if(ty != 2){
		return -1;  //did not receive right packet type, exit
	}

	int rec_ack = get(buffer,1);
		
	printEvent(2,2,buffer,"ACK",sip,spt,rip,rpt);
	c->ack_received+=1;
		

	//printf("expected ACK=%d\n",*seq_no);
	//printf("recvd ACK = %d\n",rec_ack);
	
	if(rec_ack == *seq_no){
		return 1;
	}

	return -1;
	

	
}

//_______________________________________________MAIN_____________________________________________________________

int main(int argc, char *argv[]){


	struct timeval start =(struct timeval){0};
	struct timeval end = (struct timeval){0};

	gettimeofday(&start,NULL);

    int sockfd, portno, cliport;
    socklen_t cli_len;
    char buffer[MAXBUFLEN];
    struct sockaddr_in serv_addr, cli_addr;
    int numbytes;

    //verify cmd line params..
    if (argc < 4) {
        printf( "Usage: %s <s:ip> <s:pt> <r:ip> <r:port> <file_name>\n\n", argv[0] );
        fprintf(stderr,"ERROR, not enough parameters. Graceful exit...\n");
        return -1;
    }



    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
        perror("sws: error on socket(), Graceful exit..");
        return -1;
    }

    char * file = argv[5];
    char * sip = argv[1];
    char * spt = argv[2];
    char * dip = argv[3];
    char * dpt = argv[4];

    printf("\nSending file: %s from: %s:%s  to: %s:%s\n\n",file,sip,spt,dip,dpt);

    //SERVER configuration
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = atoi(spt);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(sip);
    serv_addr.sin_port = htons(portno);

    //CLIENT configuration
    bzero((char *) & cli_addr,sizeof(cli_addr));
    cliport = atoi(dpt);
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = inet_addr(dip);
    cli_addr.sin_port = htons(cliport);



    int optval = 1;
    if ( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval) < 0 ) {
        perror("sws: error on set socket option!");
        return -1;
    }


    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        close(sockfd);
        perror("sws: error on binding! Graceful exit...");
        return -1;
    }


    struct Info stat;
    assignDef(&stat);

    srand(time(NULL));
    int seq_no = rand() % 10000;
	printf("start seq=%d\n",seq_no);
 

    int chars_taken=0;
    FILE *fp = fopen(file,"r");
    FILE *fp2= fopen(file,"r");
    if(fp==NULL || fp2==NULL){
        printf("Could not open file..\nProgram exit\n");
        exit(1);
    }


    int len=0;
    int c;
    while((c=fgetc(fp))){
        if(c==EOF) break;
        len+=1;
    }

    fclose(fp);

    int sendby = 5;
    char ** tosend = (char **) malloc(sendby*sizeof(char *));  //will contain the packets "to be sent" or "waiting on ACK"
    int q;
    for(q=0;q<sendby;q++){
        tosend[q] = (char *) malloc(MAXBUFLEN*sizeof(char));
    }
	
	int loc1=0;
	int loc2=0;
	int loc3=0;		//boolean variable keeping track of FILL of tosend[locX]
	int loc4=0;		//there are 5 because sendby == 5
	int loc5=0;

	int status1;
	int status2;
	int status3;	//values keep track of status of packet in tosend[statusX]
	int status4;	//2 = waiting on ACK, 1 = not sent yet
	int status5;
	

	struct timeval timeout = (struct timeval){0};
    timeout.tv_sec=TIMEOUT;
    timeout.tv_usec= 0;

	fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(sockfd, &readfds);
	
	int syn=1;
	int can_send;
	int most_recent_ACK;
	int winsz=0;
	int maxbuf = MAXBUFLEN;
	float num;
	int retval;
	int retried =0;
	int pkty;


	char rcv [MAXBUFLEN];

	int last_pk_prep=0;
	int last_ack=0;
	int last_ack_val=0;


	//struct timeval te;
	//gettimeofday(&te,NULL);
	//printf("%ld.%06ld\n",te.tv_sec,te.tv_usec);

	int loop=1;

    while(last_ack==0){ //while last_ack no rcvd
		
		if( syn == 1 ){
			if(estConn(&seq_no, &stat, cli_addr, sockfd, &winsz,sip,spt,dip,dpt,&last_pk_prep,&last_ack_val,&most_recent_ACK)==0){
				printf("Establishing connection..\n");
        		printf("Could not establist connection..\nProgram exit..\n");
         		exit(1);
			}
			syn=0;
		}

	
		//sleep(1);

		num = winsz/maxbuf;
		can_send = (int) floor(num); // how many packets the receiver can buffer

	
		//fill tosend[] and update status variables via pointer	

		if(last_pk_prep!=1){	
			filltosend(tosend,&loc1,&loc2,&loc3,&loc4,&loc5,&seq_no,fp2,&chars_taken, \
								&status1,&status2,&status3,&status4,&status5,&last_pk_prep,&last_ack_val);
		}
		/*int f;
		printf("in tosend\n");
		for(f=0;f<5;f++){
			printf("[%d] seq = %d\n",f,get(tosend[f],3));
		}
		printf("--\n");*/

		if(can_send>=1){
			sndpackets(tosend,&stat,can_send,cli_addr,sockfd,&status1,&status2,&status3,&status4,&status5,sip,spt,dip,dpt);
		}


		FD_ZERO(&readfds);
   		FD_SET(sockfd, &readfds);
		timeout.tv_sec=1;
	
		retval = select(sockfd+1, &readfds, NULL, NULL, &timeout);	
	
		if(retval==-1){
            printf("select() error...\nExit\n");
            exit(1);
        }
        if(retval==0){ // if select() has timed out
			retried+=1;
			//printf("retry\n");
			if(retried == 5){
				printf("Number of retries timed out..\nExit\n");
				exit(1);
			}
			else {
				if(can_send>=1){ // if select() has timed out, resend last packet that was not ack
					//printf("had to resend\n");
					resend(most_recent_ACK,tosend,&stat,can_send,cli_addr,sockfd,sip,spt,dip,dpt,&loc1,&loc2,&loc3,&loc4,&loc5);
					//printf("resent!\n");
				}
					continue;
			}			 
          
        }
		
		retried = 0;

		//select() has noticed content at socket! -> proceed

		
		if ((numbytes = recvfrom(sockfd, rcv, MAXBUFLEN-1 , 0,(struct sockaddr *)&cli_addr, &cli_len)) == -1) {
        	perror("sws: error on recvfrom()!");
        	return -1;
    	}
		

		pkty = isA(rcv);
		if(pkty==2){	//received ACK packet

			//printf("last ack val =%d, is last pk prep?%d\n",last_ack_val,last_pk_prep);
			if(get(rcv,1) <= most_recent_ACK){ //recvd dupACK
				//printf("DUP ACK\n");
				printEvent(2,1,rcv,"ACK",sip,spt,dip,dpt);
				stat.ack_received+=1;
				dupAckSendData(tosend,most_recent_ACK,sockfd,cli_addr,&stat,sip,spt,dip,dpt,&loc1,&loc2,&loc3,&loc4,&loc5);
				//dupAckSendData(tosend,get(rcv,1),sockfd,cli_addr,&stat,sip,spt,dip,dpt);
				continue;
			}

			else{   // ACK is not dupACK
				
				stat.ack_received+=1;
				printEvent(2,2,rcv,"ACK",sip,spt,dip,dpt);

				//check if it is the last ACK
				if(last_pk_prep == 1 && last_ack_val == get(rcv,1)){
					break;
				}

				else{ //ACK is in sequence, proceed..
					most_recent_ACK = get(rcv,1);
					winsz = get(rcv,2);	
					//printf("Clear to send[]\n");

					/*int v;
					for(v=0;v<5;v++){
						printf("[%d] seq = %d\n",v,get(tosend[v],3));
					}*/
					
					clearTosend(tosend,most_recent_ACK,&loc1, &loc2, &loc3, &loc4, &loc5);
					continue;
				}
			}
			

		}

		if(pkty==5){  //received RST packet
			
			stat.rst_received+=1;
			syn=1;
		}
	
		else{		//received unknow packet... dont do anything
			continue;
		}
		
       
		

    }///while

	finAndAck(&seq_no, &stat, cli_addr, sockfd,sip,spt,dip,dpt,&last_pk_prep,&last_ack_val);


	printf("\n\n");
	printStats(&stat);

	
	//end program timer

    int h;
    for(h=0;h<sendby;h++){
        free(tosend[h]);
    }
    free(tosend);


	gettimeofday(&end,NULL);

	double et = end.tv_usec - start.tv_usec;
	et/=1000000;
	et= et + (end.tv_sec - start.tv_sec);

	printf("\nExecution time = %fs\n",et); 


}
