#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <libgen.h>

#define MAX_SIZE 300
#define IP_ADDRESS "127.0.0.1"
int sndsock, rcvsock;
int clen;
int IP_condition = 0, MAC_condition = 0, table_count = -1, table_num; // IP, MAC의 상태와 Cache테이블 카운터와 테이블 체크를 위한 변수

// sender
int ip_saddr[4] = {203, 255, 43, 21}; // 고정 IP주소
int input_IP[4]; // 입력 받은 IP를 저장할 변수
char mac_saddr[20] = "0A:10:9C:31:79:6F"; // 고정 MAC주소

//destination
int ip_daddr[4] = {192, 168, 43, 13};// 고정 IP주소
int rec_IP[4]; // 전달 받은 IP를 저장할 변수
char mac_daddr[20] = "0A:77:81:9A:52:36";// 고정 MAC주소
char rec_MAC[20]; // 전달 받은 MAC을 저장할 변수

char output[MAX_SIZE]; // 전달 받은 메시지를 저장할 변수
int type = 1; // type을 저장할 변수
char mode = 'n'; // sender와 Cache_table thread를 구별할 변수
int re_time = 60; // renewal 타임 변수
char thread_type = 's'; // thread 타입을 지정할 변수
clock_t past; // clock을 이용해 과거 시간을 저장할 변수

struct sockaddr_in s_addr,r_addr;
int is_server = 0;

struct L1{
	int own_IP[4];
	int rec_IP[4];
	int length;
	char data[MAX_SIZE];
}; // 구조체 L2

struct L2{
	char own_MAC[20];
	char rec_MAC[20];
	int length;
	int type;
	char data[MAX_SIZE];
}; // 구조체 L1

struct ARP_Cache_Table{
	int IP[4];
	char MAC[20];
} ARP_Cache[5]; // ARP_Cache_Table 구조체

void L1_send(char *input, int length);
void L2_send(char *input, int length);
char *L1_receive(int *);
char *L2_receive(int *);

void data_send(char *data, int length);
char *data_receive(int *);

void *table_thread(void *); // Cache_table용 thread
int check_table(char *); // Cache_table에 저장된 값들을 검사할 함수

void *do_thread(void *); // receive용 thread
void init_socket();
void check_is_server(char *const *argv);

int main (int argc, char *argv[]) {
	char input[MAX_SIZE]; // 메시지를 입력 받을 input 배열
	int select; // 메뉴를 선택할 변수
	char dest_ip[50]; // ip값을 저장하기 위한 변수
	int length; 
	pthread_t tid; 

	check_is_server(argv);
    init_socket();
	pthread_create(&tid, NULL, do_thread, (void *)0); // receive용 thread 생성

    if(is_server == 0) { 
	    pthread_create(&tid, NULL, table_thread, (void *)0); // Cache_table용 thread 생성
        thread_type = 's';
        printf("My IP : %d.%d.%d.%d\n", ip_saddr[0], ip_saddr[1], ip_saddr[2], ip_saddr[3]);
        while (1) {
            if(thread_type == 's' && type == 1 && mode == 'n') {
                printf("\n----------------------------\n");
                printf("- 1. Send Data             -\n");
                printf("- 2. View ARP Cache Table  -\n");
                printf("- 3. Exit                  -\n");
                printf("----------------------------\n");
                printf("- Input : ");
                scanf("%d", &select);

                switch(select) {
                case 1: // send data와 ip를 입력받는다
                    memset(dest_ip, 0x00, 50);
                    printf("Send Text : ");
                    scanf("%s", input);
                    printf("Destination IP : ");
                    scanf("%s", dest_ip);
                    if(check_table(dest_ip) == 1) {
                        memcpy(dest_ip, "Request", strlen("Request"));
                        L1_send(dest_ip, strlen(dest_ip));
                        thread_type = 'r';
                    } // Cache_table에 IP의 값이 없을 경우 MAC을 호출하기 위해
                    else{
                        type = 2;
                    } // Cache_table에 IP의 값이 있을 경우 메시지를 전송하기 위해
                    break;
                case 2: // Cache_table을 본다
                    mode = 'v';
                    break; 
                case 3: // 종료
                    memcpy(input, "exit", strlen("exit"));
                    break;
                default: // 1~3 이외의 값을 입력할 경우
                    printf("Please Write number in menu\n");
                }		
                if(!strcmp(input, "exit")) break;
            }
            else if(thread_type == 's' && type == 2 && mode == 'n') {
                L1_send(input, strlen(input));
                type = 1;
            } // Cache_table에 입력한 IP의 값이 있을경우 메시지 전송
        }
        close(sndsock);
    }
    else {
        thread_type = 'r';
        printf("My IP : %d.%d.%d.%d\n", ip_daddr[0], ip_daddr[1], ip_daddr[2], ip_daddr[3]);

        while (1) {
            if(thread_type == 'r') {
                memset(output, 0x00, MAX_SIZE);
                strcpy(output, L1_receive(&length));
                output[length] = '\0';

                if((IP_condition == 0) && (type == 1)) {
                    if(type == 1) {
                        type = 2;
                    }
                    if(output != '\0') {
                        thread_type = 's';
                    }
                } // 나의 MAC주소를 요청할 경우 MAC주소를 넘겨주기 위해
                else if((IP_condition == 0) && (MAC_condition == 0) && (type == 2)) {
                    printf("Received Length %d\n", length);
                    printf("Received Message : %s\n\n", output);
                } // 메시지를 전송 받을 경우 메시지 출력
                else{
                    thread_type = 'e';
                } // 전송 받은 데이터가 나의 것이 아닌 경우
                if(!strcmp(output, "exit")) break;
            }
        }
        close(rcvsock);
    }
}

void L1_send(char *input, int length) {
	struct L1 layer; 
	char temp[350]; 
	int size = 0; 

    if(is_server == 0) {
        memcpy(layer.own_IP, &ip_saddr, sizeof(ip_saddr)); // 고정 IP의 값을 저장

        if(type == 1) {
            memcpy(layer.rec_IP, &input_IP, sizeof(input_IP));
            printf("ARP_Request\n");
        } // Cache_Table에 입력받은 IP의 MAC주소가 존재하지 않을 경우 입력받은 IP값 저장
        else if(type == 2) {
            memcpy(layer.rec_IP, &ARP_Cache[table_num].IP, sizeof(layer.rec_IP));
        } // Cache_Table에 입력받은 IP의 값이 존재할경우 Cache_Table의 값을 가져온다.

        layer.length = length; 
        memset(layer.data, 0x00, MAX_SIZE); 
        memcpy(layer.data, (void *)input, length); 

        size = sizeof(struct L1) - sizeof(layer.data) + length; 

        memset(temp, 0x00, 350); 
        memcpy(temp, (void *)&layer, size); 

        L2_send(temp, size); 
    }
    else {
        memcpy(layer.rec_IP, &ip_daddr, sizeof(ip_daddr)); // 나의 IP주소 저장
        memcpy(layer.own_IP, &rec_IP, sizeof(rec_IP)); // 전송할 곳의 IP주소 저장

        layer.length = length; 
        memset(layer.data, 0x00, MAX_SIZE); 
        memcpy(layer.data, (void *)input, length); 

        size = sizeof(struct L1) - sizeof(layer.data) + length; 

        memset(temp, 0x00, 350); 
        memcpy(temp, (void *)&layer, size); 

        L2_send(temp, size); 
    }
}

void L2_send(char *input, int length) {
	struct L2 layer; 
	char temp[350]; 
	int size = 0; 

	layer.type = type; 
	layer.length = length; 

    if(is_server == 0) {
        memcpy(layer.own_MAC, mac_saddr, sizeof(mac_saddr)); // 나의 MAC주소 저장

        if(type == 2) {
            memcpy(layer.rec_MAC, ARP_Cache[table_num].MAC, sizeof(ARP_Cache[table_num].MAC)); // 전송할 곳의 MAC주소 저장
        } // 입력 받은 IP의 MAC주소가 Cache_Table에 존재할 경우
        else {
            memset(layer.rec_MAC, 0x00, sizeof(layer.rec_MAC));
        } // 입력 받은 IP의 MAC 주소를 모를 경우

        memset(layer.data, 0x00, MAX_SIZE); 
        memcpy(layer.data, input, length);

        size = sizeof(struct L2) - sizeof(layer.data) + length; // input 값을 저장한 구조체 L1의 사이즈 계산

        memset(temp, 0x00, 350); 
        memcpy(temp, (void *)&layer, size); 

        data_send(temp, size);
    }
    else {
        memcpy(layer.rec_MAC, mac_daddr, sizeof(mac_daddr)); // 나의 MAC주소 저장
        memcpy(layer.own_MAC, rec_MAC, sizeof(rec_MAC)); // 전송할 곳의 MAC주소 저장

        memset(layer.data, 0x00, MAX_SIZE); 
        memcpy(layer.data, input, length); 

        size = sizeof(struct L2) - sizeof(layer.data) + length; 

        memset(temp, 0x00, 350); 
        memcpy(temp, (void *)&layer, size); 

        data_send(temp, size);
    }
}

char *L1_receive(int *length) {
	struct L1 *layer; 
	int i;

	layer = (struct L1*)L2_receive(length); 

	for(i = 0; i < 4; i++) {
		if(ip_saddr[i] == layer->own_IP[i]) {
			IP_condition = 0;
		}
		else {
			IP_condition = 1;
			break;
		}
	} // 전송받은 data의 IP 검사 

    if(is_server == 0) {
        if(IP_condition == 0 && MAC_condition == 0) {
            memcpy(ARP_Cache[table_count].IP, layer->rec_IP, sizeof(layer->rec_IP));
            re_time = 60;
            printf("ARP_Cache Table is Set!!\n");
        } // 받아온 IP주소를 Cache_Table에 저장
        else {
            memset(ARP_Cache[table_count].MAC, 0x00, sizeof(ARP_Cache[table_count].MAC));
            table_count--;
        } // 전송 받은 data의 값이 나의 것이 아닐경우 MAC값 초기화
    }
    else {
        if(IP_condition == 0) {
            memcpy(rec_IP, layer->own_IP, sizeof(rec_IP));
        } // IP의 값이 이상이 없을 경우 상대방의 IP저장
    }

    *length = *length - sizeof(layer->own_IP) - sizeof(layer->rec_IP) - sizeof(layer->length); 
    return (char *)layer->data;
}

char *L2_receive(int *length) {
	struct L2 *layer; 

	layer = (struct L2*)data_receive(length); 
    type = layer->type;

	if(is_server == 0) {
        if(strcmp(mac_saddr, layer->own_MAC) == 0) {
            MAC_condition = 0;
        } // 전송 받은 data의 MAC주소값을 검사한다.
        else {
            MAC_condition = 1;
        }

        if(MAC_condition == 0 && layer->type != 3) {
            table_count++;
            memcpy(ARP_Cache[table_count].MAC, layer->rec_MAC, sizeof(layer->rec_MAC));
        } // MAC값이 이상 없을 경우 Cache_Table에 MAC값 저장
    }
    else {
        if(type == 1) {
            memcpy(rec_MAC, layer->own_MAC, sizeof(layer->own_MAC));
        } // MAC 응답을 위한 상대방의 MAC저장
        else if(type == 2) {
            if(strcmp(mac_daddr, layer->rec_MAC) == 0) {
                MAC_condition = 0;
            }
            else {
                MAC_condition = 1;
            }
        } // 메시지를 전송 받을 경우 나의 것인지 MAC 검사
    }

	*length = *length - sizeof(layer->own_MAC) - sizeof(layer->rec_MAC) - sizeof(layer->length) - sizeof(layer->type);
	return (char *)layer->data;
}

void data_send(char *data, int length) {
	sendto(sndsock, data, length, 0, (struct sockaddr *)&s_addr, sizeof(s_addr));
    printf("####################################################\n");
}

char *data_receive(int *length) {
	static char data[MAX_SIZE];
    *length = recvfrom(rcvsock, data, MAX_SIZE, 0, (struct sockaddr *)&r_addr, &clen);
    return data;
}

void *table_thread(void *arg) {
	int i, back, p_time;

	past = clock();// 현재의 clock값을 저장
	re_time = 60;

	while(1) {
		if((clock() - past) / CLOCKS_PER_SEC) {
			re_time--;
			past = clock();
		} // 1초마다 renewal time의 값을 줄인다.

		if(re_time == 0) {
			memset(ARP_Cache, 0x00, sizeof(struct ARP_Cache_Table));
			table_count = -1;
			re_time = 10;
		} // renewal의 값이 0이 될 경우 ARP_Cache_Table을 초기화한다.

		if(mode == 'v') { // ARP_Cache_Table 출력
			for(i = 0; i <= table_count; i++) {
				printf("ARP_Cache Table number : %d\n", i);
				printf("Destination_IP : %d.%d.%d.%d\n", ARP_Cache[i].IP[0], ARP_Cache[i].IP[1], ARP_Cache[i].IP[2], ARP_Cache[i].IP[3]);
				printf("Destination_MAC : %s\n\n", ARP_Cache[i].MAC);
			}

			if(table_count <= -1) {
				printf("ARP_Cache Table is empty\n");
				mode = 'n';
			}
			else {
				mode = 't';
			}

			back = re_time;
			p_time = re_time + 1;
		}

		if(mode == 't' && table_count > -1) { 
			if(re_time != p_time) {
				printf("\rRenewal Time : %2d", re_time);
				fflush(stdout);

				p_time = re_time;
			} // renewal까지 남은 시간을 출력

			if((back - re_time) >= 5) {
				mode = 'n';
			} // 5초간 renewal까지 남은 시간을 보여주고 메뉴로 돌아간다.
		}
		else if(mode == 't' && table_count == -1) {
			printf("\nRenewal Cache_table\n\n");
			mode = 'n';
		} // Cache_Table을 보고 있을 때 renewal time이 0이되면 출력
	}
}

int check_table(char *ip) {
	int i, j, c;
	char token[10];
	int result = 1;

	memset(token, 0x00, 10); // token 초기화

	for(i = 0, j = 0; i < 4; i++) {
		for(c = 0; j < 50; j++) {
			if('0' <= ip[j] && ip[j] <= '9') {
				token[c] = ip[j];
				c++;
			} 
			else {
				j++;
				break;
			} 
		}
		input_IP[i] = atoi(token); 
		memset(token, 0x00, 10); 
	} // 입력받은 IP의 값을 token을 이용해 분리하여 input_IP에 저장한다.

	for(i = 0; i <= table_count; i++) {
		for(j = 0, c = 0; j < 4; j++) {
			if(ARP_Cache[i].IP[j] == input_IP[j]) {
				c++;
			}
		}		
		if(c == 4) {
			table_num = i;
			result = 0;
			break;
		}
		else {
			result = 1;
		}
	} // 입력받은 IP의 값이 Cache_Table에 존재하는지 검사한다.

	return result;
}

void *do_thread(void *arg) {
	int length; // 데이터의 사이즈를 저장할 변수

    if(is_server == 0) {
        while (1) {
            if(thread_type == 'r') {
                memset(output, 0x00, MAX_SIZE);
                strcpy(output, L1_receive(&length));

                if(type == 2) {
                    printf("ARP_Reply\n");
                } // MAC 주소를 받아왔을 경우
                else if(type == 3 ) {
                    printf("Nobody have input IP\n");
                    type = 1;
                } // 입력 받은 IP를 가지고 있는 곳이 없을경우

                output[length] = '\0';

                if(output != '\0') {
                    thread_type = 's';
                } // sender를 실행
                if(!strcmp(output, "exit")) break;
            }
        }
        close(rcvsock);
    }
    else {
        while(1) {
            if(thread_type == 's') {
                L1_send(output, strlen(output));

                thread_type = 'r';
            } // MAC주소 전송
            else if(thread_type == 'e') {
                memcpy(output, "error", sizeof("error"));
                type = 3;
                L1_send(output, strlen(output));

                thread_type = 'r';
            } // error전송
            if(!strcmp(output, "exit")) break; 
        }
        close(sndsock);
    }
}

void check_is_server(char *const *argv) {
    char *progname = basename(argv[0]);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pgrep -x %s | wc -l", progname);
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }
    int process_count = 0;
    char line[256];
    if (fgets(line, sizeof(line), fp) != NULL) {
        process_count = atoi(line);
    }
    pclose(fp);
    is_server = process_count == 1;
}
void init_socket() {
    int send_port;
    int receive_port; 	
    if (is_server == 0) {
        printf("Session 2 Start\n");
        send_port = 8811;
        receive_port = 8810;
    }
    else {
        printf("Session 1 Start\n");
        send_port = 8810;
        receive_port = 8811;
    }
    if ((sndsock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket error : ");
        exit(1);
    }
    s_addr.sin_family = AF_INET;
    s_addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    s_addr.sin_port = htons(send_port);
    if (connect(sndsock, (struct sockaddr *)&s_addr, sizeof(s_addr)) < 0) {
        perror("connect error : ");
        exit(1);
    }
    if ((rcvsock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket error : ");
        exit(1);
    }
    clen = sizeof(r_addr);
    memset(&r_addr, 0, sizeof(r_addr));
    r_addr.sin_family = AF_INET;
    r_addr.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    r_addr.sin_port = htons(receive_port);
    if (bind(rcvsock, (struct sockaddr *)&r_addr, sizeof(r_addr)) < 0) {
        perror("bind error : ");
        exit(1);
    }
    int optvalue = 1;
    int optlen = sizeof(optvalue);
    setsockopt(sndsock, SOL_SOCKET, SO_REUSEADDR, &optvalue, optlen);
    setsockopt(rcvsock, SOL_SOCKET, SO_REUSEADDR, &optvalue, optlen);
    printf("####################################################\n");
}