#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  
  // Ethernet 헤더 정보 출력
  printf("Ethernet Header\n");
  printf("   Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
         eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], 
         eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  printf("   Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
         eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], 
         eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800은 IP 타입
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    
    // IP 헤더 정보 출력
    printf("IP Header\n");
    printf("   Version: %d\n", ip->iph_ver);
    printf("   Header Length: %d bytes\n", ip->iph_ihl * 4);
    printf("   Type of Service: %d\n", ip->iph_tos);
    printf("   Total Length: %d bytes\n", ntohs(ip->iph_len));
    printf("   Identification: %d\n", ntohs(ip->iph_ident));
    printf("   TTL: %d\n", ip->iph_ttl);
    printf("   Protocol: %d\n", ip->iph_protocol);
    printf("   Checksum: 0x%04x\n", ntohs(ip->iph_chksum));
    printf("   Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    // TCP 패킷 분석
    if (ip->iph_protocol == IPPROTO_TCP) {
        int ip_header_len = ip->iph_ihl * 4;
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
        
        // TCP 헤더 정보 출력
        printf("TCP Header\n");
        printf("   Source Port: %d\n", ntohs(tcp->tcp_sport));
        printf("   Destination Port: %d\n", ntohs(tcp->tcp_dport));
        printf("   Sequence Number: %u\n", ntohl(tcp->tcp_seq));
        printf("   Acknowledgment Number: %u\n", ntohl(tcp->tcp_ack));
        printf("   Header Length: %d bytes\n", TH_OFF(tcp) * 4);
        printf("   Flags: 0x%02x\n", tcp->tcp_flags);
        if (tcp->tcp_flags & TH_FIN) printf("      FIN: Yes\n");
        if (tcp->tcp_flags & TH_SYN) printf("      SYN: Yes\n");
        if (tcp->tcp_flags & TH_RST) printf("      RST: Yes\n");
        if (tcp->tcp_flags & TH_PUSH) printf("      PUSH: Yes\n");
        if (tcp->tcp_flags & TH_ACK) printf("      ACK: Yes\n");
        if (tcp->tcp_flags & TH_URG) printf("      URG: Yes\n");
        printf("   Window Size: %d\n", ntohs(tcp->tcp_win));
        printf("   Checksum: 0x%04x\n", ntohs(tcp->tcp_sum));
        printf("   Urgent Pointer: %d\n", ntohs(tcp->tcp_urp));
        
        // 메시지 출력
        int tcp_header_len = TH_OFF(tcp) * 4;
        int ip_total_len = ntohs(ip->iph_len);
        int payload_length = ip_total_len - ip_header_len - tcp_header_len;
        
        if (payload_length > 0) {
            printf("Payload Data (%d bytes):\n", payload_length);
            const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            
            // 16진수로 출력 (디버깅용)
            printf("   ");
            for (int i = 0; i < payload_length; i++) {
                printf("%02x ", payload[i]);
                if ((i + 1) % 16 == 0) printf("\n   ");
            }
            printf("\n");
            
            // ASCII로 출력 (텍스트 데이터인 경우)
            printf("   ASCII: ");
            for (int i = 0; i < payload_length; i++) {
                if (payload[i] >= 32 && payload[i] < 127)
                    printf("%c", payload[i]);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
  }
  printf("----------------------------------------------------\n\n");
}


int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";  // TCP 패킷만 캡처하도록 변경
  bpf_u_int32 net;

  // 네트워크 인터페이스 획득 (개선된 방식)
  pcap_if_t *alldevs;
  char *dev = NULL;

  // 모든 네트워크 장치 찾기
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
      fprintf(stderr, "장치를 찾을 수 없음: %s\n", errbuf);
      return 1;
  }

  // 첫 번째 장치 사용
  if (alldevs != NULL) {
      dev = alldevs->name;
      printf("사용할 장치: %s\n", dev);
  } else {
      fprintf(stderr, "사용 가능한 네트워크 장치가 없습니다\n");
      return 1;
  }

  // PCAP 세션 시작
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
      printf("pcap_open_live() 실패: %s\n", errbuf);
      pcap_freealldevs(alldevs); // 자원 해제
      return 1;
  }

  // 필터 컴파일 및 적용
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      printf("필터 컴파일 실패: %s\n", pcap_geterr(handle));
      pcap_freealldevs(alldevs); // 자원 해제
      return 1;
  }
  
  if (pcap_setfilter(handle, &fp) == -1) {
      printf("필터 설정 실패: %s\n", pcap_geterr(handle));
      pcap_freealldevs(alldevs); // 자원 해제
      return 1;
  }

  printf("TCP 패킷 캡처 시작...\n");
  
  // 패킷 캡처 루프
  pcap_loop(handle, -1, got_packet, NULL);

  // 프로그램 종료 전에 자원 해제
  pcap_freealldevs(alldevs); // 네트워크 장치 목록 해제
  pcap_close(handle);        // PCAP 세션 종료

  return 0;
}
