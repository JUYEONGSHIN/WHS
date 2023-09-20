#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char ether_dhost[6]; /* destination host address */
    u_char ether_shost[6]; /* source host address */
    u_short ether_type;    /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    u_char iph_ihl:4,      // IP header length
          iph_ver:4;       // IP version
    u_char iph_tos;        // Type of service
    u_short iph_len;       // IP Packet length (data + header)
    u_short iph_ident;     // Identification
    u_short iph_flag_off;  // Flags and Fragment offset
    u_char iph_ttl;        // Time to Live
    u_char iph_protocol;   // Protocol type
    u_short iph_chksum;    // IP datagram checksum
    struct in_addr iph_sourceip; // Source IP address
    struct in_addr iph_destip;   // Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcph_srcport;  // Source port
    u_short tcph_destport; // Destination port
    u_int tcph_seqnum;     // Sequence number
    u_int tcph_acknum;     // Acknowledgment number
    u_char tcph_offx2;     // Data offset and Reserved
    u_char tcph_flags;     // TCP Flags
    u_short tcph_win;      // Window size
    u_short tcph_chksum;   // TCP Checksum
    u_short tcph_urgptr;   // Urgent pointer
};

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == ETHERTYPE_IP) { // IP 프로토콜 확인
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        if (ip->iph_protocol == IPPROTO_TCP) { // TCP 프로토콜 확인
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl << 2));

            // 이더넷 헤더
            printf("이더넷 헤더:\n");
            printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            // IP 헤더
            printf("IP 헤더:\n");
            printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
            printf("IP Header Length: %u bytes\n", (unsigned int)(ip->iph_ihl << 2));

            // TCP 헤더
            printf("TCP 헤더:\n");
            printf("Source Port: %u\n", ntohs(tcp->tcph_srcport));
            printf("Destination Port: %u\n", ntohs(tcp->tcph_destport));

            // 데이터 길이 계산
            unsigned int ip_header_len = (ip->iph_ihl) << 2;
            unsigned int tcp_header_len = (tcp->tcph_offx2 >> 4) << 2;
            unsigned int data_len = pkthdr->len - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);
            printf("IP Header Length: %u bytes\n", ip_header_len);
            printf("TCP Header Length: %u bytes\n", tcp_header_len);
            
            // 메시지 출력 (예시로 처음 16바이트만 출력)
            printf("메시지:\n");
            for (int i = 0; i < data_len && i < 16; i++) {
                printf("%02X ", packet[sizeof(struct ethheader) + ip_header_len + tcp_header_len + i]);
            }
            printf("\n");
            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 패킷 캡처 장치 열기 (여기서는 ens33을 사용)
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "패킷 캡처 장치를 열 수 없음: %s\n", errbuf);
        return 1;
    }

    // 패킷 캡처 루프 시작
    pcap_loop(handle, 0, packet_handler, NULL);

    // 핸들 닫기
    pcap_close(handle);

    return 0;
}
