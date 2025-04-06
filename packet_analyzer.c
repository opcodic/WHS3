#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "myheader.h"

void print_payload(const u_char *payload, int len) {
    for(int i=0; i<len; i++) {
        printf("%02x ", payload[i]);
        if((i+1)%16 == 0) printf("\n");
    }
    printf("\n");
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    
    printf("\n[Ethernet Header]\n");
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    if(ntohs(eth->h_proto) != ETH_P_IP) return;

    struct iphdr *ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
    if(ip->protocol != IPPROTO_TCP) return;

    printf("\n[IP Header]\n");
    printf("Src IP: %s\n", inet_ntoa(*(struct in_addr*)&ip->saddr));
    printf("Dst IP: %s\n", inet_ntoa(*(struct in_addr*)&ip->daddr));

    struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip->ihl*4);
    printf("\n[TCP Header]\n");
    printf("Src Port: %d\n", ntohs(tcp->source));
    printf("Dst Port: %d\n", ntohs(tcp->dest));

    int eth_len = sizeof(struct ethhdr);
    int ip_len = ip->ihl*4;
    int tcp_len = tcp->doff*4;

    // 헤더 길이 검증
    if(ip_len < 20) ip_len = 20;
    if(tcp_len < 20) tcp_len = 20;

    int total_headers = eth_len + ip_len + tcp_len;
    int payload_len = pkthdr->len - total_headers;

    // 디버그 정보
    printf("[DEBUG] Eth:%d IP:%d(%d) TCP:%d(%d) Total:%d Payload:%d\n",
           eth_len, ip_len, ip->ihl, tcp_len, tcp->doff, 
           total_headers, payload_len);

    if(payload_len < 0) {
        printf("[WARN] Invalid payload length! Adjusting to 0\n");
        payload_len = 0;
    }

    printf("\n[Payload (%d bytes)]\n", payload_len);
    const u_char *payload = packet + total_headers;
    print_payload(payload, payload_len > 50 ? 50 : payload_len);
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], 65536, 1, 1000, errbuf);
    
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    printf("Starting packet capture on %s...\n", argv[1]);
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
