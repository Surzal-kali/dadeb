#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdint>
#include <cstdlib>

uint16_t checksum(const uint16_t* data, size_t length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1) {
        uint16_t tmp = 0;
        *(uint8_t*)&tmp = *(uint8_t*)data;
        sum += tmp;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

extern "C" {
    /**
     * raw_syn_scan
     * Returns 1 if port is open, 0 if closed/filtered, -1 on error.
     */
    int raw_syn_scan(const char* source_ip,
                 const char* target_ip,
                 uint16_t port,
                 int timeout_ms) {
        int s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (s < 0) return -1;

        // Tell the kernel not to put its own TCP header on this packet
        int one = 1;
        if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            close(s);
            return -1;
        }

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        sin.sin_addr.s_addr = inet_addr(target_ip);

        // Build the packet buffer (IP Header + TCP Header)
        char packet[4096];
        memset(packet, 0, 4096);

        struct iphdr *iph = (struct iphdr *) packet;
        struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(struct iphdr));

        // IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htons(54321); 
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0; 
        iph->saddr = inet_addr(source_ip); // Note: This should be dynamic in a full impl
        iph->daddr = sin.sin_addr.s_addr;

        // TCP Header
        tcph->source = htons(12345); 
        tcph->dest = htons(port);
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->syn = 1; // The "SYN" in SYN scan
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        // Pseudo header for checksum
        struct pseudo_header {
            uint32_t saddr;
            uint32_t daddr;
            uint8_t placeholder;
            uint8_t protocol;
            uint16_t tcp_len;
        } psh;

        psh.saddr = iph->saddr;
        psh.daddr = iph->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_len = htons(sizeof(tcphdr));

        uint8_t pseudo[sizeof(pseudo_header) + sizeof(tcphdr)]{};
        memcpy(pseudo, &psh, sizeof(psh));
        memcpy(pseudo + sizeof(psh), tcph, sizeof(tcphdr));
        tcph->check = checksum(reinterpret_cast<uint16_t*>(pseudo), sizeof(pseudo));

        // Send it
        if (sendto(s, packet, ntohs(iph->tot_len), 0,
                   reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) < 0) {
            close(s);
            return -1;
        }

        // Set timeout for the response
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Listen for the response
        unsigned char buffer[65536];
        struct sockaddr_in saddr;
        socklen_t saddr_size = sizeof(saddr);
        
        int data_size = recvfrom(s, buffer, 65536, 0, (struct sockaddr *) &saddr, &saddr_size);
        if (data_size < 0) {
            close(s);
            return 0; // Filtered/Closed
        }

        struct tcphdr *res_tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));
        
        close(s);

        // If SYN and ACK are both set, the port is open
        if (res_tcph->syn && res_tcph->ack) {
            return 1;
        }

        return 0;
    }
}
