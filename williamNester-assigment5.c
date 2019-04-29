/* Compile with: gcc williamNester-assigment4.c -lpcap  -ldumbnet */
#include <stdio.h>
#include <pcap.h>
#include <dumbnet.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define PORT_LENGTH 7

//packet number and flag
int packet_counter = 0;
int firstime = 1;
int bsend = 0;
int receivedResponse = 0;
int notsent = 1;

// address ASCII arrays
char eth_victim[ETH_ADDR_BITS], eth_attacker[ETH_ADDR_BITS], eth_new_victim[ETH_ADDR_BITS];
char ip_victim[IP_ADDR_BITS], ip_new_victim[IP_ADDR_BITS], ip_attacker[IP_ADDR_BITS];
char my_ip[IP_ADDR_BITS], my_eth[IP_ADDR_BITS];
char eth_source[ETH_ADDR_BITS], eth_destination[ETH_ADDR_BITS];
char eth_new_source[ETH_ADDR_BITS], eth_new_destination[ETH_ADDR_BITS];
char ip_source[ETH_ADDR_BITS], ip_destination[ETH_ADDR_BITS];
char ip_new_source[ETH_ADDR_BITS], ip_new_destination[ETH_ADDR_BITS];
char victim_port[PORT_LENGTH] = {0};
char attacker_port[PORT_LENGTH] = {0};
char new_victim_port[PORT_LENGTH] = {0};
char my_port[PORT_LENGTH] = {0};

// address struct arrays
struct addr struct_my_eth, struct_eth_victim, struct_eth_new_victim, struct_eth_attacker;
struct addr struct_my_ip, struct_ip_victim, struct_ip_new_victim, struct_ip_attacker;

// interface name and timing
char iface[32];
char timing[32];
char pcap_filename[50];

// pcap and config filenames
char *cfile;

FILE *fp;
int err;

intf_t *i;
//eth_t *e;
pcap_t *handle;
struct intf_entry ie;

//response
uint32_t response_ack, response_seq, temp;
// functions
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void usage();
void readcfg(char *cfile);
void open_devices();
void rmnl(char *s);
void rmslash(char *s);
int load_address(FILE *fp, char *ip, char *eth, struct addr *ip_struct, struct addr *eth_struct);
void getVictimResponse();

void main(int argc, char *argv[])
{
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	int magNum, majVer, minVer, snapLen, linkType;

	if (argc == 2)
	{
		if (strcmp(argv[1], "-h") == 0)
		{
			usage(1);
			return;
		}
		else
		{
			cfile = argv[1];
		}
	}
	else
	{
		usage(0);
	}
	readcfg(cfile);
	open_devices();

	descr = pcap_open_offline(pcap_filename, errbuf);

	if (descr == NULL)
	{
		printf("descriptor could not open\n");
		return;
	}

	majVer = pcap_major_version(descr);
	printf("Version major number: %d\n", majVer);
	minVer = pcap_minor_version(descr);
	printf("Version minor number: %d\n", minVer);
	snapLen = pcap_snapshot(descr);
	printf("Snaplen = %d\n", snapLen);
	linkType = pcap_datalink(descr);
	printf("Linktype = %d\n\n", linkType);

	if (pcap_loop(descr, 0, packetHandler, NULL) < 0)
	{
		printf("pcap_loop() failed");
		return;
	}

	printf("capture finished\n");
	return;
}

/*
	print and modify each replayed packet
*/

void packetHandler(u_char *userData, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
	//protocol headers
	struct eth_hdr *ethernetHeader;
	struct ip_hdr *ipHeader;
	struct tcp_hdr *tcpHeader;
	struct udp_hdr *udpHeader;
	const struct icmp_hdr *icmpHeader;
	const struct igmp_hdr *igmpHeader;
	const struct arp_hdr *arpHeader;
	// time variables
	int b_usec = 0;
	int c_usec = 0;
	unsigned int b_sec = 0;
	unsigned int c_sec = 0;
	// var to store the ethernet type value
	short eth_type;
	// packet lenght variables
	u_int length = packet_header->len;
	u_int caplen = packet_header->caplen;
	// address structures
	struct addr srcad, srcha;
	// new address strings
	char eth_new_source[ETH_ADDR_BITS];
	char eth_new_destination[ETH_ADDR_BITS];
	char ip_new_source[IP_ADDR_BITS];
	char ip_new_destination[IP_ADDR_BITS];
	int n;

	printf("\nPacket %d\n", packet_counter);
	++packet_counter;

	//calculate times
	if (firstime)
	{
		firstime = 0;
		b_sec = packet_header->ts.tv_sec;
		b_usec = packet_header->ts.tv_usec;
	}
	else
	{
		c_sec = packet_header->ts.tv_sec - b_sec;
		c_usec = packet_header->ts.tv_usec - b_usec;
		while (c_usec < 0)
		{
			c_usec += 1000000;
			c_sec--;
		}
	}

	// print times
	printf("%05u.%06u\n", (unsigned)c_sec, (unsigned)c_usec);
	printf("Captured Packet Length\t%d\n", (caplen * 4));
	printf("Actual Packet Length\t%d\n", (length * 4));

	// get ethernet header
	ethernetHeader = (struct eth_hdr *)(packet);

	// print and modify ethernet header
	printf("Ethernet Header\n");

	addr_pack(&srcha, ADDR_TYPE_ETH, ETH_ADDR_BITS, &(ethernetHeader->eth_src), ETH_ADDR_LEN);

	eth_ntop(&(ethernetHeader->eth_dst), eth_destination, ETH_ADDR_BITS);
	eth_ntop(&(ethernetHeader->eth_src), eth_source, ETH_ADDR_BITS);

	if (addr_cmp(&srcha, &struct_eth_victim))
	{
		printf("entered send");
		memcpy(&ethernetHeader->eth_dst, &struct_eth_new_victim.addr_eth, ETH_ADDR_LEN);
		memcpy(&ethernetHeader->eth_src, &struct_my_eth.addr_eth, ETH_ADDR_LEN);
		bsend = 1;
	}
	else
	{
		getVictimResponse();
		memcpy(&ethernetHeader->eth_src, &struct_eth_new_victim.addr_eth, ETH_ADDR_LEN);
		memcpy(&ethernetHeader->eth_dst, &struct_my_eth.addr_eth, ETH_ADDR_LEN);
	}

	eth_ntop(&(ethernetHeader->eth_dst), eth_new_destination, ETH_ADDR_BITS);
	eth_ntop(&(ethernetHeader->eth_src), eth_new_source, ETH_ADDR_BITS);

	printf("\teth_src =\t%s\n", eth_source);
	printf("\trep_src =\t%s\n", eth_new_source);

	printf("\teth_dest =\t%s\n", eth_destination);
	printf("\trep_dest =\t%s\n", eth_new_destination);

	eth_type = packet[12] * 256 + packet[13];

	if (eth_type >= 0x600)
	{
		switch (eth_type)
		{
		case 0x800: // IP Packet
			printf("\tIP\n");

			ipHeader = (struct ip_hdr *)(packet + sizeof(struct eth_hdr));
			printf("\t\tip len = %d\n", ipHeader->ip_len);

			addr_pack(&srcad, ADDR_TYPE_IP, IP_ADDR_BITS, &(ipHeader->ip_src), IP_ADDR_LEN);

			ip_ntop(&(ipHeader->ip_dst), ip_destination, IP_ADDR_BITS);
			ip_ntop(&(ipHeader->ip_src), ip_source, IP_ADDR_BITS);

			if (bsend == 0)
			{
				memcpy(&ipHeader->ip_src, &struct_ip_new_victim.addr_ip, IP_ADDR_LEN);
				memcpy(&ipHeader->ip_dst, &struct_my_ip.addr_ip, IP_ADDR_LEN);
			}
			else
			{
				memcpy(&ipHeader->ip_src, &struct_my_ip.addr_ip, IP_ADDR_LEN);
				memcpy(&ipHeader->ip_dst, &struct_ip_new_victim.addr_ip, IP_ADDR_LEN);
			}

			ip_ntop(&(ipHeader->ip_dst), ip_new_destination, IP_ADDR_BITS);
			ip_ntop(&(ipHeader->ip_src), ip_new_source, IP_ADDR_BITS);

			printf("\t\tip src = %s\n", ip_source);
			printf("\t\trep src = %s\n", ip_new_source);

			printf("\t\tip dst = %s\n", ip_destination);
			printf("\t\trep dst = %s\n", ip_new_destination);

			if ((ipHeader->ip_p) == IP_PROTO_TCP)
			{

				printf("\t\tTCP\n");
				tcpHeader = (struct tcp_hdr *)(packet + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
				char *tcp_payload;
				printf("\t\t\tsrc port = %d\n", htons(tcpHeader->th_sport));
				printf("\t\t\tdst port = %d\n", htons(tcpHeader->th_dport));
				printf("\t\t\tseq = %u\n", htonl(tcpHeader->th_seq));
				printf("\t\t\tack = %u\n", htonl(tcpHeader->th_ack));
				tcp_payload = (u_char *)(packet + sizeof(struct eth_hdr) + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr));
				int payloadsize = sizeof(tcp_payload);

				if (receivedResponse == 1 && bsend == 1)
				{
					/*

					else if Flag & THF_FIN == TH_FIN

					Else 

					Ack = payload
					*/
					printf("\t\t\treceived response entered\n");
					if (tcpHeader->th_flags == TH_SYN || tcpHeader->th_flags == TH_ACK)
					{
						temp = (htonl(response_seq) + 1);
						response_seq = ntohl(temp);
						memcpy(&tcpHeader->th_ack, &response_seq, sizeof(tcpHeader->th_ack));
					}
					else if (tcpHeader->th_flags == TH_PUSH)
					{
						memcpy(&tcpHeader->th_ack, &response_seq, sizeof(tcpHeader->th_ack));
					}
					printf("\t\t\tmod seq = %u\n", htonl(tcpHeader->th_seq));
					printf("\t\t\tmod ack = %u\n", htonl(tcpHeader->th_ack));
				}
			}
			else if (ipHeader->ip_p == IP_PROTO_UDP)
			{
				printf("\t\tUDP\n");
				udpHeader = (struct udp_hdr *)(packet + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
				printf("\t\t\tsrc port = %d\n", htons(udpHeader->uh_sport));
				printf("\t\t\tdst port = %d\n", htons(udpHeader->uh_dport));
			}
			else if (ipHeader->ip_p == IP_PROTO_ICMP)
			{
				printf("\t\tICMP\n");
				icmpHeader = (struct icmp_hdr *)(packet + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
				switch (icmpHeader->icmp_type)
				{
				case ICMP_ECHOREPLY:
					printf("\t\t\tEcho Reply\n");
					break;
				case ICMP_UNREACH:
					printf("\t\t\tDestination Unreachable\n");
					break;
				case ICMP_SRCQUENCH:
					printf("\t\t\tSource Quench\n");
					break;
				case ICMP_REDIRECT:
					printf("\t\t\tRoute redirection\n");
					break;
				case ICMP_ALTHOSTADDR:
					printf("\t\t\tAlternate Host Address\n");
					break;
				case ICMP_ECHO:
					printf("\t\t\tEcho\n");
					break;
				case ICMP_RTRADVERT:
					printf("\t\t\tRoute Advertisement\n");
					break;
				case ICMP_RTRSOLICIT:
					printf("\t\t\tRoute Solicitation\n");
					break;
				case ICMP_TIMEXCEED:
					printf("\t\t\tTime Exceeded\n");
					break;
				case ICMP_PARAMPROB:
					printf("\t\t\tBad IP Header\n");
					break;
				case ICMP_TSTAMP:
					printf("\t\t\tTimestamp Request\n");
					break;
				case ICMP_TSTAMPREPLY:
					printf("\t\t\tTime Stamp Reply\n");
					break;
				case ICMP_INFO:
					printf("\t\t\tInformation Request\n");
					break;
				case ICMP_INFOREPLY:
					printf("\t\t\tInformation Reply\n");
					break;
				case ICMP_MASK:
					printf("\t\t\tAddress Mask Request\n");
					break;
				case ICMP_TRACEROUTE:
					printf("\t\t\tTraceroute\n");
					break;
				case ICMP_DATACONVERR:
					printf("\t\t\tData Conversion Error\n");
					break;
				case ICMP_MOBILE_REDIRECT:
					printf("\t\t\tMobile Host Redirection\n");
					break;
				case ICMP_IPV6_WHEREAREYOU:
					printf("\t\t\tIPV6 Where Are You?\n");
					break;
				case ICMP_IPV6_IAMHERE:
					printf("\t\t\tIPV6 I am Here\n");
					break;
				case ICMP_MOBILE_REG:
					printf("\t\t\tMobile Registration Request\n");
					break;
				case ICMP_MOBILE_REGREPLY:
					printf("\t\t\tMobile Registration Reply\n");
					break;
				case ICMP_DNS:
					printf("\t\t\tDomain Name Request\n");
					break;
				case ICMP_DNSREPLY:
					printf("\t\t\tDomain Name Reply\n");
					break;
				case ICMP_SKIP:
					printf("\t\t\tSkip\n");
					break;
				case ICMP_PHOTURIS:
					printf("\t\t\tPhotorius\n");
					break;
				default:
					printf("\t\t\tOther\n");
					break;
				}
			}
			else if (ipHeader->ip_p == IP_PROTO_IGMP)
			{
				igmpHeader = (struct igmp_hdr *)(packet + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));
				printf("\t\tIGMP\n");
			}
			else
			{
				printf("\t\tOTHER\n");
			}
			break;
		case 0x806: // ARP Packet
			printf("\tARP\n");
			arpHeader = (struct arp_hdr *)(packet + sizeof(struct eth_hdr));
			switch (arpHeader->ar_op)
			{
			case ARP_OP_REQUEST:
				printf("\t\tARP Request");
				break;
			case ARP_OP_REPLY:
				printf("\t\tARP Reply");
				break;
			case ARP_OP_REVREQUEST:
				printf("\t\tARP Reverse Reply");
				break;
			case ARP_OP_REVREPLY:
				printf("\t\tARP Reverse Reply");
				break;
			default:
				printf("\t\tARP Other");
				break;
			}
		}
	}
	ip_checksum((void *)ipHeader, ntohs(ipHeader->ip_len));
	if (bsend == 1)
	{
		receivedResponse = 0;
		n = pcap_sendpacket(handle, packet, packet_header->len);
		if (n != 0)
		{
			printf("\tPacket not sent because of failure\n\n");
		}
		else
		{
			printf("\tPacket sent\n\n");
			if (strcmp(timing, "delay") == 0)
			{
				usleep(500000);
			}
		}
		bsend = 0;
	}
	else
	{
		notsent++;
		printf("\tPacket not sent\n\n");
	}
}

/*
	print the usage in case of usage error
*/

void usage(int flag)
{
	if (flag == 0)
	{
		printf("wrong usage\n");
		printf("correct usage: ./assign5 <configuration file>\n");
	}
	else
	{
		printf("usage: ./assign5 <configuration file>\n");
	}
}

/*
	read the provided configuration file
*/

void readcfg(char *cfile)
{
	FILE *fp;
	fp = fopen(cfile, "r");
	if (fp == NULL)
	{
		perror(cfile);
		exit(-1);
	}
	// Get log file name
	if (fgets(pcap_filename, sizeof(pcap_filename), fp) == NULL)
	{
		fprintf(stderr, "log file name to long");
		exit(-1);
	}
	rmnl(pcap_filename);
	printf("file name: %s", pcap_filename);
	//Get victim IP and MAC address
	if ((err = load_address(fp, ip_victim, eth_victim, &struct_ip_victim, &struct_eth_victim)) < 0)
		printf("error loading address of victim");
	printf("ip_victim: %s", ip_victim);
	printf("eth_victim: %s", eth_victim);
	// Get Victim Port
	if (fgets(victim_port, PORT_LENGTH, fp) == NULL)
	{
		fprintf(stderr, "Victim Port too Large");
		exit(-1);
	}
	printf("victim_port: %s", victim_port);
	// Get attatcker IP and MAC address
	if ((err = load_address(fp, ip_attacker, eth_attacker, &struct_ip_attacker, &struct_eth_attacker)) < 0)
		printf("error loading address of attacker");
	printf("ip_attacker: %s", ip_attacker);
	printf("eth_attacker: %s", eth_attacker);
	// Get Attacker Port
	if (fgets(attacker_port, PORT_LENGTH, fp) == NULL)
	{
		fprintf(stderr, "Atttacker Port too Large");
		exit(-1);
	}
	printf("attacker_port: %s", attacker_port);
	// Get new victim IP and MAC address
	if ((err = load_address(fp, ip_new_victim, eth_new_victim, &struct_ip_new_victim, &struct_eth_new_victim)) < 0)
		printf("error loading address of new victim");
	// Get Victim Port
	if (fgets(new_victim_port, PORT_LENGTH, fp) == NULL)
	{
		fprintf(stderr, "New Victim Port too Large");
		exit(-1);
	}
	// Get my IP and MAC address
	if ((err = load_address(fp, my_ip, my_eth, &struct_my_ip, &struct_my_eth)) < 0)
		printf("error loading my address\n");
	// Get My Port
	if (fgets(my_port, PORT_LENGTH, fp) == NULL)
	{
		fprintf(stderr, "My Port too Large");
		exit(-1);
	}
	// Get interface name
	if (fgets(iface, sizeof(iface), fp) == NULL)
	{
		fprintf(stderr, "Interface too large");
		exit(-1);
	}
	rmnl(iface);
	printf("interface: %s", iface);
	// Get timing
	if (fgets(timing, sizeof(timing), fp) == NULL)
	{
		fprintf(stderr, "Timing too large");
		exit(-1);
	}
	rmnl(timing);
}

/*
	open device for sending packets and get my ip and my eth addresses
*/

void open_devices(void)
{
	/*

	i = intf_open();
	if (i == NULL)
	{
		perror("intf open error");
		exit(-1);
	}
	strncpy(ie.intf_name, iface, 60);
	if (intf_get(i, &ie) == -1)
	{
		printf("intf get error, interface: %s", iface);
		//perror("intf get error, interface: %s");
		exit(-1);
	}
	e = eth_open(iface);
	if (e == NULL)
	{
		perror("eth open error");
		exit(-1);
	}
	if (pcap_compile(e, &filter, filter_exp, 0, ip) == -1)
	{
		perror("bad filter");
		exit(-1);
	}
	if (pcap_setfilter(e, &filter) == -1)
	{
		perror("error setting filter");
		exit(-1);
	}
	*/

	char filter_exp[1024];
	snprintf(filter_exp, sizeof(filter_exp), "ip src %s", ip_new_victim);
	char error_buffer[PCAP_ERRBUF_SIZE];
	bpf_u_int32 subnet_mask, ip;
	struct bpf_program filter;

	i = intf_open();
	if (i == NULL)
	{
		perror("intf open error");
		exit(-1);
	}
	strncpy(ie.intf_name, iface, 60);

	if (pcap_lookupnet(iface, &ip, &subnet_mask, error_buffer) == -1)
	{
		printf("Could not get information for device: %s\n", iface);
		ip = 0;
		subnet_mask = 0;
	}
	handle = pcap_open_live(iface, PCAP_ERRBUF_SIZE, 1, 1000, error_buffer);
	if (handle == NULL)
	{
		printf("Could not open %s - %s\n", iface, error_buffer);
	}
	if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1)
	{
		printf("Bad filter - %s\n", pcap_geterr(handle));
	}
	if (pcap_setfilter(handle, &filter) == -1)
	{
		printf("Error setting filter - %s\n", pcap_geterr(handle));
	}
}

/*
	load addres into address structure
*/

int load_address(FILE *fp, char *ip, char *eth, struct addr *ip_struct, struct addr *eth_struct)
{
	// Get IP address
	if (fgets(ip, 32, fp) == NULL)
		return (-1);
	rmnl(ip);
	if (addr_aton(ip, ip_struct) == -1)
		return (-2);
	if (fgets(eth, 32, fp) == NULL)
		return (-3);
	rmnl(eth);
	if (addr_aton(eth, eth_struct) == -1)
		return (-4);
	return (0);
}

void rmnl(char *s)
{
	while (*s != '\n' && *s != '\0')
		s++;
	*s = '\0';
}

void getVictimResponse()
{
	printf("\tGetting Actual Response\n");
	struct pcap_pkthdr header;	 /* The header that pcap gives us */
	const u_char *response_packet; /* The actual packet */
	struct tcp_hdr *responseTCPHeader;
	struct eth_hdr *ethernetResponseHeader;
	struct ip_hdr *ipHeader;
	char ip_source_response[ETH_ADDR_BITS], ip_destination_response[ETH_ADDR_BITS];
	struct ip_hdr *ipHeaderResponse;

	response_packet = pcap_next(handle, &header);

	ethernetResponseHeader = (struct eth_hdr *)(response_packet);

	printf("\tIP\n");

	ipHeaderResponse = (struct ip_hdr *)(response_packet + sizeof(struct eth_hdr));
	printf("\t\tip len = %d\n", ipHeaderResponse->ip_len);

	ip_ntop(&(ipHeaderResponse->ip_dst), ip_destination_response, IP_ADDR_BITS);
	ip_ntop(&(ipHeaderResponse->ip_src), ip_source_response, IP_ADDR_BITS);

	printf("\t\tip src response= %s\n", ip_source_response);
	printf("\t\tip dst response = %s\n", ip_destination_response);

	responseTCPHeader = (struct tcp_hdr *)(response_packet + sizeof(struct eth_hdr) + sizeof(struct ip_hdr));

	response_ack = responseTCPHeader->th_ack;
	response_seq = responseTCPHeader->th_seq;

	printf("\t\t\tgot response seq = %u\n", htonl(responseTCPHeader->th_seq));
	printf("\t\t\tgot response ack = %u\n\n\n", htonl(response_ack));

	receivedResponse = 1;
}
