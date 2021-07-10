#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include<getopt.h> 

#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

FILE *logfile;

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);



/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

 int i;
 int gap;
 const u_char *ch;

  fprintf(logfile,"%05d   ", offset);
 
 ch = payload;
 for(i = 0; i < len; i++) {
   fprintf(logfile,"%02x ", *ch);
  ch++;
  if (i == 7)
    fprintf(logfile," ");
 }
 if (len < 8)
   fprintf(logfile," ");
 
 if (len < 16) {
  gap = 16 - len;
  for (i = 0; i < gap; i++) {
    fprintf(logfile,"   ");
  }
 }
  fprintf(logfile,"   ");
 
 ch = payload;
 for(i = 0; i < len; i++) {
  if (isprint(*ch))
    fprintf(logfile,"%c", *ch);
  else
   fprintf(logfile,".");
  ch++;
 }

  fprintf(logfile,"\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

 int len_rem = len;
 int line_width = 16;  
 int line_len;
 int offset = 0;    
 const u_char *ch = payload;

 if (len <= 0)
  return;

 if (len <= line_width) {
  print_hex_ascii_line(ch, len, offset);
  return;
 }

 for ( ;; ) {
  line_len = line_width % len_rem;
  print_hex_ascii_line(ch, line_len, offset);
  len_rem = len_rem - line_len;
  ch = ch + line_len;
  offset = offset + line_width;
  if (len_rem <= line_width) {
   print_hex_ascii_line(ch, len_rem, offset);
   break;
  }
 }

return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

 static int count = 1;                   
 
 const struct sniff_ethernet *ethernet; 
 const struct sniff_ip *ip;           
 const struct sniff_tcp *tcp;          
 const char *payload;                  

 int size_ip;
 int size_tcp;
 int size_payload;
 
  fprintf(logfile,"\nPacket number %d:\n", count);
 count++;
 
 ethernet = (struct sniff_ethernet*)(packet);
 
 ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
 size_ip = IP_HL(ip)*4;
 if (size_ip < 20) {
  printf("   * Invalid IP header length: %u bytes\n", size_ip);
  return;
 }

  fprintf(logfile,"       From: %s\n", inet_ntoa(ip->ip_src));
  fprintf(logfile,"         To: %s\n", inet_ntoa(ip->ip_dst));
 
 switch(ip->ip_p) {
  case IPPROTO_TCP:
    fprintf(logfile,"   Protocol: TCP\n");
   break;
  default:
    fprintf(logfile,"   Protocol: unknown\n");
   return;
 }
 
 /*
  *  OK, this packet is TCP.
  */
 
 tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
 size_tcp = TH_OFF(tcp)*4;
 if (size_tcp < 20) {
  printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
  return;
 }
 
  fprintf(logfile,"   Src port: %d\n", ntohs(tcp->th_sport));
  fprintf(logfile,"   Dst port: %d\n", ntohs(tcp->th_dport));
 
 payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
 
 size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
 
 if (size_payload > 0) {
   fprintf(logfile,"   Payload (%d bytes):\n", size_payload);
  print_payload(payload, size_payload);
 }

return;
}

/* main function */

int main(int argc, char **argv)
{
 int c;
 char *dev = NULL;  
 char errbuf[PCAP_ERRBUF_SIZE];  
 pcap_t *handle;   

 char filter_exp[] = "tcp"; 
 struct bpf_program fp;   
 bpf_u_int32 mask;  
 bpf_u_int32 net;   
 int num_packets ;   
 char *file_name;
 int errNum = 0;

while((c=getopt(argc, argv, "if")) != -1)
{
    switch(c)
    {
    case 'i':
  	dev = argv[2];
	printf("%s\n",argv[2]);
        break;
    case 'f':
	file_name= argv[4];
	printf("%s\n",argv[4]);
        break;
    case '?':
        printf("wrong command");
        break;
    }
}

 logfile=fopen(file_name,"w");
 if(logfile==NULL)
 {
	errNum = errno;
	printf("open fail errno = %d  \n", errNum);
 }
 printf("Starting...\n");

 if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
  fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
      dev, errbuf);
  net = 0;
  mask = 0;
 }

 printf("Device: %s\n", dev);
 printf("Number of packets: %d\n", num_packets);
 printf("Filter expression: %s\n", filter_exp);
 printf("Starting sniffer..... exit: Ctrl+C \n");

 handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
 if (handle == NULL) {
  fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
  exit(EXIT_FAILURE);
 }

 if (pcap_datalink(handle) != DLT_EN10MB) {
  fprintf(stderr, "%s is not an Ethernet\n", dev);
  exit(EXIT_FAILURE);
 }

 if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
  fprintf(stderr, "Couldn't parse filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
  exit(EXIT_FAILURE);
 }

 if (pcap_setfilter(handle, &fp) == -1) {
  fprintf(stderr, "Couldn't install filter %s: %s\n",
      filter_exp, pcap_geterr(handle));
  exit(EXIT_FAILURE);
 }

 pcap_loop(handle, num_packets, got_packet, NULL);

 pcap_freecode(&fp);
 pcap_close(handle);

 printf("\nCapture complete.\n");

return 0;
}
