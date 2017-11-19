#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

int check_etype(const unsigned char *pkt_data);
void print_mac(const unsigned char *pkt_data);
void print_ip(const unsigned char *pkt_data);
void print_port(const unsigned char *pkt_data);

int main(void)
{
    int i=0;
    u_char a=0;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    while(1)
    {        
        pcap_next_ex(handle,&header,&pkt_data); //패킷 캡쳐
        if(check_etype(pkt_data)) //패킷 타입 검사
            continue;

        print_mac(pkt_data);

        pkt_data = &pkt_data[14]; //pkt_data에서 ethernet header 제거
        print_ip(pkt_data);

        a = (*((u_char*)&(pkt_data[0])));  //ip header의 첫 4비트 : 버전, 다음 4비트 : 길이
        a = a & 0xF; //0xF == 00001111 1바이트 a에서 아래4비트 추
        pkt_data = &pkt_data[a*4];  //pkt_data에서 ip header 제거
        print_port(pkt_data);
    }
    return(0);
}

int check_etype(const unsigned char *pkt_data)
{
    u_short etype= ntohs(*((u_short*)(&(pkt_data[12])))); //ethernet header 0-5 : dmac, 6-11 : smac, 12-13 : ether type(0x0800=ip)
    if(etype==0x0800) //etype이 0x0800(ip)이면 진
        return 0;
    else
        return 1;
}

void print_mac(const unsigned char *pkt_data)
{
    int i=0;
    printf("eth.smac : ");
    for(i=6;i<12;i++)
    {
        printf("%02x",(u_char)pkt_data[i]);
        if(i!=11)
            printf(":");
    }
    printf("\n");

    printf("eth.dmac : ");
    for(i=0;i<6;i++)
    {
        printf("%02x",(u_char)pkt_data[i]);
        if(i!=5)
            printf(":");
    }
    printf("\n");
}

void print_ip(const unsigned char *pkt_data)
{
    struct sockaddr_in dip, sip;
    char *dipstr;
    char *sipstr;

    sip.sin_addr.s_addr=(*((u_int*)(&(pkt_data[12]))));
    sipstr=inet_ntoa(sip.sin_addr);
    printf("ip.sip : %s\n",sipstr);

    dip.sin_addr.s_addr=(*((u_int*)(&(pkt_data[16]))));
    dipstr=inet_ntoa(dip.sin_addr);
    printf("ip.dip : %s\n",dipstr);
}

void print_port(const unsigned char *pkt_data)
{
    u_short dport, sport;

    sport = ntohs(*((u_short*)(&(pkt_data[0]))));
    printf("tcp.sport : %d\n",(int)sport);

    dport = ntohs(*((u_short*)(&(pkt_data[2]))));
    printf("tcp.dport : %d\n\n",(int)dport);
}
