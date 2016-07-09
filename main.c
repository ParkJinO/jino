#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

int main(void)
{
    int i=0;
    int iphlen =0;
    u_char a=0;

    struct sockaddr_in dip, sip;
    u_short dport, sport;
    char *dipstr;
    char *sipstr;

    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;

    char track[] = "컨설팅";
    char name[] = "박진오";

    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    printf("[bob5][%s]pcap_test[%s]", track, name);
    printf("\n");

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
        pcap_next_ex(handle,&header,&pkt_data);
        a = (*((u_char*)&(pkt_data[14])));
        a = a << 4;
        a = a >> 4;
        iphlen = a * 4;
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
        sip.sin_addr.s_addr=(*((u_int*)(&(pkt_data[26]))));
        dip.sin_addr.s_addr=(*((u_int*)(&(pkt_data[30]))));
        sport = ntohs(*((u_short*)(&(pkt_data[14+iphlen]))));
        dport = ntohs(*((u_short*)(&(pkt_data[16+iphlen]))));
        sipstr=inet_ntoa(sip.sin_addr);
        printf("ip.sip : %s\n",sipstr);
        dipstr=inet_ntoa(dip.sin_addr);
        printf("ip.dip : %s\n",dipstr);
        printf("tcp.sport : %d\n",(int)sport);
        printf("tcp.dport : %d\n\n",(int)dport);
    }
    return(0);
}
