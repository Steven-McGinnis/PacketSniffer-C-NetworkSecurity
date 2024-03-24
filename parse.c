#include "parse.h"

/**
 * Parse a TCP packet, print header info and payload
 * @param packet
 * @param ip
 * @param tcp
 */
void parse_tcp(const u_char *packet, const struct sniff_ip *ip, const struct sniff_tcp *tcp)
{
    // Assuming IP header and TCP header are correctly passed in

    // Extract and print source and destination ports
    printf("Source Port: %d\n", ntohs(tcp->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp->th_dport));

    // Print sequence and acknowledgment numbers
    printf("Sequence Number: %u\n", ntohl(tcp->th_seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp->th_ack));

    // Print TCP flags if set
    printf("Flags: ");
    if (tcp->th_flags & TH_SYN)
        printf("SYN ");
    if (tcp->th_flags & TH_ACK)
        printf("ACK ");
    if (tcp->th_flags & TH_FIN)
        printf("FIN ");
    if (tcp->th_flags & TH_RST)
        printf("RST ");
    if (tcp->th_flags & TH_PUSH)
        printf("PUSH ");
    if (tcp->th_flags & TH_URG)
        printf("URG ");
    printf("\n");

    // Payload size calculation
    int size_payload = ntohs(ip->ip_len) - (IP_HL(ip) * 4) - (TH_OFF(tcp) * 4);

    // Print payload data if there is any
    if (size_payload > 0)
    {
        const char *payload = (const char *)(packet + SIZE_ETHERNET + IP_HL(ip) * 4 + TH_OFF(tcp) * 4);
        printf("Payload (%d bytes):\n", size_payload);
        print_payload((const u_char *)payload, size_payload);
    }
}

/**
 * Parse a UDP packet, print header info and payload */
void parse_udp(const u_char *packet, const struct sniff_ip *ip)
{
    // Assuming IP header is correctly passed in
    // UDP header is located after the IP header
    const struct sniff_udp *udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + IP_HL(ip) * 4);

    // Extract and print source and destination ports
    printf("Source Port: %d\n", ntohs(udp->th_sport));
    printf("Destination Port: %d\n", ntohs(udp->th_dport));

    // Calculate payload size
    int size_payload = ntohs(udp->th_len) - sizeof(struct sniff_udp);

    // Print payload data if there is any
    if (size_payload > 0)
    {
        const char *payload = (const char *)(packet + SIZE_ETHERNET + IP_HL(ip) * 4 + sizeof(struct sniff_udp));
        printf("Payload (%d bytes):\n", size_payload);
        print_payload((const u_char *)payload, size_payload);
    }
}

/*
 * print data in rows of 16 bytes: offset     ascii
 *
 */
void print_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    const u_char *ch;

    /* ascii (if printable) */
    ch = payload;
    for (i = 0; i < len; i++)
    {
        if (isprint(*ch))
            printf("%c", *ch); // character by character
        else
            printf("."); // non-ASCII
        ch++;
    }
}

/*
 * Print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16; /* number of bytes per line */
    int line_len;
    int offset = 0; /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width)
    {
        print_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for (;;)
    {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width)
        {
            /* print last line and get out */
            print_ascii_line(ch, len_rem, offset);
            break;
        }
    }

   

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct sniff_ethernet *ethernet; // The ethernet header
    const struct sniff_ip *ip;             // The IP header
    const struct sniff_tcp *tcp;           // The TCP header
    const char *payload;                   // Packet payload

    int size_ip;
    int size_tcp;
    int size_payload;

    // Define ethernet header
    ethernet = (struct sniff_ethernet*)(packet);
    
    // Define IP header
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // Define TCP header
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    // Define payload
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
    // Check if it's the right packet using conditions based on ethernet, ip and tcp fields
    // This part will depend on what exactly you need to do with the packet

    // Example condition to check if the packet is TCP and port 80
    if (ip->ip_p == IPPROTO_TCP && ntohs(tcp->th_dport) == 80) {
        printf("TCP packet from port 80\n");
        // Do something with the payload
    }
}
