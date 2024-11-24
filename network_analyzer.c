#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

// Ethernet Header structure
struct ethernet_header {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short h_protocol;
};

// Function prototypes
void print_mac_address(const unsigned char *mac);
void decode_ethernet_header(const unsigned char *buffer);
void decode_ip_header(const unsigned char *buffer, int packet_size);
void decode_tcp_header(const unsigned char *buffer);
void decode_udp_header(const unsigned char *buffer);
int is_valid_ip_packet(const unsigned char *buffer);
int is_valid_mac_address(const unsigned char *mac);
int is_http_request(unsigned char *payload, int size);
int is_image(unsigned char *payload, int size);
void detect_payload_type(const unsigned char *payload, int size);

int main() {
    unsigned char *buffer;
    int packet_size, raw_socket;

    // Create a raw socket to capture all packets
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        fprintf(stderr,"Socket creation failed");
        exit(EXIT_FAILURE);
    }

    buffer = (unsigned char *)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        fprintf(stderr,"Memory allocation error");
        close(raw_socket);
        exit(EXIT_FAILURE);
    }

    printf("Starting packet capture. Press Ctrl+C to stop.\n");

    while (1) {
        // Capture raw packet data
        packet_size = recvfrom(raw_socket, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (packet_size < 0) {
            fprintf(stderr,"Packet reception failed");
            break;
        }

        // Check if packet is valid before printing information
        struct ethernet_header *eth = (struct ethernet_header *)buffer;
        
        // Skip loopback packets with all-zero MAC addresses
        if (ntohs(eth->h_protocol) == ETH_P_IP && 
            is_valid_ip_packet(buffer + sizeof(struct ethernet_header)) &&
            is_valid_mac_address(eth->dest_mac) && 
            is_valid_mac_address(eth->src_mac)) {


            fprintf(stdout, "\n==============================\n");
            fprintf(stdout,"      Packet Captured\n");
            fprintf(stdout, "==============================\n");

            // Decode Ethernet header
            decode_ethernet_header(buffer);

            // Decode IP header if Ethernet protocol is IP
            decode_ip_header(buffer + sizeof(struct ethernet_header), packet_size);
        }
    }

    close(raw_socket);
    free(buffer);

    return 0;
}

// Print a MAC address
void print_mac_address(const unsigned char *mac) {
    for (int i = 0; i < 6; i++) {
        fprintf(stdout,"%02x", mac[i]);
        if (i < 5) printf(":");
    }
}

// Decode and display the Ethernet header
void decode_ethernet_header(const unsigned char *buffer) {
    struct ethernet_header *eth = (struct ethernet_header *)buffer;
    
    fprintf(stdout, "\n--- Ethernet Header ---\n");
    fprintf(stdout, "Destination MAC: ");
    print_mac_address(eth->dest_mac);
    fprintf(stdout, "\nSource MAC: ");
    print_mac_address(eth->src_mac);
    fprintf(stdout, "\nProtocol: 0x%04x\n", ntohs(eth->h_protocol));
}

// Decode and display the IP header
void decode_ip_header(const unsigned char *buffer, int packet_size) {
    struct iphdr *ip = (struct iphdr *)buffer;

    fprintf(stdout, "\n--- IP Header ---\n");
    fprintf(stdout, "Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
    fprintf(stdout, "Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
    fprintf(stdout, "Protocol: %d\n", ip->protocol);

    // Check for TCP or UDP and decode accordingly
    if (ip->protocol == IPPROTO_TCP) {
        fprintf(stdout, "\n--- TCP Protocol Detected ---\n");
        decode_tcp_header(buffer + ip->ihl * 4); // Decode TCP header after IP header

        // Detect payload type
        detect_payload_type(buffer + ip->ihl * 4 + sizeof(struct tcphdr), packet_size - ip->ihl * 4 - sizeof(struct tcphdr));

    } else if (ip->protocol == IPPROTO_UDP) {
        fprintf(stdout, "\n--- UDP Protocol Detected ---\n");
        decode_udp_header(buffer + ip->ihl * 4); // Decode UDP header after IP header
    } else {
        fprintf(stdout, "\n--- Other Protocol --- %d\n", ip->protocol); // Handle other protocols
    }
}

// Decode and display the TCP header
void decode_tcp_header(const unsigned char *buffer) {
    struct tcphdr *tcp = (struct tcphdr *)buffer;

    fprintf(stdout, "\n--- TCP Header ---\n");
    fprintf(stdout, "Source Port       : %u\n", ntohs(tcp->source));
    fprintf(stdout, "Destination Port  : %u\n", ntohs(tcp->dest));
    fprintf(stdout, "Sequence Number   : %u\n", ntohl(tcp->seq));
    fprintf(stdout, "Acknowledgment No : %u\n", ntohl(tcp->ack_seq));
}

// Decode and display the UDP header
void decode_udp_header(const unsigned char *buffer) {
    struct udphdr *udp = (struct udphdr *)buffer;

    fprintf(stdout, "\n--- UDP Header ---\n");
    fprintf(stdout, "Source Port       : %u\n", ntohs(udp->source));
    fprintf(stdout, "Destination Port  : %u\n", ntohs(udp->dest));
    fprintf(stdout, "Length            : %u\n", ntohs(udp->len));
}

// Function to check if the IP packet has valid information
int is_valid_ip_packet(const unsigned char *buffer) {
    struct iphdr *ip = (struct iphdr *)buffer;

    // Ensure the packet has valid source and destination IP addresses
    if (ip->saddr != 0 && ip->daddr != 0) {
        return 1; // Valid IP packet
    }

    return 0; // Invalid IP packet
}

// Function to check if the MAC address is not all-zero
int is_valid_mac_address(const unsigned char *mac) {
    unsigned char zero_mac[6] = {0, 0, 0, 0, 0, 0};
    return memcmp(mac, zero_mac, 6) != 0;
}

// Check for HTTP request in the payload
int is_http_request(unsigned char *payload, int size) {
    if (size > 4 && 
        (strncasecmp((char *)payload, "GET", 3) == 0 ||
         strncasecmp((char *)payload, "POST", 4) == 0 ||
         strncasecmp((char *)payload, "PUT", 3) == 0 ||
         strncasecmp((char *)payload, "DELETE", 6) == 0)) {
        return 1; // HTTP request found
    }
    return 0;
}

// Check for image file types based on magic numbers
int is_image(unsigned char *payload, int size) {
    if (size >= 4) {
        if (payload[0] == 0xFF && payload[1] == 0xD8 && payload[2] == 0xFF) {
            return 1; // JPEG image
        } else if (payload[0] == 0x89 && payload[1] == 0x50 && payload[2] == 0x4E && payload[3] == 0x47) {
            return 2; // PNG image
        }
    }
    return 0; // Not an image
}

// Detect the type of payload based on the content
void detect_payload_type(const unsigned char *payload, int payload_size) {
    if (payload_size > 0) {
        if (payload[0] == 0x48 && payload[1] == 0x54 && payload[2] == 0x54 && payload[3] == 0x50) {
            fprintf(stdout, "Payload Type: HTTP Request\n");
        } else if (payload_size > 4 && payload[0] == 0xFF && payload[1] == 0xD8) {
            fprintf(stdout, "Payload Type: Image (JPEG)\n");
        } else if (payload_size > 4 && payload[0] == 0x89 && payload[1] == 0x50 && payload[2] == 0x4E && payload[3] == 0x47) {
            fprintf(stdout, "Payload Type: Image (PNG)\n");
        } else {
            fprintf(stdout, "Payload Type: Binary Data (File Transfer)\n");
        }
    } else {
        fprintf(stdout, "Payload is empty or invalid.\n");
    }
}