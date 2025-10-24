#ifndef PCAP_SERIALIZER_H
#define PCAP_SERIALIZER_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_PCAP_SIZE 65536
#define MAX_PACKETS 50

typedef struct {
    uint8_t *data;
    uint16_t len;
    uint32_t timestamp_sec;
    uint32_t timestamp_usec;
} pcap_packet_t;

typedef struct {
    pcap_packet_t packets[MAX_PACKETS];
    int count;
    uint32_t total_size;
} pcap_buffer_t;

// Initialize PCAP buffer
void pcap_init(pcap_buffer_t *buf);

// Add packet to buffer
bool pcap_add_packet(pcap_buffer_t *buf, const uint8_t *packet, uint16_t len);

// Serialize to PCAP format
int pcap_serialize(pcap_buffer_t *buf, uint8_t *output, int max_len);

// Clear buffer
void pcap_clear(pcap_buffer_t *buf);

// Get download-ready PCAP data
int pcap_get_download(pcap_buffer_t *buf, uint8_t **data);

#endif