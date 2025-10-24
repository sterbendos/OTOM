#include "pcap_serializer.h"
#include <string.h>
#include <stdlib.h>
#include "esp_timer.h"

// PCAP file header
typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_header_t;

// PCAP packet header
typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

void pcap_init(pcap_buffer_t *buf) {
    memset(buf, 0, sizeof(pcap_buffer_t));
}

bool pcap_add_packet(pcap_buffer_t *buf, const uint8_t *packet, uint16_t len) {
    if (buf->count >= MAX_PACKETS) return false;
    if (buf->total_size + len > MAX_PCAP_SIZE) return false;
    
    uint8_t *pkt_copy = malloc(len);
    if (!pkt_copy) return false;
    
    memcpy(pkt_copy, packet, len);
    
    uint64_t now = esp_timer_get_time();
    buf->packets[buf->count].data = pkt_copy;
    buf->packets[buf->count].len = len;
    buf->packets[buf->count].timestamp_sec = now / 1000000;
    buf->packets[buf->count].timestamp_usec = now % 1000000;
    
    buf->count++;
    buf->total_size += len;
    
    return true;
}

int pcap_serialize(pcap_buffer_t *buf, uint8_t *output, int max_len) {
    int offset = 0;
    
    // Write file header
    pcap_file_header_t file_hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 105  // IEEE 802.11
    };
    
    if (offset + sizeof(file_hdr) > max_len) return -1;
    memcpy(output + offset, &file_hdr, sizeof(file_hdr));
    offset += sizeof(file_hdr);
    
    // Write packets
    for (int i = 0; i < buf->count; i++) {
        pcap_packet_header_t pkt_hdr = {
            .ts_sec = buf->packets[i].timestamp_sec,
            .ts_usec = buf->packets[i].timestamp_usec,
            .incl_len = buf->packets[i].len,
            .orig_len = buf->packets[i].len
        };
        
        if (offset + sizeof(pkt_hdr) + buf->packets[i].len > max_len) break;
        
        memcpy(output + offset, &pkt_hdr, sizeof(pkt_hdr));
        offset += sizeof(pkt_hdr);
        
        memcpy(output + offset, buf->packets[i].data, buf->packets[i].len);
        offset += buf->packets[i].len;
    }
    
    return offset;
}

void pcap_clear(pcap_buffer_t *buf) {
    for (int i = 0; i < buf->count; i++) {
        if (buf->packets[i].data) {
            free(buf->packets[i].data);
        }
    }
    memset(buf, 0, sizeof(pcap_buffer_t));
}

int pcap_get_download(pcap_buffer_t *buf, uint8_t **data) {
    int total_size = sizeof(pcap_file_header_t);
    for (int i = 0; i < buf->count; i++) {
        total_size += sizeof(pcap_packet_header_t) + buf->packets[i].len;
    }
    
    *data = malloc(total_size);
    if (!*data) return -1;
    
    return pcap_serialize(buf, *data, total_size);
}