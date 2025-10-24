#ifndef FRAME_ANALYZER_H
#define FRAME_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi_types.h"

// Frame control field structure
typedef struct {
    unsigned protocol:2;
    unsigned type:2;
    unsigned subtype:4;
    unsigned to_ds:1;
    unsigned from_ds:1;
    unsigned more_frag:1;
    unsigned retry:1;
    unsigned pwr_mgmt:1;
    unsigned more_data:1;
    unsigned wep:1;
    unsigned order:1;
} frame_ctrl_t;

// Management frame header
typedef struct {
    frame_ctrl_t frame_ctrl;
    uint16_t duration;
    uint8_t addr1[6];  // Receiver
    uint8_t addr2[6];  // Transmitter
    uint8_t addr3[6];  // BSSID
    uint16_t seq_ctrl;
} mgmt_header_t;

// Data frame header
typedef struct {
    frame_ctrl_t frame_ctrl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
    uint8_t addr4[6];  // Only in WDS
} data_header_t;

// EAPOL frame structure
typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t length;
} eapol_header_t;

// Key frame info
typedef struct {
    uint8_t type;
    uint16_t info;
    uint16_t length;
    uint64_t replay_counter;
    uint8_t nonce[32];
    uint8_t iv[16];
    uint8_t rsc[8];
    uint8_t id[8];
    uint8_t mic[16];
    uint16_t data_length;
} eapol_key_t;

// Frame type identifiers
#define FRAME_TYPE_MGMT 0
#define FRAME_TYPE_CTRL 1
#define FRAME_TYPE_DATA 2

// Management subtypes
#define SUBTYPE_ASSOC_REQ    0
#define SUBTYPE_ASSOC_RESP   1
#define SUBTYPE_REASSOC_REQ  2
#define SUBTYPE_REASSOC_RESP 3
#define SUBTYPE_PROBE_REQ    4
#define SUBTYPE_PROBE_RESP   5
#define SUBTYPE_BEACON       8
#define SUBTYPE_DISASSOC     10
#define SUBTYPE_AUTH         11
#define SUBTYPE_DEAUTH       12

// Data subtypes
#define SUBTYPE_QOS_DATA     8

// EAPOL types
#define EAPOL_KEY 3

// Analysis functions
bool is_eapol_packet(const uint8_t *packet, uint16_t len);
bool is_handshake_packet(const uint8_t *packet, uint16_t len, uint8_t *message_num);
bool is_pmkid_frame(const uint8_t *packet, uint16_t len);
bool extract_pmkid(const uint8_t *packet, uint16_t len, uint8_t *pmkid);
void get_packet_bssid(const uint8_t *packet, uint8_t *bssid);
void get_packet_src(const uint8_t *packet, uint8_t *src);
void get_packet_dst(const uint8_t *packet, uint8_t *dst);

#endif