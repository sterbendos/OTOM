#include "frame_analyzer.h"
#include <string.h>

bool is_eapol_packet(const uint8_t *packet, uint16_t len) {
    if (len < sizeof(data_header_t) + 8) return false;
    
    data_header_t *hdr = (data_header_t *)packet;
    if (hdr->frame_ctrl.type != FRAME_TYPE_DATA) return false;
    
    // Check for LLC header (AA AA 03) and EAPOL type (88 8E)
    const uint8_t *llc = packet + sizeof(data_header_t);
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
        llc[6] == 0x88 && llc[7] == 0x8E) {
        return true;
    }
    return false;
}

bool is_handshake_packet(const uint8_t *packet, uint16_t len, uint8_t *message_num) {
    if (!is_eapol_packet(packet, len)) return false;
    
    const uint8_t *eapol = packet + sizeof(data_header_t) + 8;
    eapol_header_t *eapol_hdr = (eapol_header_t *)eapol;
    
    if (eapol_hdr->type != EAPOL_KEY) return false;
    
    eapol_key_t *key = (eapol_key_t *)(eapol + sizeof(eapol_header_t));
    uint16_t key_info = __builtin_bswap16(key->info);
    
    // Determine message number based on key info flags
    bool install = (key_info & 0x0040);
    bool ack = (key_info & 0x0080);
    bool mic = (key_info & 0x0100);
    bool secure = (key_info & 0x0200);
    
    if (message_num) {
        if (ack && !install && !mic) *message_num = 1;
        else if (!ack && mic && !install && !secure) *message_num = 2;
        else if (ack && mic && secure && !install) *message_num = 3;
        else if (!ack && mic && secure) *message_num = 4;
        else *message_num = 0;
    }
    
    return true;
}

bool is_pmkid_frame(const uint8_t *packet, uint16_t len) {
    if (!is_eapol_packet(packet, len)) return false;
    
    // PMKID is in message 1 of 4-way handshake
    uint8_t msg_num;
    if (!is_handshake_packet(packet, len, &msg_num)) return false;
    
    return (msg_num == 1);
}

bool extract_pmkid(const uint8_t *packet, uint16_t len, uint8_t *pmkid) {
    if (!is_pmkid_frame(packet, len)) return false;
    
    const uint8_t *eapol = packet + sizeof(data_header_t) + 8;
    eapol_header_t *eapol_hdr = (eapol_header_t *)eapol;
    eapol_key_t *key = (eapol_key_t *)(eapol + sizeof(eapol_header_t));
    
    uint16_t data_len = __builtin_bswap16(key->data_length);
    const uint8_t *key_data = (const uint8_t *)(key + 1);
    
    // Parse RSN IE for PMKID
    for (uint16_t i = 0; i < data_len - 2; i++) {
        if (key_data[i] == 0xDD && i + 20 < data_len) {  // Vendor specific IE
            uint8_t oui[] = {0x00, 0x0F, 0xAC, 0x04};
            if (memcmp(&key_data[i + 2], oui, 4) == 0) {
                memcpy(pmkid, &key_data[i + 6], 16);
                return true;
            }
        }
    }
    return false;
}

void get_packet_bssid(const uint8_t *packet, uint8_t *bssid) {
    mgmt_header_t *hdr = (mgmt_header_t *)packet;
    memcpy(bssid, hdr->addr3, 6);
}

void get_packet_src(const uint8_t *packet, uint8_t *src) {
    mgmt_header_t *hdr = (mgmt_header_t *)packet;
    memcpy(src, hdr->addr2, 6);
}

void get_packet_dst(const uint8_t *packet, uint8_t *dst) {
    mgmt_header_t *hdr = (mgmt_header_t *)packet;
    memcpy(dst, hdr->addr1, 6);
}