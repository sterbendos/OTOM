#ifndef ATTACK_HANDSHAKE_H
#define ATTACK_HANDSHAKE_H

#include "esp_err.h"
#include "esp_http_server.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool has_m1;
    bool has_m2;
    bool has_m3;
    bool has_m4;
    uint8_t ap_mac[6];
    uint8_t sta_mac[6];
    char ssid[33];
    uint32_t timestamp;
} handshake_capture_t;

typedef struct {
    handshake_capture_t capture;
    bool running;
    bool complete;
    uint32_t packets_captured;
    uint32_t deauth_sent;
} handshake_status_t;

esp_err_t handshake_attack_handler(httpd_req_t *req);

void handshake_attack_start(const uint8_t *ap_mac, uint8_t channel, const char *ssid, bool deauth);
void handshake_attack_stop(void);
bool handshake_is_running(void);
void handshake_get_status(handshake_status_t *status);
int handshake_get_pcap(uint8_t **data);

#endif