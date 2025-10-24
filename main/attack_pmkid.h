#ifndef ATTACK_PMKID_H
#define ATTACK_PMKID_H

#include "esp_err.h"
#include "esp_http_server.h"
#include <stdbool.h>
#include <stdint.h>

#define MAX_PMKID_CAPTURES 10

typedef struct {
    uint8_t ap_mac[6];
    uint8_t sta_mac[6];
    uint8_t pmkid[16];
    char ssid[33];
    uint32_t timestamp;
    bool valid;
} pmkid_capture_t;

typedef struct {
    pmkid_capture_t captures[MAX_PMKID_CAPTURES];
    int count;
    uint32_t assoc_attempts;
    bool running;
} pmkid_status_t;

// HTTP handler
esp_err_t pmkid_attack_handler(httpd_req_t *req);

// Attack control
void pmkid_attack_start(const uint8_t *ap_mac, uint8_t channel, const char *ssid);
void pmkid_attack_stop(void);
bool pmkid_is_running(void);
void pmkid_get_status(pmkid_status_t *status);

// PCAP download
int pmkid_get_pcap(uint8_t **data);

#endif