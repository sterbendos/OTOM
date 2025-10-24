#ifndef DEAUTH_ATTACK_H
#define DEAUTH_ATTACK_H

#include "esp_err.h"
#include "esp_http_server.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t ap_mac[6];
    uint8_t client_mac[6];
    uint8_t channel;
    uint32_t packets_sent;
    uint32_t elapsed_sec;
    uint32_t duration_sec;
    bool broadcast;
} deauth_status_t;

esp_err_t wifi_deauth_handler(httpd_req_t *req);
void deauth_attack_start(const uint8_t *ap_mac, const uint8_t *client_mac, uint8_t channel, uint32_t duration_sec);
void deauth_attack_stop(void);
bool is_deauth_running(void);
void deauth_get_status(deauth_status_t *status);

#endif