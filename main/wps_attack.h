#ifndef WPS_ATTACK_H
#define WPS_ATTACK_H

#include "esp_err.h"
#include "esp_http_server.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint8_t ap_mac[6];
    char ssid[33];
    uint8_t channel;
    uint32_t pins_tried;
    uint32_t current_pin;
    bool running;
    bool locked;
} wps_status_t;

esp_err_t wps_attack_handler(httpd_req_t *req);

void wps_attack_start(const uint8_t *ap_mac, uint8_t channel, const char *ssid);
void wps_attack_stop(void);
bool wps_is_running(void);
void wps_get_status(wps_status_t *status);

#endif