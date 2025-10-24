#ifndef ATTACK_DOS_H
#define ATTACK_DOS_H

#include "esp_err.h"
#include "esp_http_server.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    DOS_AUTH_FLOOD,
    DOS_ASSOC_FLOOD,
    DOS_REASSOC_FLOOD,
    DOS_DISASSOC_FLOOD,
    DOS_COMBINED
} dos_attack_type_t;

typedef struct {
    dos_attack_type_t type;
    uint8_t ap_mac[6];
    uint8_t channel;
    uint32_t packets_sent;
    uint32_t duration_sec;
    uint32_t elapsed_sec;
    bool running;
} dos_status_t;

esp_err_t dos_attack_handler(httpd_req_t *req);

void dos_attack_start(dos_attack_type_t type, const uint8_t *ap_mac, uint8_t channel, uint32_t duration);
void dos_attack_stop(void);
bool dos_is_running(void);
void dos_get_status(dos_status_t *status);

#endif