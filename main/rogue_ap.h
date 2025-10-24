#ifndef ROGUE_AP_H
#define ROGUE_AP_H

#include "esp_wifi.h"
#include "esp_http_server.h"
#include "wifi_scan.h"

esp_err_t rogue_ap_handler(httpd_req_t *req);
void rogue_ap_start(const wifi_ap_record_t *target);
void rogue_ap_stop(void);

#endif