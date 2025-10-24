#ifndef PACKET_MONITOR_H
#define PACKET_MONITOR_H

#include "esp_wifi.h"
#include "esp_http_server.h"

esp_err_t packet_monitor_handler(httpd_req_t *req);
void packet_monitor_start(uint8_t channel);
void packet_monitor_stop(void);

#endif