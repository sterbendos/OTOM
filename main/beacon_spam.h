#ifndef BEACON_SPAM_H
#define BEACON_SPAM_H

#include "esp_err.h"
#include "esp_http_server.h"

esp_err_t wifi_beacon_handler(httpd_req_t *req);
void beacon_spam_task(void *pvParameter);
void beacon_spam_stop(void);

#endif