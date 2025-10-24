#ifndef PWNAGOTCHI_DETECT_H
#define PWNAGOTCHI_DETECT_H

#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_http_server.h"

void pwnagotchi_detect_start(void);
void pwnagotchi_detect_stop(void);
esp_err_t pwnagotchi_detect_handler(httpd_req_t *req);

#endif