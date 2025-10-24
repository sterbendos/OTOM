#ifndef EVIL_PORTAL_H
#define EVIL_PORTAL_H

#include "esp_http_server.h"

esp_err_t evil_portal_handler(httpd_req_t *req);
void evil_portal_start(void);
void evil_portal_stop(void);

#endif