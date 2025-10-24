#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include "esp_wifi.h"
#include <stdbool.h>

#define DEFAULT_SCAN_LIST_SIZE 20
#define MAX_CLIENTS_PER_AP 20

typedef struct {
    uint8_t mac[6];
    int8_t rssi;
    uint32_t last_seen;
} client_info_t;

typedef struct {
    wifi_ap_record_t ap;
    client_info_t clients[MAX_CLIENTS_PER_AP];
    int client_count;
} ap_with_clients_t;

char *wifi_scan_html(bool deep_scan);
int wifi_scan_get_results(ap_with_clients_t *results, int max_count);

#endif