#ifndef PROBE_SNIFFER_H
#define PROBE_SNIFFER_H

#include "esp_err.h"
#include "esp_http_server.h"
#include <stdbool.h>
#include <stdint.h>

// Maximum number of devices to track
#define MAX_TRACKED_DEVICES 50

// Structure to store probe request data
typedef struct {
    uint8_t mac[6];
    char ssid[33];
    int8_t rssi;
    uint32_t last_seen;
    uint16_t count;
} probe_device_t;

// HTTP handler for probe sniffer page
esp_err_t probe_sniffer_handler(httpd_req_t *req);

// Start/stop probe sniffer (snapshot mode - scans all channels then restores AP)
void probe_sniffer_start(void);
void probe_sniffer_stop(void);
bool is_probe_sniffer_running(void);

// Get tracked devices (for web display)
int probe_sniffer_get_devices(probe_device_t *devices, int max_devices);
void probe_sniffer_clear_devices(void);

#endif // PROBE_SNIFFER_H