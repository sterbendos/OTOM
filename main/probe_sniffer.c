#include "probe_sniffer.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <time.h>

static const char *TAG = "PROBE_SNIFFER";

static bool sniffer_running = false;
static bool scan_in_progress = false;
static probe_device_t tracked_devices[MAX_TRACKED_DEVICES];
static int device_count = 0;
static SemaphoreHandle_t device_mutex = NULL;
static TaskHandle_t scan_task_handle = NULL;

static const uint8_t scan_channels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
static const int num_channels = sizeof(scan_channels) / sizeof(scan_channels[0]);

typedef struct {
    unsigned protocol:2;
    unsigned type:2;
    unsigned subtype:4;
    unsigned to_ds:1;
    unsigned from_ds:1;
    unsigned more_frag:1;
    unsigned retry:1;
    unsigned pwr_mgmt:1;
    unsigned more_data:1;
    unsigned wep:1;
    unsigned order:1;
} wifi_frame_ctrl_t;

typedef struct {
    wifi_frame_ctrl_t frame_ctrl;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq_ctrl;
} wifi_mgmt_hdr_t;

static int find_or_add_device(const uint8_t *mac) {
    for (int i = 0; i < device_count; i++) {
        if (memcmp(tracked_devices[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    
    if (device_count < MAX_TRACKED_DEVICES) {
        memcpy(tracked_devices[device_count].mac, mac, 6);
        tracked_devices[device_count].ssid[0] = '\0';
        tracked_devices[device_count].count = 0;
        tracked_devices[device_count].rssi = 0;
        tracked_devices[device_count].last_seen = xTaskGetTickCount();
        return device_count++;
    }
    
    return -1;
}

static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT || !scan_in_progress) {
        return;
    }
    
    const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    const wifi_mgmt_hdr_t *hdr = (wifi_mgmt_hdr_t *)ppkt->payload;
    
    if (hdr->frame_ctrl.type == 0 && hdr->frame_ctrl.subtype == 4) {
        xSemaphoreTake(device_mutex, portMAX_DELAY);
        
        int idx = find_or_add_device(hdr->addr2);
        if (idx >= 0) {
            tracked_devices[idx].count++;
            tracked_devices[idx].rssi = ppkt->rx_ctrl.rssi;
            tracked_devices[idx].last_seen = xTaskGetTickCount();
            
            const uint8_t *payload = ppkt->payload + sizeof(wifi_mgmt_hdr_t);
            int payload_len = ppkt->rx_ctrl.sig_len - sizeof(wifi_mgmt_hdr_t);
            
            for (int i = 0; i < payload_len - 2; i++) {
                if (payload[i] == 0) {
                    uint8_t ssid_len = payload[i + 1];
                    if (ssid_len > 0 && ssid_len < 33 && (i + 2 + ssid_len) <= payload_len) {
                        memcpy(tracked_devices[idx].ssid, &payload[i + 2], ssid_len);
                        tracked_devices[idx].ssid[ssid_len] = '\0';
                    }
                    break;
                }
            }
        }
        
        xSemaphoreGive(device_mutex);
    }
}

static void probe_scan_task(void *pvParameters) {
    ESP_LOGI(TAG, "Starting probe scan across all channels...");
    
    wifi_mode_t original_mode;
    esp_wifi_get_mode(&original_mode);
    
    ESP_LOGI(TAG, "Switching to STA mode for scanning...");
    esp_wifi_set_mode(WIFI_MODE_STA);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
    esp_wifi_set_promiscuous(true);
    
    scan_in_progress = true;
    
    for (int i = 0; i < num_channels && sniffer_running; i++) {
        ESP_LOGI(TAG, "Scanning channel %d...", scan_channels[i]);
        esp_wifi_set_channel(scan_channels[i], WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(300));
    }
    
    scan_in_progress = false;
    
    ESP_LOGI(TAG, "Scan complete. Restoring AP mode...");
    esp_wifi_set_promiscuous(false);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    esp_wifi_set_mode(original_mode);
    vTaskDelay(pdMS_TO_TICKS(200));
    
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    
    ESP_LOGI(TAG, "AP mode restored. Detected %d devices.", device_count);
    
    scan_task_handle = NULL;
    vTaskDelete(NULL);
}

void probe_sniffer_start(void) {
    if (scan_in_progress) {
        ESP_LOGW(TAG, "Scan already in progress");
        return;
    }
    
    if (device_mutex == NULL) {
        device_mutex = xSemaphoreCreateMutex();
    }
    
    sniffer_running = true;
    xTaskCreate(probe_scan_task, "probe_scan", 4096, NULL, 5, &scan_task_handle);
}

void probe_sniffer_stop(void) {
    if (!sniffer_running) {
        return;
    }
    
    sniffer_running = false;
    scan_in_progress = false;
    
    while (scan_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "Probe sniffer stopped");
}

bool is_probe_sniffer_running(void) {
    return scan_in_progress;
}

int probe_sniffer_get_devices(probe_device_t *devices, int max_devices) {
    if (!device_mutex) {
        return 0;
    }
    
    xSemaphoreTake(device_mutex, portMAX_DELAY);
    int count = device_count < max_devices ? device_count : max_devices;
    memcpy(devices, tracked_devices, count * sizeof(probe_device_t));
    xSemaphoreGive(device_mutex);
    
    return count;
}

void probe_sniffer_clear_devices(void) {
    if (!device_mutex) {
        return;
    }
    
    xSemaphoreTake(device_mutex, portMAX_DELAY);
    device_count = 0;
    memset(tracked_devices, 0, sizeof(tracked_devices));
    xSemaphoreGive(device_mutex);
    
    ESP_LOGI(TAG, "Device list cleared");
}

esp_err_t probe_sniffer_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Probe sniffer page requested");
    
    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "scan=1") != NULL) {
            probe_sniffer_start();
            
            const char *scanning_msg = 
            "<!DOCTYPE html><html><head><title>Scanning...</title>"
            "<meta http-equiv='refresh' content='5;url=/wifi_probes'>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #0a0f1c; color: #f5c542; padding: 20px; text-align: center; }"
            ".spinner { border: 8px solid #1a1f2c; border-top: 8px solid #f5c542; border-radius: 50%; width: 60px; height: 60px; animation: spin 1s linear infinite; margin: 20px auto; }"
            "@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }"
            "</style></head><body>"
            "<h1>&#x1F50D; Scanning for Probe Requests...</h1>"
            "<div class='spinner'></div>"
            "<p>Scanning all channels (1-13)...</p>"
            "<p>This takes about 4 seconds. AP will reconnect automatically.</p>"
            "<p>Please wait...</p>"
            "</body></html>";
            
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, scanning_msg, strlen(scanning_msg));
            return ESP_OK;
            
        } else if (strstr(query, "clear=1") != NULL) {
            probe_sniffer_clear_devices();
        }
    }
    
    bool is_scanning = is_probe_sniffer_running();
    
    probe_device_t devices[MAX_TRACKED_DEVICES];
    int count = probe_sniffer_get_devices(devices, MAX_TRACKED_DEVICES);
    
    size_t buf_size = 16384;
    char *page = malloc(buf_size);
    if (!page) {
        ESP_LOGE(TAG, "Failed to allocate memory for page");
        const char *error_msg = "<html><body><h1>Memory Error</h1></body></html>";
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, error_msg, strlen(error_msg));
        return ESP_FAIL;
    }
    
    const char *html_template = 
    "<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    "%s" // Placeholder for refresh meta tag
    "<title>Probe Request Sniffer</title>"
    "<style>"
    "body { background: #0a0f1c; color: #f5c542; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }"
    "h1 { text-align: center; color: #f5c542; }"
    ".status { padding: 15px; margin: 20px 0; border-radius: 8px; text-align: center; font-weight: bold; }"
    ".status.scanning { background: #ff8800; color: #000; }"
    ".status.ready { background: #44ff44; color: #0a0f1c; }"
    ".btn { display: inline-block; padding: 12px 20px; margin: 5px; background: #f5c542; color: #0a0f1c; text-decoration: none; font-weight: bold; border-radius: 8px; border: none; cursor: pointer; }"
    ".btn:hover { background: #d4a017; }"
    ".btn.danger { background: #ff4444; color: white; }"
    "table { width: 100%%; border-collapse: collapse; margin-top: 20px; }"
    "th, td { padding: 10px; border: 1px solid #f5c542; text-align: left; }"
    "th { background: #1a1f2c; color: #f5c542; }"
    "tr:nth-child(even) { background: #111111; }"
    ".info { background: #1a1f2c; padding: 15px; border-radius: 8px; margin: 20px 0; }"
    ".spinner { border: 4px solid #1a1f2c; border-top: 4px solid #f5c542; border-radius: 50%%; width: 30px; height: 30px; animation: spin 1s linear infinite; display: inline-block; vertical-align: middle; margin-left: 10px; }"
    "@keyframes spin { 0%% { transform: rotate(0deg); } 100%% { transform: rotate(360deg); } }"
    "</style>"
    "</head><body>"
    "<h1>&#x1F4E1; Probe Request Sniffer</h1>"
    "<div class='status %s'>%s</div>"
    "<div class='info'>%s</div>"
    "<div style='text-align: center;'>%s</div>"
    "<div class='info'>&#x1F4CA; <strong>Devices Detected:</strong> %d / %d</div>"
    "%s" // Placeholder for table or no-devices message
    "<div style='text-align: center; margin-top: 30px;'>"
    "<a href='/' class='btn'>&#x2B05; Back to Main Menu</a>"
    "</div></body></html>";
    
    char refresh[64];
    char status_class[16];
    char status_text[64];
    char info[256];
    char controls[256];
    char table[8192] = "";
    
    if (is_scanning) {
        snprintf(refresh, sizeof(refresh), "<meta http-equiv='refresh' content='2'>");
        snprintf(status_class, sizeof(status_class), "scanning");
        snprintf(status_text, sizeof(status_text), "&#x1F50D; SCANNING IN PROGRESS<div class='spinner'></div>");
        snprintf(info, sizeof(info), 
            "&#x23F3; Scanning all WiFi channels (1-13)... "
            "Your connection will briefly disconnect and reconnect automatically. "
            "Scan takes ~4 seconds.");
        snprintf(controls, sizeof(controls), 
            "<p style='color: #ff8800;'>&#x23F3; Please wait for scan to complete...</p>");
    } else {
        refresh[0] = '\0'; // Empty string, no snprintf needed
        snprintf(status_class, sizeof(status_class), "ready");
        snprintf(status_text, sizeof(status_text), "&#x2705; READY - AP Mode Active");
        snprintf(info, sizeof(info), 
            "&#x1F4E1; <strong>How it works:</strong> Click 'Start Scan' to temporarily "
            "switch to monitor mode, capture probe requests across all channels, then automatically "
            "restore the AP. You'll see devices searching for WiFi networks nearby.");
        snprintf(controls, sizeof(controls), 
            "<a href='/wifi_probes?scan=1' class='btn'>&#x1F50D; Start Scan (All Channels)</a>"
            "<a href='/wifi_probes?clear=1' class='btn danger'>&#x1F5D1; Clear List</a>");
    }
    
    int offset = 0;
    if (count > 0) {
        offset += snprintf(table + offset, sizeof(table) - offset,
            "<table><tr><th>MAC Address</th><th>SSID Searching</th><th>RSSI</th><th>Probe Count</th><th>Last Seen</th></tr>");
        
        uint32_t current_time = xTaskGetTickCount();
        
        for (int i = 0; i < count && offset < sizeof(table) - 512; i++) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                devices[i].mac[0], devices[i].mac[1], devices[i].mac[2],
                devices[i].mac[3], devices[i].mac[4], devices[i].mac[5]);
            
            const char *ssid_display = strlen(devices[i].ssid) > 0 ? 
                devices[i].ssid : "&lt;broadcast&gt;";
            
            uint32_t seconds_ago = (current_time - devices[i].last_seen) / 1000;
            char time_str[32];
            if (seconds_ago < 60) {
                snprintf(time_str, sizeof(time_str), "%lus ago", (unsigned long)seconds_ago);
            } else {
                snprintf(time_str, sizeof(time_str), "%lum ago", (unsigned long)(seconds_ago / 60));
            }
            
            offset += snprintf(table + offset, sizeof(table) - offset,
                "<tr><td>%s</td><td>%s</td><td>%d dBm</td><td>%u</td><td>%s</td></tr>",
                mac_str, ssid_display, devices[i].rssi, devices[i].count, time_str);
        }
        offset += snprintf(table + offset, sizeof(table) - offset, "</table>");
    } else {
        offset += snprintf(table + offset, sizeof(table) - offset,
            "<div class='info' style='text-align: center;'>"
            "&#x1F614; No devices detected yet. Click 'Start Scan' to capture probe requests."
            "</div>");
    }
    
    snprintf(page, buf_size, html_template, 
             refresh, status_class, status_text, info, controls, count, MAX_TRACKED_DEVICES, table);
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, page, strlen(page));
    free(page);
    
    return ESP_OK;
}