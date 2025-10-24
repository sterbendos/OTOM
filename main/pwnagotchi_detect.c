#include "pwnagotchi_detect.h"
#include "main.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "PWNAGOTCHI";
static TaskHandle_t pwnagotchi_task_handle = NULL;
static bool detect_running = false;
static uint8_t detect_channel = 1;

#define MAX_PWNAGOTCHIS 10
typedef struct {
    uint8_t mac[6];
    uint32_t deauth_count;
    uint32_t last_seen;
} pwnagotchi_t;
static pwnagotchi_t pwnagotchis[MAX_PWNAGOTCHIS];
static int pwnagotchi_count = 0;

static void promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT || !detect_running) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *data = pkt->payload;
    if (data[0] == 0xc0 || data[0] == 0xa0) { // Deauth or Disassoc frame
        uint8_t *src_mac = &data[10];
        for (int i = 0; i < pwnagotchi_count; i++) {
            if (memcmp(pwnagotchis[i].mac, src_mac, 6) == 0) {
                pwnagotchis[i].deauth_count++;
                pwnagotchis[i].last_seen = esp_log_timestamp();
                ESP_LOGI(TAG, "Pwnagotchi %02X:%02X:%02X:%02X:%02X:%02X updated, deauths: %" PRIu32,
                         src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
                         pwnagotchis[i].deauth_count);
                return;
            }
        }
        if (pwnagotchi_count < MAX_PWNAGOTCHIS) {
            memcpy(pwnagotchis[pwnagotchi_count].mac, src_mac, 6);
            pwnagotchis[pwnagotchi_count].deauth_count = 1;
            pwnagotchis[pwnagotchi_count].last_seen = esp_log_timestamp();
            ESP_LOGI(TAG, "New Pwnagotchi detected: %02X:%02X:%02X:%02X:%02X:%02X",
                     src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
            pwnagotchi_count++;
        }
    }
}

static void pwnagotchi_task(void *pvParameters) {
    ESP_LOGI(TAG, "Pwnagotchi detection started on channel %d", detect_channel);
    esp_wifi_set_promiscuous_rx_cb(&promiscuous_cb);
    esp_wifi_set_promiscuous(true);
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_channel(detect_channel, WIFI_SECOND_CHAN_NONE);
    
    while (detect_running) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    
    esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "Pwnagotchi detection stopped");
    pwnagotchi_task_handle = NULL;
    vTaskDelete(NULL);
}

void pwnagotchi_detect_start(void) {
    if (detect_running) {
        ESP_LOGW(TAG, "Pwnagotchi detection already running");
        return;
    }
    detect_running = true;
    xTaskCreate(pwnagotchi_task, "pwnagotchi_task", 4096, NULL, 5, &pwnagotchi_task_handle);
}

void pwnagotchi_detect_stop(void) {
    if (!detect_running) return;
    detect_running = false;
    while (pwnagotchi_task_handle != NULL) vTaskDelay(pdMS_TO_TICKS(100));
    esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "Pwnagotchi detection terminated");
}

esp_err_t pwnagotchi_detect_handler(httpd_req_t *req) {
    stop_all_tools();
    ESP_LOGI(TAG, "Pwnagotchi detection page requested");
    
    char query[256];
    char response[4096];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            pwnagotchi_detect_stop();
            snprintf(response, sizeof(response),
                "<!DOCTYPE html><html><head><title>Pwnagotchi Detection Stopped</title>"
                "<meta http-equiv='refresh' content='2;url=/wifi_pwn'>"
                "<style>"
                "body { font-family: Arial, sans-serif; background: #0a0f1c; color: #f5c542; padding: 20px; text-align: center; }"
                "</style></head><body>"
                "<h1>✓ Pwnagotchi Detection Stopped</h1>"
                "<p>Redirecting...</p>"
                "</body></html>");
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, response, strlen(response));
            return ESP_OK;
        }
        
        if (strstr(query, "start=1")) {
            char *channel_param = strstr(query, "channel=");
            if (channel_param) detect_channel = atoi(channel_param + 8);
            if (detect_channel < 1 || detect_channel > 13) detect_channel = 1;
            pwnagotchi_detect_start();
            snprintf(response, sizeof(response),
                "<!DOCTYPE html><html><head><title>Pwnagotchi Detection Started</title>"
                "<meta http-equiv='refresh' content='2;url=/wifi_pwn'>"
                "<style>"
                "body { font-family: Arial, sans-serif; background: #0a0f1c; color: #f5c542; padding: 20px; text-align: center; }"
                "</style></head><body>"
                "<h1>⚡ Pwnagotchi Detection Started</h1>"
                "<p>Running on channel %d...</p>"
                "<p>Redirecting...</p>"
                "</body></html>", detect_channel);
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, response, strlen(response));
            return ESP_OK;
        }
    }
    
    char pwnagotchi_rows[1024] = "";
    for (int i = 0; i < pwnagotchi_count; i++) {
        char row[256];
        snprintf(row, sizeof(row), "<tr><td>%02X:%02X:%02X:%02X:%02X:%02X</td><td>%" PRIu32 "</td><td>%" PRIu32 "</td></tr>",
                 pwnagotchis[i].mac[0], pwnagotchis[i].mac[1], pwnagotchis[i].mac[2],
                 pwnagotchis[i].mac[3], pwnagotchis[i].mac[4], pwnagotchis[i].mac[5],
                 pwnagotchis[i].deauth_count, pwnagotchis[i].last_seen);
        strcat(pwnagotchi_rows, row);
    }
    
    snprintf(response, sizeof(response),
        "<!DOCTYPE html>"
        "<html lang='en'>"
        "<head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        "<title>Pwnagotchi Detection</title>"
        "<style>"
        "body { background: #0a0f1c; color: #f5c542; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }"
        "h1 { text-align: center; color: #f5c542; }"
        ".container { max-width: 600px; margin: 0 auto; }"
        ".status { padding: 15px; margin: 20px 0; border-radius: 8px; text-align: center; font-weight: bold; }"
        ".status.running { background: #ff4444; color: white; }"
        ".status.stopped { background: #44ff44; color: #0a0f1c; }"
        ".control { margin: 20px 0; }"
        "label { display: block; margin: 10px 0 5px; }"
        "select { width: 100%%; padding: 10px; border-radius: 5px; border: 2px solid #f5c542; background: #1a1f2c; color: #f5c542; }"
        ".btn { display: inline-block; padding: 12px 20px; margin: 10px 5px; background: #f5c542; color: #0a0f1c; text-decoration: none; font-weight: bold; border-radius: 8px; border: none; cursor: pointer; }"
        ".btn:hover { background: #d4a017; }"
        ".btn.danger { background: #ff4444; color: white; }"
        "table { width: 100%%; border-collapse: collapse; }"
        "th, td { padding: 8px; border: 1px solid #f5c542; }"
        "</style>"
        "</head>"
        "<body>"
        "<div class='container'>"
        "<h1>🔍 Pwnagotchi Detection</h1>"
        "<div class='status %s'>%s</div>"
        "<div class='control'>"
        "%s"
        "</div>"
        "<table>"
        "<tr><th>MAC</th><th>Deauth Count</th><th>Last Seen</th></tr>"
        "%s"
        "</table>"
        "<div style='text-align: center; margin-top: 30px;'>"
        "<a href='/' class='btn'>⬅ Back to Main Menu</a>"
        "</div>"
        "</div>"
        "</body>"
        "</html>",
        detect_running ? "running" : "stopped",
        detect_running ? "🔴 DETECTION ACTIVE" : "🟢 Detection Stopped",
        detect_running ?
            "<a href='/wifi_pwn?stop=1' class='btn danger' style='width: 100%%; text-align: center;'>⏹ Stop Detection</a>" :
            "<form action='/wifi_pwn' method='get'>"
            "<label>WiFi Channel (1-13):</label>"
            "<select name='channel'>"
            "<option value='1'>Channel 1</option><option value='6'>Channel 6</option><option value='11'>Channel 11</option>"
            "<option value='2'>Channel 2</option><option value='3'>Channel 3</option><option value='4'>Channel 4</option>"
            "<option value='5'>Channel 5</option><option value='7'>Channel 7</option><option value='8'>Channel 8</option>"
            "<option value='9'>Channel 9</option><option value='10'>Channel 10</option><option value='12'>Channel 12</option>"
            "<option value='13'>Channel 13</option>"
            "</select>"
            "<input type='hidden' name='start' value='1'>"
            "<button type='submit' class='btn' style='width: 100%%; margin-top: 15px;'>▶ Start Detection</button>"
            "</form>",
        pwnagotchi_rows);
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, response, strlen(response));
    return ESP_OK;
}