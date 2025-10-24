#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "main.h"
#include "esp_netif.h"
#include "esp_event.h"
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "frame_analyzer.h"

static const char *TAG = "WiFiScan";

#define MAX_CLIENTS_PER_AP 20
#define CLIENT_TIMEOUT_MS 30000

static ap_with_clients_t scan_results[DEFAULT_SCAN_LIST_SIZE];
static int scan_result_count = 0;
static bool deep_scan_active = false;
static SemaphoreHandle_t scan_mutex = NULL;

const char *html_header =
"<!DOCTYPE html>"
"<html>"
"<head>"
"    <title>ESP32S3 Wi-Fi Recon</title>"
"    <meta name='viewport' content='width=device-width, initial-scale=1'>"
"    <style>"
"        body { font-family: Arial, sans-serif; background: #000000; color: #FFD600; margin: 0; padding: 20px; }"
"        h1 { color: #FFD600; text-align: center; }"
"        table { width: 100%; border-collapse: collapse; margin-top: 20px; }"
"        th, td { padding: 8px 12px; border: 1px solid #FFD600; text-align: left; }"
"        th { background: #1a1a1a; color: #FFD600; }"
"        tr:nth-child(even) { background: #111111; }"
"        .btn { display: inline-block; padding: 10px 16px; margin: 10px 5px;"
"               background: #FFD600; color: #000000; text-decoration: none; border-radius: 5px; }"
"        .btn:hover { background: #FFC107; }"
"        .btn.danger { background: #ff4444; color: white; }"
"        .info { background: #1a1a1a; padding: 10px; border-radius: 5px; margin: 10px 0; }"
"        .clients { font-size: 0.85em; color: #FFC107; margin-top: 5px; }"
"        .expandable { cursor: pointer; user-select: none; }"
"        .client-list { display: none; margin-top: 10px; padding: 10px; background: #0a0a0a; border-radius: 5px; }"
"        .client-list.show { display: block; }"
"    </style>"
"    <script>"
"    function toggleClients(id) {"
"        var el = document.getElementById('clients-' + id);"
"        el.classList.toggle('show');"
"    }"
"    </script>"
"</head>"
"<body>";

const char *html_footer =
"<a href='/' class='btn'>⬅ Back to Main Menu</a>"
"</body></html>";

static void client_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    mgmt_header_t *hdr = (mgmt_header_t *)pkt->payload;

    if (!scan_mutex) return;
    xSemaphoreTake(scan_mutex, portMAX_DELAY);

    for (int i = 0; i < scan_result_count; i++) {
        if (memcmp(hdr->addr3, scan_results[i].ap.bssid, 6) == 0) {
            uint8_t *client_mac = NULL;

            if (hdr->frame_ctrl.to_ds && !hdr->frame_ctrl.from_ds) {
                client_mac = hdr->addr2;
            } else if (!hdr->frame_ctrl.to_ds && hdr->frame_ctrl.from_ds) {
                client_mac = hdr->addr1;
            }

            if (client_mac && memcmp(client_mac, "\xff\xff\xff\xff\xff\xff", 6) != 0) {
                bool found = false;
                for (int j = 0; j < scan_results[i].client_count; j++) {
                    if (memcmp(scan_results[i].clients[j].mac, client_mac, 6) == 0) {
                        scan_results[i].clients[j].rssi = pkt->rx_ctrl.rssi;
                        scan_results[i].clients[j].last_seen = xTaskGetTickCount();
                        found = true;
                        break;
                    }
                }

                if (!found && scan_results[i].client_count < MAX_CLIENTS_PER_AP) {
                    memcpy(scan_results[i].clients[scan_results[i].client_count].mac, client_mac, 6);
                    scan_results[i].clients[scan_results[i].client_count].rssi = pkt->rx_ctrl.rssi;
                    scan_results[i].clients[scan_results[i].client_count].last_seen = xTaskGetTickCount();
                    scan_results[i].client_count++;
                }
            }
            break;
        }
    }

    xSemaphoreGive(scan_mutex);
}

static void deep_scan_task(void *pvParameter) {
    ESP_LOGI(TAG, "Starting deep scan for clients...");

    esp_wifi_set_promiscuous_rx_cb(client_sniffer_cb);
    esp_wifi_set_promiscuous(true);

    for (int i = 1; i <= 13 && deep_scan_active; i++) {
        esp_wifi_set_channel(i, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    esp_wifi_set_promiscuous(false);
    deep_scan_active = false;
    ESP_LOGI(TAG, "Deep scan completed");

    vTaskDelete(NULL);
}

char *wifi_scan_html(bool deep_scan) {
    if (!scan_mutex) {
        scan_mutex = xSemaphoreCreateMutex();
    }

    uint16_t number = DEFAULT_SCAN_LIST_SIZE;
    wifi_ap_record_t ap_info[DEFAULT_SCAN_LIST_SIZE];
    uint16_t ap_count = 0;
    memset(ap_info, 0, sizeof(ap_info));

    ESP_LOGI(TAG, "Starting WiFi scan...");

    wifi_mode_t current_mode;
    esp_wifi_get_mode(&current_mode);
    ESP_LOGI(TAG, "Current WiFi mode: %d", current_mode);

    esp_wifi_scan_stop();
    vTaskDelay(pdMS_TO_TICKS(100));

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {
            .active = {
                .min = 120,
                .max = 150
            }
        }
    };

    ESP_LOGI(TAG, "Starting scan with config...");
    esp_err_t scan_result = esp_wifi_scan_start(&scan_config, true);
    if (scan_result != ESP_OK) {
        ESP_LOGE(TAG, "WiFi scan start failed: %s", esp_err_to_name(scan_result));
        return NULL;
    }

    vTaskDelay(pdMS_TO_TICKS(500));

    esp_wifi_scan_get_ap_records(&number, ap_info);
    esp_wifi_scan_get_ap_num(&ap_count);

    ESP_LOGI(TAG, "Total APs scanned = %u", number);

    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    scan_result_count = number;
    for (int i = 0; i < number; i++) {
        scan_results[i].ap = ap_info[i];
        scan_results[i].client_count = 0;
    }
    xSemaphoreGive(scan_mutex);

    if (deep_scan && !deep_scan_active) {
        deep_scan_active = true;
        xTaskCreate(deep_scan_task, "deep_scan", 4096, NULL, 5, NULL);
        vTaskDelay(pdMS_TO_TICKS(7000));
    }

    size_t buf_size = 32768;
    char *page = malloc(buf_size);
    if (!page) {
        ESP_LOGE(TAG, "Failed to allocate memory for HTML page");
        return NULL;
    }
    memset(page, 0, buf_size);

    strcpy(page, html_header);
    strcat(page, "<h1>📡 Wi-Fi Recon (ESP32S3)</h1>");

    char info_section[512];
    sprintf(info_section,
        "<div class='info'>📊 <strong>Scan Results:</strong> %u networks found</div>",
        number);
    strcat(page, info_section);

    strcat(page, "<a href='/scan?deep=1' class='btn'>🔍 Deep Scan (with clients)</a>");
    strcat(page, "<a href='/scan' class='btn'>🔄 Quick Rescan</a>");
    strcat(page, "<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Auth</th><th>Clients</th></tr>");

    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    for (int i = 0; i < number; i++) {
        char row[1024];
        char bssid[18];
        sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X",
            scan_results[i].ap.bssid[0], scan_results[i].ap.bssid[1], scan_results[i].ap.bssid[2],
            scan_results[i].ap.bssid[3], scan_results[i].ap.bssid[4], scan_results[i].ap.bssid[5]);

        const char *auth;
        switch (scan_results[i].ap.authmode) {
            case WIFI_AUTH_OPEN: auth = "OPEN"; break;
            case WIFI_AUTH_WEP: auth = "WEP"; break;
            case WIFI_AUTH_WPA_PSK: auth = "WPA-PSK"; break;
            case WIFI_AUTH_WPA2_PSK: auth = "WPA2-PSK"; break;
            case WIFI_AUTH_WPA_WPA2_PSK: auth = "WPA/WPA2-PSK"; break;
            case WIFI_AUTH_WPA3_PSK: auth = "WPA3-PSK"; break;
            case WIFI_AUTH_WPA2_WPA3_PSK: auth = "WPA2/WPA3-PSK"; break;
            case WIFI_AUTH_WAPI_PSK: auth = "WAPI-PSK"; break;
            default: auth = "UNKNOWN"; break;
        }

        char client_info[512] = "";
        if (scan_results[i].client_count > 0) {
            sprintf(client_info,
                "<span class='expandable' onclick='toggleClients(%d)'>👥 %d client(s)</span>"
                "<div id='clients-%d' class='client-list'>",
                i, scan_results[i].client_count, i);

            for (int j = 0; j < scan_results[i].client_count; j++) {
                char client_mac[64];
                sprintf(client_mac, "📱 %02X:%02X:%02X:%02X:%02X:%02X (%d dBm)<br>",
                    scan_results[i].clients[j].mac[0], scan_results[i].clients[j].mac[1],
                    scan_results[i].clients[j].mac[2], scan_results[i].clients[j].mac[3],
                    scan_results[i].clients[j].mac[4], scan_results[i].clients[j].mac[5],
                    scan_results[i].clients[j].rssi);
                strcat(client_info, client_mac);
            }
            strcat(client_info, "</div>");
        } else {
            strcpy(client_info, "-");
        }

        sprintf(row,
            "<tr><td>%s</td><td>%s</td><td>%d</td><td>%d dBm</td><td>%s</td><td>%s</td></tr>",
            strlen((char *)scan_results[i].ap.ssid) > 0 ? (char *)scan_results[i].ap.ssid : "<hidden>",
            bssid,
            scan_results[i].ap.primary,
            scan_results[i].ap.rssi,
            auth,
            client_info);
        strcat(page, row);
    }
    xSemaphoreGive(scan_mutex);

    strcat(page, "</table>");
    strcat(page, html_footer);

    ESP_LOGI(TAG, "HTML page generated successfully");
    return page;
}

int wifi_scan_get_results(ap_with_clients_t *results, int max_count) {
    if (!scan_mutex) return 0;

    xSemaphoreTake(scan_mutex, portMAX_DELAY);
    int count = scan_result_count < max_count ? scan_result_count : max_count;
    memcpy(results, scan_results, count * sizeof(ap_with_clients_t));
    xSemaphoreGive(scan_mutex);

    return count;
}
