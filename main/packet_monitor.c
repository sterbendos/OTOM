#include "packet_monitor.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "main.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "PACKET_MONITOR";
static bool monitoring = false;

typedef struct {
    int mgmt_count;
    int ctrl_count;
    int data_count;
} packet_stats_t;
static packet_stats_t stats = {0};

#define MAX_PKTS 20
typedef struct {
    wifi_promiscuous_pkt_type_t type;
    int rssi;
    uint32_t timestamp;
} recent_pkt_t;
static recent_pkt_t recent_pkts[MAX_PKTS];
static int pkt_index = 0;

static void pkt_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!monitoring) return;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    
    switch (type) {
        case WIFI_PKT_MGMT: stats.mgmt_count++; break;
        case WIFI_PKT_CTRL: stats.ctrl_count++; break;
        case WIFI_PKT_DATA: stats.data_count++; break;
        default: break;
    }
    
    recent_pkts[pkt_index].type = type;
    recent_pkts[pkt_index].rssi = pkt->rx_ctrl.rssi;
    recent_pkts[pkt_index].timestamp = esp_log_timestamp();
    pkt_index = (pkt_index + 1) % MAX_PKTS;
}

void packet_monitor_start(uint8_t channel) {
    if (monitoring) {
        ESP_LOGW(TAG, "Monitor already running");
        return;
    }
    
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL };
    esp_wifi_set_promiscuous_filter(&filter);
    
    esp_wifi_set_promiscuous_rx_cb(&pkt_rx_cb);
    esp_wifi_set_promiscuous(true);
    monitoring = true;
    
    stats.mgmt_count = 0;
    stats.ctrl_count = 0;
    stats.data_count = 0;
    pkt_index = 0;
    memset(recent_pkts, 0xFF, sizeof(recent_pkts));
    
    ESP_LOGI(TAG, "Packet monitor started on channel %d", channel);
}

void packet_monitor_stop(void) {
    if (!monitoring) return;
    esp_wifi_set_promiscuous(false);
    monitoring = false;
    ESP_LOGI(TAG, "Packet monitor stopped");
}

esp_err_t packet_monitor_handler(httpd_req_t *req) {
    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            packet_monitor_stop();
        } else if (strstr(query, "start=1")) {
            char *channel_param = strstr(query, "channel=");
            uint8_t channel = 1;
            if (channel_param) {
                channel = atoi(channel_param + 8);
                if (channel < 1 || channel > 13) channel = 1;
            }
            packet_monitor_start(channel);
        }
    }
    
    char pkt_rows[2048] = "";
    int row_offset = 0;
    for (int i = 0; i < MAX_PKTS && row_offset < 1900; i++) {
        int idx = (pkt_index - 1 - i + MAX_PKTS) % MAX_PKTS;
        if (recent_pkts[idx].type != 0xFF) {
            const char *type_str = "UNKNOWN";
            if (recent_pkts[idx].type == WIFI_PKT_MGMT) type_str = "MGMT";
            else if (recent_pkts[idx].type == WIFI_PKT_CTRL) type_str = "CTRL";
            else if (recent_pkts[idx].type == WIFI_PKT_DATA) type_str = "DATA";
            
            row_offset += snprintf(pkt_rows + row_offset, sizeof(pkt_rows) - row_offset,
                "<tr><td>%s</td><td>%d dBm</td><td>%" PRIu32 "</td></tr>",
                type_str, recent_pkts[idx].rssi, recent_pkts[idx].timestamp);
        }
    }
    
    const char *html_template = 
    "<!DOCTYPE html>"
    "<html>"
    "<head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    "%s"
    "<title>Packet Monitor</title>"
    "<style>"
    "body { background: #0a0f1c; color: #f5c542; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }"
    "h1 { text-align: center; color: #f5c542; }"
    ".container { max-width: 800px; margin: 0 auto; }"
    ".status { padding: 15px; margin: 20px 0; border-radius: 8px; text-align: center; font-weight: bold; }"
    ".status.running { background: #ff4444; color: white; }"
    ".status.stopped { background: #44ff44; color: #0a0f1c; }"
    ".control { margin: 20px 0; background: #1a1f2c; padding: 20px; border-radius: 8px; }"
    "label { display: block; margin: 10px 0 5px; font-weight: bold; }"
    "select { width: 100%; padding: 10px; border-radius: 5px; border: 2px solid #f5c542; background: #0a0f1c; color: #f5c542; margin-bottom: 15px; }"
    ".btn { display: inline-block; padding: 12px 20px; margin: 10px 0; background: #f5c542; color: #0a0f1c; text-decoration: none; font-weight: bold; border-radius: 8px; border: none; cursor: pointer; width: 100%; box-sizing: border-box; }"
    ".btn:hover { background: #d4a017; }"
    ".btn.danger { background: #ff4444; color: white; }"
    "table { width: 100%; border-collapse: collapse; margin-top: 20px; }"
    "th, td { padding: 10px; border: 1px solid #f5c542; text-align: left; }"
    "th { background: #1a1f2c; color: #f5c542; }"
    "tr:nth-child(even) { background: #111111; }"
    ".stats-table { margin: 20px 0; }"
    "</style>"
    "</head>"
    "<body>"
    "<div class='container'>"
    "<h1>&#x1F4E1; Packet Monitor</h1>"
    "<div class='status %s'>%s</div>"
    "<div class='control'>"
    "%s"
    "</div>"
    "<h3>&#x1F4CA; Packet Statistics</h3>"
    "<table class='stats-table'>"
    "<tr><th>Management</th><th>Control</th><th>Data</th></tr>"
    "<tr><td>%d</td><td>%d</td><td>%d</td></tr>"
    "</table>"
    "<h3>&#x1F98B; Recent Packets</h3>"
    "<table><tr><th>Type</th><th>RSSI</th><th>Timestamp</th></tr>%s</table>"
    "<div style='text-align: center; margin-top: 30px;'>"
    "<a href='/' class='btn'>&#x2B05; Back to Main Menu</a>"
    "</div>"
    "</div>"
    "</body>"
    "</html>";
    
    const char *auto_refresh = monitoring ? "<meta http-equiv='refresh' content='2'>" : "";
    const char *status_class = monitoring ? "running" : "stopped";
    const char *status_text = monitoring ? "&#x1F534; MONITORING ACTIVE" : "&#x1F7E2; Monitor Stopped";
    
    const char *controls = monitoring ?
        "<a href='/wifi_packets?stop=1' class='btn danger'>&#x23F9; Stop Monitor</a>" :
        "<form action='/wifi_packets' method='get'>"
        "<label>WiFi Channel (1-13):</label>"
        "<select name='channel'>"
        "<option value='1'>Channel 1</option>"
        "<option value='6' selected>Channel 6</option>"
        "<option value='11'>Channel 11</option>"
        "<option value='2'>Channel 2</option><option value='3'>Channel 3</option>"
        "<option value='4'>Channel 4</option><option value='5'>Channel 5</option>"
        "<option value='7'>Channel 7</option><option value='8'>Channel 8</option>"
        "<option value='9'>Channel 9</option><option value='10'>Channel 10</option>"
        "<option value='12'>Channel 12</option><option value='13'>Channel 13</option>"
        "</select>"
        "<input type='hidden' name='start' value='1'>"
        "<button type='submit' class='btn'>&#x25B6; Start Monitor</button>"
        "</form>";
    
    char *response = malloc(8192);
    if (!response) {
        ESP_LOGE(TAG, "Failed to allocate response buffer");
        const char *error_msg = "<html><body><h1>Memory Error</h1></body></html>";
        httpd_resp_send(req, error_msg, strlen(error_msg));
        return ESP_FAIL;
    }
    
    snprintf(response, 8192, html_template, 
             auto_refresh, status_class, status_text, controls,
             stats.mgmt_count, stats.ctrl_count, stats.data_count, pkt_rows);
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, response, strlen(response));
    free(response);
    return ESP_OK;
}