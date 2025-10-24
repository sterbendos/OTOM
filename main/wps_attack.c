/*
 * safe_wps_simulator.c
 *
 * SIMULATED WPS PIN "attack" — DOES NOT TRANSMIT OR BRUTE-FORCE ANY REAL DEVICE.
 *
 * Purpose: preserve UI, HTTP handler, and background-task behavior for development/testing.
 * IMPORTANT: This file is for simulation only.
 */

#include "wps_attack.h"
#include "wifi_scan.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "main.h"
#include "esp_http_server.h"
#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "WPS_SIM";

static wps_status_t wps_status = {0};
static SemaphoreHandle_t status_mutex = NULL;
static TaskHandle_t wps_task_handle = NULL;

/* Common WPS PINs to try (simulation) */
static const uint32_t common_pins[] = {
    12345670, 12345678, 00000000, 11111111, 22222222, 33333333,
    44444444, 55555555, 66666666, 77777777, 88888888, 99999999,
    12341234, 11223344, 55667788, 12121212, 98989898, 87654321
};
static const int common_pins_count = sizeof(common_pins) / sizeof(common_pins[0]);

/* Helper: safe string copy for SSID (ensure null termination) */
static void safe_strncpy(char *dst, const char *src, size_t dstlen) {
    if (dstlen == 0) return;
    strncpy(dst, src, dstlen - 1);
    dst[dstlen - 1] = '\0';
}

/* Simulated "attempt" — just logs and sleeps. Returns false always (no success). */
static bool simulated_try_pin(uint32_t pin) {
    ESP_LOGI(TAG, "SIMULATED: trying WPS PIN %08lu", pin);
    /* Simulate network/processing delay */
    vTaskDelay(pdMS_TO_TICKS(200));
    /* Always return false in simulation (no real success) */
    return false;
}

/* Background task that simulates trying common PINs then a simple brute-force progression.
   It updates wps_status fields so UI can display progress. */
static void wps_attack_task(void *pvParameters) {
    ESP_LOGI(TAG, "SIMULATED WPS PIN attack started (ssid=\"%s\")", wps_status.ssid);

    /* Try common pins first */
    for (int i = 0; i < common_pins_count; i++) {
        /* Check running flag under mutex */
        xSemaphoreTake(status_mutex, portMAX_DELAY);
        bool running = wps_status.running;
        xSemaphoreGive(status_mutex);
        if (!running) break;

        xSemaphoreTake(status_mutex, portMAX_DELAY);
        wps_status.current_pin = common_pins[i];
        wps_status.pins_tried++;
        xSemaphoreGive(status_mutex);

        simulated_try_pin(common_pins[i]);
    }

    /* Simulated brute force — iterate a subset for demo purpose to avoid long run in dev */
    /* We step by 1 but keep the range limited (e.g., 0..99999) for simulation */
    for (uint32_t pin = 0; pin < 100000 && wps_status.running; ++pin) {
        xSemaphoreTake(status_mutex, portMAX_DELAY);
        wps_status.current_pin = pin;
        wps_status.pins_tried++;
        xSemaphoreGive(status_mutex);

        if ((pin % 10000) == 0) {
            ESP_LOGI(TAG, "SIMULATED: tried %lu PINs so far", wps_status.pins_tried);
        }

        simulated_try_pin(pin);
    }

    /* End simulation */
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    wps_status.running = false;
    xSemaphoreGive(status_mutex);

    ESP_LOGI(TAG, "SIMULATED WPS attack finished (simulated). Pins tried: %lu", wps_status.pins_tried);

    wps_task_handle = NULL;
    vTaskDelete(NULL);
}

/* Public control functions (simulate behavior) */
void wps_attack_start(const uint8_t *ap_mac, uint8_t channel, const char *ssid) {
    if (status_mutex == NULL) {
        status_mutex = xSemaphoreCreateMutex();
        if (!status_mutex) {
            ESP_LOGE(TAG, "Failed to create status mutex");
            return;
        }
    }

    xSemaphoreTake(status_mutex, portMAX_DELAY);
    if (wps_status.running) {
        ESP_LOGW(TAG, "Simulated WPS attack already running");
        xSemaphoreGive(status_mutex);
        return;
    }

    memset(&wps_status, 0, sizeof(wps_status));
    if (ap_mac) memcpy(wps_status.ap_mac, ap_mac, 6);
    safe_strncpy(wps_status.ssid, ssid ? ssid : "", sizeof(wps_status.ssid));
    wps_status.channel = channel;
    wps_status.running = true;
    wps_status.pins_tried = 0;
    wps_status.current_pin = 0;
    xSemaphoreGive(status_mutex);

    xTaskCreate(wps_attack_task, "wps_task_sim", 4096, NULL, 5, &wps_task_handle);
}

void wps_attack_stop(void) {
    if (!status_mutex) {
        return;
    }

    xSemaphoreTake(status_mutex, portMAX_DELAY);
    if (!wps_status.running) {
        xSemaphoreGive(status_mutex);
        return;
    }
    wps_status.running = false;
    xSemaphoreGive(status_mutex);

    /* Wait for background task to stop */
    while (wps_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    ESP_LOGI(TAG, "Simulated WPS attack stopped (stop called)");
}

bool wps_is_running(void) {
    bool running = false;
    if (!status_mutex) return false;
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    running = wps_status.running;
    xSemaphoreGive(status_mutex);
    return running;
}

void wps_get_status(wps_status_t *status) {
    if (!status_mutex || !status) return;
    xSemaphoreTake(status_mutex, portMAX_DELAY);
    memcpy(status, &wps_status, sizeof(wps_status_t));
    xSemaphoreGive(status_mutex);
}

/* HTTP handler: serves UI and accepts start/stop requests.
   Uses the same UI structure as your original, fixed and completed. */
esp_err_t wps_attack_handler(httpd_req_t *req) {
    stop_all_tools(); /* preserve app behavior */

    char query[512] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            wps_attack_stop();

            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_wps'>"
                "<style>body{background:#0a0f1c;color:#f5c542;text-align:center;padding:50px;}</style>"
                "</head><body><h1>✅ Simulation Stopped</h1></body></html>";

            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }

        if (strstr(query, "start=1")) {
            uint8_t ap_mac[6] = {0};
            uint8_t channel = 1;
            char ssid[33] = "";

            char *ap_param = strstr(query, "ap=");
            char *ch_param = strstr(query, "channel=");
            char *ssid_param = strstr(query, "ssid=");

            if (ap_param) {
                sscanf(ap_param + 3, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                       &ap_mac[0], &ap_mac[1], &ap_mac[2],
                       &ap_mac[3], &ap_mac[4], &ap_mac[5]);
            }
            if (ch_param) channel = (uint8_t)atoi(ch_param + 8);
            if (ssid_param) {
                int i = 0, j = 0;
                char *s = ssid_param + 5;
                while (s[i] && j < 32 && s[i] != '&') {
                    if (s[i] == '+') ssid[j++] = ' ';
                    else ssid[j++] = s[i];
                    i++;
                }
                ssid[j] = '\0';
            }

            wps_attack_start(ap_mac, channel, ssid);

            const char *resp = "<!DOCTYPE html><html><head>"
                "<meta http-equiv='refresh' content='1;url=/wifi_wps'>"
                "<style>body{background:#0a0f1c;color:#f5c542;text-align:center;padding:50px;}</style>"
                "</head><body><h1>⚡ Simulation Started</h1></body></html>";

            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
    }

    /* Generate UI page */
    bool is_running = wps_is_running();
    wps_status_t status;
    wps_get_status(&status);

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
        "<title>WPS Attack (Simulation)</title><style>"
        "body{background:#0a0f1c;color:#f5c542;font-family:sans-serif;margin:0;padding:20px;}"
        "h1,h2{text-align:center;color:#f5c542;}h2{border-bottom:2px solid #f5c542;padding-bottom:5px;}"
        ".container{max-width:900px;margin:0 auto;}"
        ".status{padding:15px;margin:20px 0;border-radius:8px;text-align:center;font-weight:bold;}"
        ".status.running{background:#ff8800;color:#000;}.status.stopped{background:#44ff44;color:#0a0f1c;}"
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
        ".stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:20px 0;}"
        ".stat-box{background:#1a1f2c;padding:15px;border-radius:8px;text-align:center;}"
        ".stat-value{font-size:2em;font-weight:bold;color:#f5c542;}"
        "</style>"
        "<script>function selectAP(b,c,s){document.getElementById('ap').value=b;"
        "document.getElementById('channel').value=c;document.getElementById('ssid').value=s;}</script>"
        "</head><body><div class='container'>"
        "<h1>🔓 WPS PIN (SIMULATION)</h1>",
        auto_refresh);

    if (is_running) {
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='status running'>🟠 SIMULATION IN PROGRESS</div>"
            "<div class='stats'>"
            "<div class='stat-box'><div class='stat-value'>%lu</div><div>PINs Tried</div></div>"
            "<div class='stat-box'><div class='stat-value'>%08lu</div><div>Current PIN</div></div>"
            "</div>"
            "<div class='info'><strong>Target:</strong> %s (%02X:%02X:%02X:%02X:%02X:%02X)</div>"
            "<div class='control'><a href='/wifi_wps?stop=1' class='btn danger full'>⏹ Stop Simulation</a></div>",
            status.pins_tried, status.current_pin,
            status.ssid[0] ? status.ssid : "unknown",
            status.ap_mac[0], status.ap_mac[1], status.ap_mac[2],
            status.ap_mac[3], status.ap_mac[4], status.ap_mac[5]);
    } else {
        offset += snprintf(page + offset, 32768 - offset,
            "<div class='status stopped'>🟢 Ready (Simulation)</div>"
            "<div class='info'><strong>ℹ️ About this Simulation:</strong> "
            "This simulates trying common WPS PINs and a small brute-force sweep for testing the UI. "
            "No frames are sent and no devices are targeted.</div>"
            "<div class='control'><h2>Start Simulation</h2>"
            "<form action='/wifi_wps' method='get'>"
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
            "<input type='hidden' name='start' value='1'>"
            "<button type='submit' class='btn full'>▶ Start Simulation</button></form></div>");
    }

    if (!is_running && scan_count > 0) {
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
                "<tr onclick=\"selectAP('%s',%d,'%s')\"><td>%s</td><td>%c%c:%c%c:%c%c:%c%c:%c%c:%c%c</td><td>%d</td><td>%d</td></tr>",
                bssid, scan_results[i].ap.primary, ssid_str, ssid_str,
                bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5],
                bssid[6],bssid[7],bssid[8],bssid[9],bssid[10],bssid[11],
                scan_results[i].ap.primary, scan_results[i].ap.rssi);
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
