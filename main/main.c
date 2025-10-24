#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include <string.h>
#include "wifi_scan.h"
#include "beacon_spam.h"
#include "deauth_attack.h"
#include "probe_sniffer.h"
#include "packet_monitor.h"
#include "rogue_ap.h"
#include "evil_portal.h"
#include "pwnagotchi_detect.h"
#include "attack_pmkid.h"
#include "attack_handshake.h"
#include "attack_dos.h"
#include "wps_attack.h"

#define WIFI_SSID "OTOM"
#define WIFI_PASS "SHARDS123@a"

static const char *TAG = "OTOM_AP";

void stop_all_tools(void) {
    deauth_attack_stop();
    packet_monitor_stop();
    probe_sniffer_stop();
    rogue_ap_stop();
    pwnagotchi_detect_stop();
    beacon_spam_stop();
    pmkid_attack_stop();
    handshake_attack_stop();
    dos_attack_stop();
    wps_attack_stop();
    ESP_LOGI(TAG, "All tools stopped");
}

void init_ap(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = WIFI_SSID,
            .ssid_len = strlen(WIFI_SSID),
            .channel = 1,
            .password = WIFI_PASS,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK
        },
    };

    if (strlen(WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "ESP32S3 AP started. SSID:%s Password:%s", WIFI_SSID, WIFI_PASS);
}

esp_err_t otm_get_handler(httpd_req_t *req) {
    const char* html_content = 
    "<!DOCTYPE html>"
    "<html lang='en'>"
    "<head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    "<title>OTOM Marauder</title>"
    "<style>"
    "body { background: #0a0f1c; color: #f5c542; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }"
    "h1 { text-align: center; font-size: 2.5rem; color: #f5c542; margin-bottom: 20px; }"
    ".category { margin: 30px 0; }"
    ".category h2 { color: #f5c542; border-bottom: 2px solid #f5c542; padding-bottom: 5px; }"
    ".btn { display: inline-block; padding: 12px 20px; margin: 8px; background: #f5c542; color: #0a0f1c; text-decoration: none; font-weight: bold; border-radius: 8px; transition: background 0.3s; }"
    ".btn:hover { background: #d4a017; }"
    "</style>"
    "</head>"
    "<body>"
    "<h1>⚡ OTOM Marauder ESP32S3</h1>"
    "<div class='category'>"
    "<h2>📡 Wi-Fi Reconnaissance</h2>"
    "<a href='/wifi_scan' class='btn'>Scan Networks</a>"
    "<a href='/wifi_probes' class='btn'>Probe Sniffer</a>"
    "<a href='/wifi_packets' class='btn'>Packet Monitor</a>"
    "</div>"
    "<div class='category'>"
    "<h2>⚔️ Wi-Fi Attacks</h2>"
    "<a href='/wifi_deauth' class='btn'>Deauth Attack</a>"
    "<a href='/wifi_pmkid' class='btn'>PMKID Capture</a>"
    "<a href='/wifi_handshake' class='btn'>Handshake Capture</a>"
    "<a href='/wifi_dos' class='btn'>DoS Attack</a>"
    "<a href='/wifi_wps' class='btn'>WPS Attack</a>"
    "</div>"
    "<div class='category'>"
    "<h2>🎭 Deception</h2>"
    "<a href='/wifi_beacon' class='btn'>Beacon Spam</a>"
    "<a href='/wifi_rogue' class='btn'>Rogue AP</a>"
    "<a href='/wifi_evil' class='btn'>Evil Portal</a>"
    "</div>"
    "<div class='category'>"
    "<h2>🤖 Detection</h2>"
    "<a href='/wifi_pwn' class='btn'>Pwnagotchi Detect</a>"
    "</div>"
    "</body></html>";

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, html_content, strlen(html_content));
    return ESP_OK;
}

esp_err_t wifi_scan_handler(httpd_req_t *req) {
    // DON'T stop all tools - let scan run independently
    ESP_LOGI(TAG, "WiFi scan requested");
    
    bool deep_scan = false;
    char query[64];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "deep=1")) {
            deep_scan = true;
        }
    }
    
    char *html_content = wifi_scan_html(deep_scan);
    if (html_content) {
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, html_content, strlen(html_content));
        free(html_content);
        ESP_LOGI(TAG, "WiFi scan completed and sent");
        return ESP_OK;
    }
    
    const char *error_msg = 
    "<!DOCTYPE html>"
    "<html>"
    "<head>"
    "<title>Scan Error</title>"
    "<style>"
    "body { font-family: Arial, sans-serif; background: #000000; color: #FFD600; margin: 0; padding: 20px; }"
    "h1 { color: #FFD600; text-align: center; }"
    ".btn { display: inline-block; padding: 10px 16px; margin: 10px 0; background: #FFD600; color: #000000; text-decoration: none; border-radius: 5px; }"
    "</style>"
    "</head>"
    "<body>"
    "<h1>❌ WiFi Scan Failed</h1>"
    "<p>Unable to perform WiFi scan. Please try again.</p>"
    "<a href='/' class='btn'>⬅ Back to Main Menu</a>"
    "</body>"
    "</html>";
    
    ESP_LOGE(TAG, "WiFi scan failed");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, error_msg, strlen(error_msg));
    return ESP_OK;
}

void start_server(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 10240;
    config.max_uri_handlers = 20;
    httpd_handle_t server = NULL;
    
    if (httpd_start(&server, &config) == ESP_OK) {
        ESP_LOGI(TAG, "HTTP server started");
        
        httpd_uri_t uri_handlers[] = {
            {.uri = "/", .method = HTTP_GET, .handler = otm_get_handler, .user_ctx = NULL},
            {.uri = "/wifi_scan", .method = HTTP_GET, .handler = wifi_scan_handler, .user_ctx = NULL},
            {.uri = "/scan", .method = HTTP_GET, .handler = wifi_scan_handler, .user_ctx = NULL},
            {.uri = "/wifi_deauth", .method = HTTP_GET, .handler = wifi_deauth_handler, .user_ctx = NULL},
            {.uri = "/wifi_pmkid", .method = HTTP_GET, .handler = pmkid_attack_handler, .user_ctx = NULL},
            {.uri = "/wifi_handshake", .method = HTTP_GET, .handler = handshake_attack_handler, .user_ctx = NULL},
            {.uri = "/wifi_dos", .method = HTTP_GET, .handler = dos_attack_handler, .user_ctx = NULL},
            {.uri = "/wifi_wps", .method = HTTP_GET, .handler = wps_attack_handler, .user_ctx = NULL},
            {.uri = "/wifi_beacon", .method = HTTP_GET, .handler = wifi_beacon_handler, .user_ctx = NULL},
            {.uri = "/wifi_probes", .method = HTTP_GET, .handler = probe_sniffer_handler, .user_ctx = NULL},
            {.uri = "/wifi_packets", .method = HTTP_GET, .handler = packet_monitor_handler, .user_ctx = NULL},
            {.uri = "/wifi_rogue", .method = HTTP_GET, .handler = rogue_ap_handler, .user_ctx = NULL},
            {.uri = "/wifi_evil", .method = HTTP_GET, .handler = evil_portal_handler, .user_ctx = NULL},
            {.uri = "/wifi_pwn", .method = HTTP_GET, .handler = pwnagotchi_detect_handler, .user_ctx = NULL}
        };
        
        for (int i = 0; i < sizeof(uri_handlers) / sizeof(httpd_uri_t); i++) {
            httpd_register_uri_handler(server, &uri_handlers[i]);
        }
        
        ESP_LOGI(TAG, "All URI handlers registered");
    } else {
        ESP_LOGE(TAG, "Failed to start HTTP server");
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "Starting OTOM Marauder on ESP32S3");
    
    init_ap();
    vTaskDelay(pdMS_TO_TICKS(1000));
    start_server();
    
    ESP_LOGI(TAG, "System ready - Connect to SSID: %s", WIFI_SSID);
}