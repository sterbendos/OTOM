// rf_jammer.cpp - New file to add to your OTOM project
#include "rf_jammer.h"
#include "RF24.h"
#include <SPI.h>
#include <Adafruit_NeoPixel.h>
#include "esp_bt.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include <string.h>

#define NEOPIXEL_PIN 48
#define NUM_PIXELS 1
#define SPI_SPEED 16000000

static const char *TAG = "RF_JAMMER";

SPIClass *spiVSPI = NULL;
SPIClass *spiHSPI = NULL;

RF24 radioVSPI(4, 5, SPI_SPEED);  // CE=4, CSN=5
RF24 radioHSPI(6, 7, SPI_SPEED);  // CE=6, CSN=7

Adafruit_NeoPixel pixels(NUM_PIXELS, NEOPIXEL_PIN, NEO_GRB + NEO_KHZ800);

int bluetooth_channels[] = {32, 34, 46, 48, 50, 52, 0, 1, 2, 4, 6, 8, 22, 24, 26, 28, 30, 74, 76, 78, 80};
int ble_channels[] = {2, 26, 80};

static int currentMode = 0;
static bool jammer_running = false;
static TaskHandle_t jammer_task_handle = NULL;

void configureRadio(RF24 &radio, int channel, SPIClass *spi) {
    if (radio.begin(spi)) {
        radio.setAutoAck(false);
        radio.stopListening();
        radio.setRetries(0, 0);
        radio.setPALevel(RF24_PA_MAX, true);
        radio.setDataRate(RF24_2MBPS);
        radio.setCRCLength(RF24_CRC_DISABLED);
        radio.startConstCarrier(RF24_PA_HIGH, channel);
        ESP_LOGI(TAG, "Radio configured on channel %d", channel);
    } else {
        ESP_LOGE(TAG, "Failed to configure radio");
    }
}

void updateNeoPixel() {
    switch (currentMode) {
        case 0:
            pixels.clear();
            pixels.show();
            ESP_LOGI(TAG, "Status: IDLE - LED Off");
            break;
        case 1:
            pixels.setPixelColor(0, pixels.Color(0, 0, 25));
            pixels.show();
            ESP_LOGI(TAG, "Status: BLE JAMMING - LED Blue");
            break;
        case 2:
            pixels.setPixelColor(0, pixels.Color(0, 25, 0));
            pixels.show();
            ESP_LOGI(TAG, "Status: BLUETOOTH JAMMING - LED Green");
            break;
        case 3:
            pixels.setPixelColor(0, pixels.Color(25, 0, 0));
            pixels.show();
            ESP_LOGI(TAG, "Status: JAM ALL - LED Red");
            break;
    }
}

void jamBLE() {
    int randomIndex = random(0, sizeof(ble_channels) / sizeof(ble_channels[0]));
    int channel = ble_channels[randomIndex];
    radioVSPI.setChannel(channel);
    radioHSPI.setChannel(channel);
}

void jamBluetooth() {
    int randomIndex = random(0, sizeof(bluetooth_channels) / sizeof(bluetooth_channels[0]));
    int channel = bluetooth_channels[randomIndex];
    radioVSPI.setChannel(channel);
    radioHSPI.setChannel(channel);
}

void jamAll() {
    if (random(0, 2)) {
        jamBluetooth();        
    } else {
        jamBLE();
    }
}

void executeMode() {
    switch (currentMode) {
        case 0:
            vTaskDelay(pdMS_TO_TICKS(100));
            break;
        case 1:
            jamBLE();
            break;
        case 2:
            jamBluetooth();
            break;
        case 3:
            jamAll();
            break;
    }
}

void jammer_task(void *pvParameters) {
    ESP_LOGI(TAG, "Jammer task started");
    while (jammer_running) {
        executeMode();
        vTaskDelay(pdMS_TO_TICKS(1)); // Small delay for task switching
    }
    ESP_LOGI(TAG, "Jammer task stopped");
    vTaskDelete(NULL);
}

void rf_jammer_init(void) {
    ESP_LOGI(TAG, "Initializing RF Jammer");
    
    // Disable WiFi and Bluetooth to avoid interference
    esp_wifi_stop();
    esp_bt_controller_deinit();
    
    // Initialize NeoPixel
    pixels.begin();
    pixels.clear();
    pixels.show();
    
    // Initialize SPI buses
    spiVSPI = new SPIClass(FSPI);
    spiVSPI->begin(12, 13, 11, 5); // SCK=12, MISO=13, MOSI=11, SS=5
    configureRadio(radioVSPI, ble_channels[0], spiVSPI);
    
    spiHSPI = new SPIClass(HSPI);
    spiHSPI->begin(14, 9, 10, 7); // SCK=14, MISO=9, MOSI=10, SS=7
    configureRadio(radioHSPI, bluetooth_channels[0], spiHSPI);
    
    updateNeoPixel();
    ESP_LOGI(TAG, "RF Jammer initialized successfully");
}

void rf_jammer_set_mode(int mode) {
    if (mode >= 0 && mode <= 3) {
        currentMode = mode;
        updateNeoPixel();
        ESP_LOGI(TAG, "Jammer mode changed to: %d", mode);
    } else {
        ESP_LOGE(TAG, "Invalid mode: %d", mode);
    }
}

void rf_jammer_start(int mode) {
    if (jammer_running) {
        ESP_LOGW(TAG, "Jammer already running");
        return;
    }
    
    rf_jammer_set_mode(mode);
    jammer_running = true;
    
    xTaskCreate(jammer_task, "jammer_task", 4096, NULL, 5, &jammer_task_handle);
    ESP_LOGI(TAG, "RF Jammer started in mode %d", mode);
}

void rf_jammer_stop(void) {
    if (!jammer_running) {
        ESP_LOGW(TAG, "Jammer not running");
        return;
    }
    
    jammer_running = false;
    
    // Wait for task to finish
    if (jammer_task_handle != NULL) {
        vTaskDelay(pdMS_TO_TICKS(100));
        jammer_task_handle = NULL;
    }
    
    // Reset to idle mode
    currentMode = 0;
    updateNeoPixel();
    
    ESP_LOGI(TAG, "RF Jammer stopped");
}

bool rf_jammer_is_running(void) {
    return jammer_running;
}

int rf_jammer_get_mode(void) {
    return currentMode;
}

// HTTP Handler for RF Jammer
esp_err_t rf_jammer_handler(httpd_req_t *req) {
    char query[128];
    int mode = 0;
    bool start = false;
    bool stop = false;
    
    // Parse query parameters
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        char param[32];
        if (httpd_query_key_value(query, "mode", param, sizeof(param)) == ESP_OK) {
            mode = atoi(param);
        }
        if (httpd_query_key_value(query, "action", param, sizeof(param)) == ESP_OK) {
            if (strcmp(param, "start") == 0) {
                start = true;
            } else if (strcmp(param, "stop") == 0) {
                stop = true;
            }
        }
    }
    
    // Execute action
    if (stop) {
        rf_jammer_stop();
    } else if (start) {
        rf_jammer_start(mode);
    }
    
    // Build HTML response
    const char *mode_names[] = {"IDLE (Off)", "BLE Jamming", "Bluetooth Classic Jamming", "JAM ALL (BLE + BT)"};
    const char *mode_colors[] = {"#666666", "#0066FF", "#00FF00", "#FF0000"};
    
    char html_buffer[2048];
    snprintf(html_buffer, sizeof(html_buffer),
        "<!DOCTYPE html>"
        "<html lang='en'>"
        "<head>"
        "<meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
        "<title>RF Jammer Control</title>"
        "<style>"
        "body { background: #0a0f1c; color: #f5c542; font-family: 'Segoe UI', sans-serif; margin: 0; padding: 20px; }"
        "h1 { text-align: center; font-size: 2.5rem; color: #f5c542; margin-bottom: 20px; }"
        ".status { text-align: center; padding: 20px; margin: 20px 0; background: #1a1f2c; border-radius: 10px; }"
        ".status-indicator { display: inline-block; width: 20px; height: 20px; border-radius: 50%%; margin-right: 10px; background: %s; }"
        ".category { margin: 30px 0; }"
        ".category h2 { color: #f5c542; border-bottom: 2px solid #f5c542; padding-bottom: 5px; }"
        ".btn { display: inline-block; padding: 12px 20px; margin: 8px; background: #f5c542; color: #0a0f1c; text-decoration: none; font-weight: bold; border-radius: 8px; transition: background 0.3s; }"
        ".btn:hover { background: #d4a017; }"
        ".btn-stop { background: #ff4444; color: white; }"
        ".btn-stop:hover { background: #cc0000; }"
        "</style>"
        "</head>"
        "<body>"
        "<h1>📡 RF Jammer Control</h1>"
        "<div class='status'>"
        "<h2><span class='status-indicator'></span>Status: %s</h2>"
        "<p>Current Mode: %s</p>"
        "</div>"
        "<div class='category'>"
        "<h2>🎯 Jammer Modes</h2>"
        "<a href='/rf_jammer?action=start&mode=1' class='btn'>Start BLE Jamming</a>"
        "<a href='/rf_jammer?action=start&mode=2' class='btn'>Start Bluetooth Jamming</a>"
        "<a href='/rf_jammer?action=start&mode=3' class='btn'>Start JAM ALL</a>"
        "<a href='/rf_jammer?action=stop' class='btn btn-stop'>⏹ STOP Jamming</a>"
        "</div>"
        "<div class='category'>"
        "<a href='/' class='btn'>⬅ Back to Main Menu</a>"
        "</div>"
        "</body></html>",
        mode_colors[currentMode],
        jammer_running ? "ACTIVE 🔴" : "IDLE 🟢",
        mode_names[currentMode]
    );
    
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, html_buffer, strlen(html_buffer));
    return ESP_OK;
}