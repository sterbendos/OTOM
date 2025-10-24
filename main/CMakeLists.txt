idf_component_register(
    SRCS 
        "main.c"
        "wifi_scan.c"
        "beacon_spam.c"
        "deauth_attack.c"
        "probe_sniffer.c"
        "packet_monitor.c"
        "rogue_ap.c"
        "evil_portal.c"
        "pwnagotchi_detect.c"
        "attack_pmkid.c"
        "attack_handshake.c"
        "attack_dos.c"
        "wps_attack.c"
        "pcap_serializer.c"
        "frame_analyzer.c"
    INCLUDE_DIRS "."
    REQUIRES 
        esp_wifi
        esp_netif
        esp_http_server
        esp_event
        esp_timer
    PRIV_REQUIRES 
        nvs_flash
)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-function -Wno-unused-variable -Wno-unused-const-variable")
