#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "driver/gpio.h"

#include "pq_mtls.h"

#define WIFI_SSID            "saab_surveillance_uav_mk2"
#define WIFI_PASS            "bruhmoment"
#define STATIC_IP_ADDR       "192.168.43.10"
#define STATIC_GW_ADDR       "192.168.43.1"
#define STATIC_NETMASK       "255.255.255.0"
#define MTLS_PORT            8443
#define PQ_SERVER_STACK_SIZE 12288

/* ESP32-C3 SuperMini / DevBoard pins:
 * - GPIO 8: Onboard blue LED (active-low: 0 = ON, 1 = OFF)
 * - GPIO 9: Onboard BOOT pushbutton (active-low with internal pull-up: 0 = PRESSED, 1 = RELEASED)
 */
#define BLINK_GPIO      GPIO_NUM_8
#define BOOT_BTN_GPIO   GPIO_NUM_9

static const char *TAG = "pq_blinky";

static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static TaskHandle_t s_led_task_handle = NULL;
static QueueHandle_t s_boot_btn_queue = NULL;

/* Dedicated task to blink the onboard blue LED once per notification */
static void led_blink_task(void *arg)
{
    (void)arg;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        /* Active-low LED on GPIO 8: 0 = ON, 1 = OFF */
        gpio_set_level(BLINK_GPIO, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
        gpio_set_level(BLINK_GPIO, 1);
    }
}

/* Dedicated task to poll & debounce the BOOT pushbutton (GPIO 9) */
static void boot_button_task(void *arg)
{
    (void)arg;
    int last_stable = 1;
    int debounce_cnt = 0;
    uint32_t press_seq = 0;

    for (;;) {
        int level = gpio_get_level(BOOT_BTN_GPIO);
        if (level != last_stable) {
            debounce_cnt++;
            if (debounce_cnt >= 2) { /* 2 * 15ms = 30ms stable */
                last_stable = level;
                debounce_cnt = 0;
                if (last_stable == 0) {
                    press_seq++;
                    ESP_LOGI(TAG, "BOOT pushbutton (GPIO %d) pressed! (seq=%lu)",
                             BOOT_BTN_GPIO, (unsigned long)press_seq);
                    if (s_boot_btn_queue != NULL) {
                        /* Overwrite/send if queue has space */
                        xQueueSend(s_boot_btn_queue, &press_seq, 0);
                    }
                }
            }
        } else {
            debounce_cnt = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(15));
    }
}

static void gpio_init_all(void)
{
    /* Configure onboard blue LED (GPIO 8, active-low, default OFF = 1) */
    gpio_reset_pin(BLINK_GPIO);
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(BLINK_GPIO, 1);

    /* Configure BOOT pushbutton (GPIO 9, input with internal pull-up) */
    gpio_config_t btn_cfg = {
        .pin_bit_mask = (1ULL << BOOT_BTN_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&btn_cfg));

    s_boot_btn_queue = xQueueCreate(16, sizeof(uint32_t));
    xTaskCreate(led_blink_task, "led_blink", 2048, NULL, 5, &s_led_task_handle);
    xTaskCreate(boot_button_task, "boot_btn", 2048, NULL, 5, NULL);
}

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "Wi-Fi disconnected, reconnecting...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *) event_data;
        ESP_LOGI(TAG, "Connected! Static IPv4 assigned: " IPSTR " (gw: " IPSTR ")",
                 IP2STR(&event->ip_info.ip), IP2STR(&event->ip_info.gw));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();
    assert(sta_netif != NULL);

    /* Configure static IP (192.168.43.10/24) for Android hotspot */
    ESP_ERROR_CHECK(esp_netif_dhcpc_stop(sta_netif));
    esp_netif_ip_info_t ip_info;
    memset(&ip_info, 0, sizeof(ip_info));
    ip_info.ip.addr      = esp_ip4addr_aton(STATIC_IP_ADDR);
    ip_info.gw.addr      = esp_ip4addr_aton(STATIC_GW_ADDR);
    ip_info.netmask.addr = esp_ip4addr_aton(STATIC_NETMASK);
    ESP_ERROR_CHECK(esp_netif_set_ip_info(sta_netif, &ip_info));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA3_PSK,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Disable Wi-Fi power saving for low-latency mTLS & button responsiveness */
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    /* Enable 40 MHz bandwidth */
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW40));

    ESP_LOGI(TAG, "Wi-Fi initialization complete. Waiting for connection...");

    xEventGroupWaitBits(s_wifi_event_group,
                        WIFI_CONNECTED_BIT,
                        pdFALSE,
                        pdFALSE,
                        portMAX_DELAY);
}

static void handle_mtls_client(int client_fd, const char *peer_ip, uint16_t peer_port)
{
    static pq_mtls_conn_t conn;

    /* Set a 10-second socket timeout during handshake */
    struct timeval hs_tv = { .tv_sec = 10, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &hs_tv, sizeof(hs_tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &hs_tv, sizeof(hs_tv));

    size_t free_heap_before = esp_get_free_heap_size();
    int64_t t_start_us = esp_timer_get_time();

    ESP_LOGI(TAG, "Starting PQ-mTLS handshake with %s:%u (free_heap=%zu B)...",
             peer_ip, peer_port, free_heap_before);

    if (pq_mtls_server_handshake(&conn, client_fd) != 0) {
        ESP_LOGE(TAG, "PQ-mTLS handshake failed with %s:%u", peer_ip, peer_port);
        return;
    }

    int64_t hs_ms = (esp_timer_get_time() - t_start_us) / 1000;
    size_t free_heap_after = esp_get_free_heap_size();
    size_t min_free_ever = esp_get_minimum_free_heap_size();
    size_t peak_heap_used = conn.hs_peak_heap_bytes;
    if (free_heap_before > min_free_ever && (free_heap_before - min_free_ever) > peak_heap_used) {
        peak_heap_used = free_heap_before - min_free_ever;
    }
    size_t stack_unused = (size_t)uxTaskGetStackHighWaterMark(NULL);
    size_t stack_peak = (PQ_SERVER_STACK_SIZE > stack_unused) ? (PQ_SERVER_STACK_SIZE - stack_unused) : 0;
    size_t total_hs_ram = conn.hs_static_bytes + stack_peak + peak_heap_used;

    ESP_LOGI(TAG, "PQ-mTLS handshake done in %lld ms! Peer=%s:%u ClientCN='%s'",
             (long long)hs_ms, peer_ip, peer_port, conn.client_cn);
    ESP_LOGI(TAG, "Handshake memory usage: total_peak=%zu B (~%.1f KB) "
                  "[static_bss=%zu B, stack_peak=%zu/%d B, heap_peak=%zu B] | "
                  "free_heap_now=%zu B (min_free_ever=%zu B)",
             total_hs_ram, (double)total_hs_ram / 1024.0,
             conn.hs_static_bytes, stack_peak, PQ_SERVER_STACK_SIZE, peak_heap_used,
             free_heap_after, min_free_ever);

    /* Clear any stale button presses queued while no client was connected */
    xQueueReset(s_boot_btn_queue);

    for (;;) {
        /* Check if BOOT button was pressed and forward over PQ-mTLS */
        uint32_t press_seq = 0;
        while (xQueueReceive(s_boot_btn_queue, &press_seq, 0) == pdTRUE) {
            char msg[64];
            int mlen = snprintf(msg, sizeof(msg), "BOOT_PRESSED seq=%lu\n", (unsigned long)press_seq);
            if (pq_mtls_write(&conn, msg, (size_t)mlen) < 0) {
                ESP_LOGW(TAG, "Failed writing BOOT_PRESSED to client, closing session");
                return;
            }
            ESP_LOGI(TAG, "Sent BOOT_PRESSED (seq=%lu) to CLI client over PQ-mTLS",
                     (unsigned long)press_seq);
        }

        /* Wait up to 20ms for incoming encrypted commands from CLI */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(client_fd, &rfds);
        struct timeval tv = { .tv_sec = 0, .tv_usec = 20000 };

        int sret = select(client_fd + 1, &rfds, NULL, NULL, &tv);
        if (sret < 0) {
            if (errno == EINTR) continue;
            ESP_LOGE(TAG, "select() error: errno=%d", errno);
            break;
        }
        if (sret > 0 && FD_ISSET(client_fd, &rfds)) {
            char rx_buf[128];
            int n = pq_mtls_read(&conn, rx_buf, sizeof(rx_buf) - 1);
            if (n == 0) {
                ESP_LOGI(TAG, "CLI client %s:%u closed PQ-mTLS connection cleanly", peer_ip, peer_port);
                break;
            }
            if (n < 0) {
                ESP_LOGW(TAG, "PQ-mTLS read error from %s:%u, disconnecting", peer_ip, peer_port);
                break;
            }
            rx_buf[n] = '\0';

            if (strstr(rx_buf, "BLINK") != NULL) {
                ESP_LOGI(TAG, "Received BLINK command over PQ-mTLS from '%s'! Blinking onboard blue LED once.",
                         conn.client_cn);
                if (s_led_task_handle != NULL) {
                    xTaskNotifyGive(s_led_task_handle);
                }
                const char *ack = "BLINK_ACK\n";
                if (pq_mtls_write(&conn, ack, strlen(ack)) < 0) {
                    break;
                }
            }
        }
    }
}

static void pq_mtls_server_task(void *arg)
{
    (void)arg;
    int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (listen_fd < 0) {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in dest_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(MTLS_PORT),
    };

    if (bind(listen_fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) != 0) {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_fd, 2) != 0) {
        ESP_LOGE(TAG, "Error occurred during listen: errno %d", errno);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "PQ-mTLS TCP server listening on 0.0.0.0:%d (X25519MLKEM768 + ChaCha20-Poly1305)",
             MTLS_PORT);

    for (;;) {
        struct sockaddr_in source_addr;
        socklen_t addr_len = sizeof(source_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&source_addr, &addr_len);
        if (client_fd < 0) {
            ESP_LOGE(TAG, "Unable to accept connection: errno %d", errno);
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        char peer_ip[32];
        inet_ntoa_r(source_addr.sin_addr, peer_ip, sizeof(peer_ip) - 1);
        uint16_t peer_port = ntohs(source_addr.sin_port);

        handle_mtls_client(client_fd, peer_ip, peer_port);
        shutdown(client_fd, SHUT_RDWR);
        close(client_fd);
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    gpio_init_all();
    wifi_init_sta();

    xTaskCreate(pq_mtls_server_task, "pq_mtls_srv", 12288, NULL, 5, NULL);
}
