idf_component_register(SRCS "esp-blinky-test.c" "mlkem768.c" "pq_mtls.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi nvs_flash esp_netif esp_event esp_driver_gpio esp_timer mbedtls lwip)
