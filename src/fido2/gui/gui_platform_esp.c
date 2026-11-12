#include "gui_platform.h"
#include "driver/temperature_sensor.h"
#include "esp_system.h"
#include "esp_private/esp_clk.h"
#include "esp_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "sd_logger.h"

extern SemaphoreHandle_t xGuiSemaphore;
static temperature_sensor_handle_t temperature;

void gui_platform_init(void) {
    temperature_sensor_config_t config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(10, 50);
    if (temperature_sensor_install(&config, &temperature) != ESP_OK) {
        temperature = NULL;
    } else if (temperature_sensor_enable(temperature) != ESP_OK) {
        temperature_sensor_uninstall(temperature);
        temperature = NULL;
    }
}

gui_metrics_t gui_platform_metrics(void) {
    gui_metrics_t metrics = {0};
    metrics.cpu_mhz = esp_clk_cpu_freq() / 1000000;
    metrics.free_heap = esp_get_free_heap_size();
    esp_flash_get_size(NULL, &metrics.flash_bytes);
    metrics.task_count = uxTaskGetNumberOfTasks();
    metrics.sd_mounted = sd_logger_is_mounted();
    metrics.sd_error = sd_logger_has_error();
    metrics.sd_capacity = sd_logger_get_capacity();
    metrics.temperature_valid = temperature &&
        temperature_sensor_get_celsius(temperature, &metrics.temperature_c) == ESP_OK;
    return metrics;
}

bool gui_platform_lock(uint32_t timeout_ms) {
    return xGuiSemaphore &&
        xSemaphoreTake(xGuiSemaphore, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}
void gui_platform_unlock(void) { xSemaphoreGive(xGuiSemaphore); }
