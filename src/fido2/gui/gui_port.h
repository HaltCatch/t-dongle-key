#pragma once

#include "esp_lcd_st7735.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "gui_config.h"

/**
 * @brief Initialize the LVGL core and display driver
 * 
 * @param io_handle The ESP-IDF LCD IO handle
 * @param panel_handle The ESP-IDF LCD panel handle
 */
void gui_port_init(esp_lcd_panel_io_handle_t io_handle, esp_lcd_panel_handle_t panel_handle);

#ifdef __cplusplus
}
#endif
