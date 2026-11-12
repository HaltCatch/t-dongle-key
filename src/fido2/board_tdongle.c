/*
 * This file is part of the Pico FIDO2 distribution (https://github.com/polhenarejos/pico-fido2).
 * Copyright (c) 2026.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "button.h"

#if defined(ESP_PLATFORM) && defined(PICO_BOARD_TDONGLE_S3)

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_st7735.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "gui_port.h"
#include "sd_logger.h"

bool picokey_sd_logger_pins(sd_logger_pins_t *pins) {
    *pins = (sd_logger_pins_t){.clk = 12, .cmd = 16, .d0 = 14};
    return true;
}

static const char *TAG = "TDONGLE_LCD";

#if !defined(CONFIG_IDF_TARGET_ESP32S3)
#error "The LilyGO T-Dongle S3 board support requires CONFIG_IDF_TARGET_ESP32S3."
#endif

#define TDONGLE_BUTTON_GPIO         GPIO_NUM_0
#define TDONGLE_APA102_DATA_GPIO    GPIO_NUM_40
#define TDONGLE_DISPLAY_MOSI_GPIO   GPIO_NUM_3
#define TDONGLE_DISPLAY_SCK_GPIO    GPIO_NUM_5
#define TDONGLE_DISPLAY_CS_GPIO     GPIO_NUM_4
#define TDONGLE_DISPLAY_DC_GPIO     GPIO_NUM_2
#define TDONGLE_DISPLAY_BL_GPIO     GPIO_NUM_38
#define TDONGLE_DISPLAY_SPI_HOST    SPI3_HOST
#define TDONGLE_DEFAULT_UP_TIMEOUT  15

#include "tdongle_lcd_init.h"

static void tdongle_display_init(void);

void picokey_board_early_init(void) {
    gpio_config_t bl_conf = {
        .mode = GPIO_MODE_OUTPUT,
        .pin_bit_mask = 1ULL << TDONGLE_DISPLAY_BL_GPIO
    };
    // Preload the active-low output before enabling its driver.
    ESP_ERROR_CHECK(gpio_set_level(TDONGLE_DISPLAY_BL_GPIO, 1));
    ESP_ERROR_CHECK(gpio_config(&bl_conf));
    tdongle_display_init();
}

static void tdongle_display_init(void) {
    ESP_LOGI(TAG, "Starting Display Init...");

    // 2. Initialize SPI bus
    ESP_LOGI(TAG, "Initializing SPI Bus on SPI3...");
    spi_bus_config_t bus_cfg = {
        .sclk_io_num = TDONGLE_DISPLAY_SCK_GPIO,
        .mosi_io_num = TDONGLE_DISPLAY_MOSI_GPIO,
        .miso_io_num = -1,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 160 * 80 * 2 + 8
    };
    esp_err_t err = spi_bus_initialize(TDONGLE_DISPLAY_SPI_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
    ESP_LOGI(TAG, "SPI Init result: %s", esp_err_to_name(err));
    ESP_ERROR_CHECK(err);

    // 3. Configure LCD IO
    ESP_LOGI(TAG, "Configuring LCD IO...");
    esp_lcd_panel_io_handle_t io_handle = NULL;
    esp_lcd_panel_io_spi_config_t io_config = {
        .dc_gpio_num = TDONGLE_DISPLAY_DC_GPIO,
        .cs_gpio_num = TDONGLE_DISPLAY_CS_GPIO,
        .pclk_hz = 20 * 1000 * 1000,
        .lcd_cmd_bits = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)TDONGLE_DISPLAY_SPI_HOST, &io_config, &io_handle));

    // 4. Install ST7735 panel driver
    ESP_LOGI(TAG, "Installing ST7735 driver...");
    esp_lcd_panel_handle_t panel_handle = NULL;
    const st7735_vendor_config_t vendor = {
        .init_cmds = tdongle_lcd_init,
        .init_cmds_size = sizeof(tdongle_lcd_init) / sizeof(*tdongle_lcd_init),
    };
    esp_lcd_panel_dev_config_t panel_config = {
        .vendor_config = (void *)&vendor,
        .reset_gpio_num = 1, // Hardware reset pin according to LilyGO official specs
        .rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR,
        .bits_per_pixel = 16,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7735(io_handle, &panel_config, &panel_handle));
    
    // 5. Initialize the panel and keep it blank until the first LVGL frame.
    ESP_LOGI(TAG, "Resetting and initializing panel...");
    ESP_ERROR_CHECK(esp_lcd_panel_reset(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_init(panel_handle));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel_handle, false));
    
    ESP_LOGI(TAG, "Configuring inversion, rotation and gap...");
    // Invert color if needed for ST7735, depending on the specific screen variation, might need panel_invert_color
    ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel_handle, true));
    
    // Rotate to Landscape mode
    ESP_ERROR_CHECK(esp_lcd_panel_swap_xy(panel_handle, true));
    ESP_ERROR_CHECK(esp_lcd_panel_mirror(panel_handle, true, false)); // Flipped 180 degrees (upside down landscape)
    
    // Set gap for Landscape (T-Dongle S3 typically uses 132x162 GRAM for 80x160 glass)
    ESP_ERROR_CHECK(esp_lcd_panel_set_gap(panel_handle, 1, 26));
    
    // Hand over control to LVGL GUI layer
    gui_port_init(io_handle, panel_handle);
    
    ESP_LOGI(TAG, "Display init complete!");
}

#include "gui/gui_port.h"

#if ENABLE_OTP_APP
extern int tdongle_otp_init(void);
#endif
int picokey_init(void) {
#if ENABLE_OTP_APP
    int status = tdongle_otp_init();
    if (status != 0) return status;
#endif
    gpio_pullup_en(TDONGLE_BUTTON_GPIO);
    gpio_pulldown_dis(TDONGLE_BUTTON_GPIO);

    if (!phy_data.up_btn_present) {
        phy_data.up_btn = TDONGLE_DEFAULT_UP_TIMEOUT;
        phy_data.up_btn_present = true;
    }
    if (!phy_data.led_driver_present) {
        phy_data.led_driver = PHY_LED_DRIVER_APA102;
        phy_data.led_driver_present = true;
    }
    if (!phy_data.led_gpio_present) {
        phy_data.led_gpio = TDONGLE_APA102_DATA_GPIO;
        phy_data.led_gpio_present = true;
    }
    
    if (!phy_data.led_brightness_present) {
        phy_data.led_brightness = GUI_APA102_BRIGHTNESS;
        phy_data.led_brightness_present = true;
    }

    return 0;
}

#endif
