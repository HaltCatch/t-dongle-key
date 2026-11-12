#include "gui_port.h"
#include "gui_screens.h"
#include "gui_anim.h"
#include "gui_controller.h"
#include "lvgl.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "picokeys.h"
#include "button.h"
#include "led.h"
#include "esp_heap_caps.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_io.h"
#include "tusb.h"
#include <stdatomic.h>

static const char *TAG = "GUI_PORT";

#ifndef TDONGLE_DISPLAY_BL_GPIO
#define TDONGLE_DISPLAY_BL_GPIO GPIO_NUM_38
#endif

#define LEDC_TIMER              LEDC_TIMER_0
#define LEDC_MODE               LEDC_LOW_SPEED_MODE
#define LEDC_OUTPUT_IO          (TDONGLE_DISPLAY_BL_GPIO)
#define LEDC_CHANNEL            LEDC_CHANNEL_0
#define LEDC_DUTY_RES           LEDC_TIMER_8_BIT

static void gui_backlight_init(void) {
#if GUI_BACKLIGHT_BRIGHTNESS > 0 && GUI_BACKLIGHT_BRIGHTNESS < 255
    ledc_timer_config_t ledc_timer = {
        .speed_mode       = LEDC_MODE,
        .timer_num        = LEDC_TIMER,
        .duty_resolution  = LEDC_DUTY_RES,
        .freq_hz          = 500,
        .clk_cfg          = LEDC_AUTO_CLK
    };
    ESP_ERROR_CHECK(ledc_timer_config(&ledc_timer));

    ledc_channel_config_t ledc_channel = {
        .speed_mode     = LEDC_MODE,
        .channel        = LEDC_CHANNEL,
        .timer_sel      = LEDC_TIMER,
        .intr_type      = LEDC_INTR_DISABLE,
        .gpio_num       = LEDC_OUTPUT_IO,
        .duty           = 255, // Active low: 255 = OFF
        .hpoint         = 0
    };
    ESP_ERROR_CHECK(ledc_channel_config(&ledc_channel));
#endif
}

static void gui_backlight_set(bool on) {
#if GUI_BACKLIGHT_BRIGHTNESS == 0
    (void)on;
#elif GUI_BACKLIGHT_BRIGHTNESS == 255
    // The early GPIO setup already owns this active-low pin.
    ESP_ERROR_CHECK(gpio_set_level(LEDC_OUTPUT_IO, !on));
#else
    if (on) {
        // Brightness is 0-255. Active low means duty = 255 - brightness
        uint32_t duty = 255 - GUI_BACKLIGHT_BRIGHTNESS;
        ledc_set_duty(LEDC_MODE, LEDC_CHANNEL, duty);
        ledc_update_duty(LEDC_MODE, LEDC_CHANNEL);
    } else {
        // Completely turn off PWM and hold the pin HIGH (Active Low OFF)
        ledc_stop(LEDC_MODE, LEDC_CHANNEL, 1);
    }
#endif
}

#define LVGL_TICK_PERIOD_MS 2
#define LVGL_TASK_MAX_DELAY_MS 20
#define LVGL_TASK_MIN_DELAY_MS 1
#define LVGL_TASK_STACK_SIZE (8 * 1024)
#define LVGL_TASK_PRIORITY 2
#define LCD_WAKE_SETTLE_MS 30

#define LCD_H_RES 160
#define LCD_V_RES 80

SemaphoreHandle_t xGuiSemaphore;
static SemaphoreHandle_t startup_frame_ready;

void picokey_boot_message(const char *message) {
    ESP_LOGI("BOOT", "%s", message);
    xSemaphoreTake(xGuiSemaphore, portMAX_DELAY);
    gui_boot_log(message);
    lv_refr_now(NULL);
    xSemaphoreGive(xGuiSemaphore);
}

void picokey_boot_complete(void) {
    ESP_LOGI("BOOT", "Component startup complete");
    gui_boot_complete();
}

static struct {
    esp_lcd_panel_io_handle_t io;
    esp_lcd_panel_handle_t panel;
} gui_display;

// The display task publishes a mode only after the corresponding frame is sent.
// The SDK LED task remains the sole writer to the rear LED.
static atomic_uint displayed_view = GUI_VIEW_DARK;

bool led_render_board_status(uint32_t now) {
    static gui_view_t last_view = GUI_VIEW_DARK;
    static uint32_t phase_start;
    gui_view_t view = atomic_load_explicit(&displayed_view, memory_order_relaxed);
    if (view != last_view) {
        last_view = view;
        phase_start = now;
    }
    const gui_status_t *status = gui_status(view);
    bool lit = gui_led_lit(status, now - phase_start) || (phy_data.opts & PHY_OPT_LED_STEADY);
    // Drivers apply the configured physical brightness. Applying it here too
    // squares the setting and can exceed the driver's normalized range.
    led_driver->set_color(status->color, status->brightness, lit ? 1.0f : 0.0f);
    return true;
}

static uint32_t gui_usb_mode(void) {
    if (!tud_mounted()) return MODE_NOT_MOUNTED;
    if (tud_suspended()) return MODE_SUSPENDED;
    uint32_t mode = led_get_mode();
    // The SDK also sets SUSPENDED when a card worker is idle on an active USB bus.
    return mode == MODE_SUSPENDED || mode == MODE_NOT_MOUNTED ? MODE_MOUNTED : mode;
}

static void lv_tick_task(void *arg) {
    (void) arg;
    lv_tick_inc(LVGL_TICK_PERIOD_MS);
}

static void disp_flush(lv_display_t *display, const lv_area_t *area, uint8_t *pixels) {
    esp_lcd_panel_handle_t panel_handle = lv_display_get_user_data(display);
    int offsetx1 = area->x1;
    int offsetx2 = area->x2;
    int offsety1 = area->y1;
    int offsety2 = area->y2;
    
    // The ST7735 takes the high byte first; LVGL renders native RGB565.
    lv_draw_sw_rgb565_swap(pixels, (offsetx2 - offsetx1 + 1) * (offsety2 - offsety1 + 1));
    ESP_ERROR_CHECK(esp_lcd_panel_draw_bitmap(panel_handle, offsetx1, offsety1, offsetx2 + 1, offsety2 + 1, pixels));
}

static bool notify_lvgl_flush_ready(esp_lcd_panel_io_handle_t panel_io, esp_lcd_panel_io_event_data_t *edata, void *user_ctx) {
    lv_display_flush_ready(user_ctx);
    return false;
}

// Import macros for GPIOs from board config or define defaults
#ifndef TDONGLE_BUTTON_GPIO
#define TDONGLE_BUTTON_GPIO GPIO_NUM_0
#endif



static void gui_task(void *arg) {
    (void)arg;
    esp_lcd_panel_io_handle_t io = gui_display.io;
    ESP_LOGI(TAG, "Starting shared GUI controller");
    gui_controller_t state;
    xSemaphoreTake(xGuiSemaphore, portMAX_DELAY);
    gui_screens_init();
    gui_controller_init(&state, (uint32_t)(esp_timer_get_time() / 1000));
    lv_refr_now(NULL);
    // A parameter transfer without a command drains the queued display DMA.
    ESP_ERROR_CHECK(esp_lcd_panel_io_tx_param(io, -1, NULL, 0));
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(gui_display.panel, true));
    xSemaphoreGive(xGuiSemaphore);
    gui_backlight_init();
    gui_backlight_set(true);
    ESP_LOGI("BOOT", "First startup frame visible");
    xSemaphoreGive(startup_frame_ready);
    gui_view_t visible_view = state.view;
    atomic_store_explicit(&displayed_view, visible_view, memory_order_relaxed);
    bool was_asleep = false;
    while (1) {
        xSemaphoreTake(xGuiSemaphore, portMAX_DELAY);
        gui_controller_step(&state, (uint32_t)(esp_timer_get_time() / 1000),
            gui_boot_finished() ? gui_usb_mode() : MODE_NOT_MOUNTED,
            gui_boot_finished() && gpio_get_level(TDONGLE_BUTTON_GPIO) == 0,
            gui_boot_finished() && is_req_button_pending());
        uint32_t delay = lv_timer_handler();
        if (!state.asleep && (was_asleep || state.view != visible_view)) {
            lv_refr_now(NULL);
            ESP_ERROR_CHECK(esp_lcd_panel_io_tx_param(io, -1, NULL, 0));
        }
        xSemaphoreGive(xGuiSemaphore);
        if (state.asleep != was_asleep) {
            if (!state.asleep) {
                // The LCD scans its frame memory after the SPI write finishes.
                // Keep the backlight off through that scan and tick rounding.
                vTaskDelay(pdMS_TO_TICKS(LCD_WAKE_SETTLE_MS) + 1);
            }
            gui_backlight_set(!state.asleep);
            ESP_LOGI(TAG, "Display %s", state.asleep ? "asleep" : "awake");
            was_asleep = state.asleep;
        }
        visible_view = state.view;
        atomic_store_explicit(&displayed_view, visible_view, memory_order_relaxed);
        if (delay > LVGL_TASK_MAX_DELAY_MS) delay = LVGL_TASK_MAX_DELAY_MS;
        if (delay < LVGL_TASK_MIN_DELAY_MS) delay = LVGL_TASK_MIN_DELAY_MS;
        TickType_t ticks = pdMS_TO_TICKS(delay);
        vTaskDelay(ticks ? ticks : 1);
    }
}

void gui_port_init(esp_lcd_panel_io_handle_t io_handle, esp_lcd_panel_handle_t panel_handle) {
    ESP_LOGI(TAG, "Initializing LVGL");
    gui_display.io = io_handle;
    gui_display.panel = panel_handle;
    
    lv_init();
    
    size_t draw_buffer_sz = LCD_H_RES * 40 * sizeof(uint16_t); // 40 lines of RGB565
    lv_color_t *buf1 = heap_caps_malloc(draw_buffer_sz, MALLOC_CAP_DMA);
    lv_color_t *buf2 = heap_caps_malloc(draw_buffer_sz, MALLOC_CAP_DMA);
    assert(buf1);
    assert(buf2);
    
    lv_display_t *display = lv_display_create(LCD_H_RES, LCD_V_RES);
    assert(display);
    lv_display_set_color_format(display, LV_COLOR_FORMAT_RGB565);
    lv_display_set_buffers(display, buf1, buf2, draw_buffer_sz, LV_DISPLAY_RENDER_MODE_PARTIAL);
    lv_display_set_user_data(display, panel_handle);
    lv_display_set_flush_cb(display, disp_flush);
    
    // Register the DMA flush ready callback
    const esp_lcd_panel_io_callbacks_t cbs = {
        .on_color_trans_done = notify_lvgl_flush_ready,
    };
    esp_lcd_panel_io_register_event_callbacks(io_handle, &cbs, display);
    
    // Create tick timer
    const esp_timer_create_args_t tick_timer_args = {
        .callback = &lv_tick_task,
        .name = "lvgl_tick"
    };
    esp_timer_handle_t tick_timer;
    ESP_ERROR_CHECK(esp_timer_create(&tick_timer_args, &tick_timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(tick_timer, LVGL_TICK_PERIOD_MS * 1000));
    
    xGuiSemaphore = xSemaphoreCreateMutex();
    startup_frame_ready = xSemaphoreCreateBinary();
    configASSERT(xGuiSemaphore && startup_frame_ready);
    configASSERT(xTaskCreate(gui_task, "gui_task", LVGL_TASK_STACK_SIZE, NULL, LVGL_TASK_PRIORITY, NULL) == pdPASS);
    xSemaphoreTake(startup_frame_ready, portMAX_DELAY);
}
