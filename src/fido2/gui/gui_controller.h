#pragma once
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    GUI_VIEW_DARK,
    GUI_VIEW_BOOT,
    GUI_VIEW_BOOT_ERROR,
    GUI_VIEW_READY,
    GUI_VIEW_CARD,
    GUI_VIEW_TOUCH,
    GUI_VIEW_ENDED,
    GUI_VIEW_USB_WAIT,
    GUI_VIEW_USB_SUSPEND,
} gui_view_t;

typedef struct {
    uint8_t color, brightness;
    uint16_t on_ms, period_ms;
    const char *text;
    uint32_t text_color;
} gui_status_t;

const gui_status_t *gui_status(gui_view_t view);
bool gui_led_lit(const gui_status_t *status, uint32_t elapsed_ms);

typedef struct {
    uint32_t boot_ms, last_activity_ms, last_mode, prompt_ms, card_ms;
    gui_view_t view;
    bool booting, asleep;
} gui_controller_t;

void gui_controller_init(gui_controller_t *state, uint32_t now_ms);
void gui_controller_step(gui_controller_t *state, uint32_t now_ms,
                         uint32_t mode, bool button, bool request_pending);
