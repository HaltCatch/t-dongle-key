#include "gui_controller.h"
#include "gui_config.h"
#include "gui_screens.h"
#include "gui_anim.h"
#include "led.h"

const gui_status_t *gui_status(gui_view_t view) {
    static const gui_status_t states[] = {
        [GUI_VIEW_DARK]        = {LED_COLOR_OFF, 0},
        [GUI_VIEW_BOOT]        = {LED_COLOR_GREEN, HALF_BTNESS, 0, 0, "Starting", 0x00FF00},
        [GUI_VIEW_BOOT_ERROR] = {LED_COLOR_RED, HALF_BTNESS, 400, 1600, "Startup failed", 0xFF4444},
        [GUI_VIEW_READY]       = {LED_COLOR_GREEN, HALF_BTNESS, 0, 0, "USB ready", 0x00FF00},
        [GUI_VIEW_CARD]        = {LED_COLOR_BLUE, HALF_BTNESS, 240, 800, "Card activity", 0xAAAAFF},
        [GUI_VIEW_TOUCH]       = {LED_COLOR_RED, MAX_BTNESS, 400, 800, "Confirm request", 0xAA0000},
        [GUI_VIEW_ENDED]       = {LED_COLOR_RED, HALF_BTNESS, 0, 0, "Request ended", 0xAA0000},
        [GUI_VIEW_USB_WAIT]    = {LED_COLOR_RED, HALF_BTNESS, 200, 2400, "USB not ready", 0xFF6666},
        [GUI_VIEW_USB_SUSPEND] = {LED_COLOR_YELLOW, HALF_BTNESS, 200, 2400, "USB suspended", 0xFFFF00},
    };
    return &states[view];
}

bool gui_led_lit(const gui_status_t *status, uint32_t elapsed) {
    return status->brightness && (!status->period_ms || elapsed % status->period_ms < status->on_ms);
}

static bool idle_mode(uint32_t mode) {
    return mode == MODE_MOUNTED || mode == MODE_SUSPENDED || mode == MODE_PROCESSING;
}

static void show_view(gui_controller_t *s, gui_view_t view) {
    if (s->view == view) return;
    s->view = view;
    const gui_status_t *status = gui_status(view);
    switch (view) {
    case GUI_VIEW_BOOT:
    case GUI_VIEW_BOOT_ERROR: gui_show_boot_logo(); break;
    case GUI_VIEW_DARK: gui_anim_stop(); break;
    case GUI_VIEW_TOUCH:
    case GUI_VIEW_ENDED: gui_show_request(status->text, view == GUI_VIEW_TOUCH, status->text_color); break;
    default: gui_show_idle(status->text, status->text_color); break;
    }
}

void gui_controller_init(gui_controller_t *s, uint32_t now) {
    gui_boot_reset();
    *s = (gui_controller_t){.boot_ms = now, .last_activity_ms = now,
                            .last_mode = UINT32_MAX, .booting = true};
    show_view(s, GUI_VIEW_BOOT);
}

void gui_controller_step(gui_controller_t *s, uint32_t now, uint32_t mode,
                         bool button, bool pending) {
    if (s->booting) {
        if (!gui_boot_finished()) {
            if (gui_boot_failed()) show_view(s, GUI_VIEW_BOOT_ERROR);
            return;
        }
        s->booting = false;
        s->last_activity_ms = now;
    }
    bool touch = mode == MODE_BUTTON || pending;
    bool idle_transition = idle_mode(mode) && idle_mode(s->last_mode);
    if (button || touch || (mode != s->last_mode && !idle_transition)) {
        s->last_activity_ms = now;
        if (s->asleep && (button || touch || mode != MODE_NOT_MOUNTED)) {
            s->asleep = false;
            gui_metrics_set_active(true);
        }
    }
    s->last_mode = mode;
    if (mode == MODE_PROCESSING) s->card_ms = now;
    if (touch) {
        if (s->view != GUI_VIEW_TOUCH) s->prompt_ms = now;
        show_view(s, GUI_VIEW_TOUCH);
    } else if (!s->asleep && now - s->last_activity_ms >= GUI_SCREEN_SLEEP_TIMEOUT_MS) {
        s->asleep = true;
        show_view(s, GUI_VIEW_DARK);
        gui_metrics_set_active(false);
    } else if (!s->asleep) {
        if (mode != MODE_NOT_MOUNTED && (s->view == GUI_VIEW_TOUCH || s->view == GUI_VIEW_ENDED) &&
            now - s->prompt_ms < GUI_FIDO_REQUEST_MIN_DUR_MS) {
            show_view(s, GUI_VIEW_ENDED);
        } else {
            bool card = mode == MODE_PROCESSING || (mode == MODE_MOUNTED && s->view == GUI_VIEW_CARD &&
                       now - s->card_ms < GUI_CARD_ACTIVITY_VISIBLE_MS);
            gui_view_t view = card ? GUI_VIEW_CARD :
                              mode == MODE_NOT_MOUNTED ? GUI_VIEW_USB_WAIT :
                              mode == MODE_SUSPENDED ? GUI_VIEW_USB_SUSPEND : GUI_VIEW_READY;
            show_view(s, view);
        }
    }
}
