#include "gui_screens.h"
#include "gui_anim.h"
#include "lvgl.h"
#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include "gui_platform.h"
#include "gui_config.h"
#include "picokeys_version.h"

static lv_obj_t *scr_boot;
static lv_obj_t *scr_idle;
static lv_obj_t *scr_fido;

static lv_obj_t *lbl_boot_log;
static char boot_lines[6][23];
static unsigned boot_line_count;
static atomic_bool boot_finished, boot_failed;

void gui_boot_reset(void) {
    atomic_store(&boot_finished, false);
    atomic_store(&boot_failed, false);
    lv_obj_set_style_text_color(lbl_boot_log, lv_color_hex(0x00FF00), 0);
    boot_line_count = 0;
    gui_boot_log("Display ready");
}

void gui_boot_log(const char *message) {
    if (!lbl_boot_log || atomic_load(&boot_failed)) return;
    if (!strncmp(message, "ERROR:", 6)) {
        atomic_store(&boot_failed, true);
        lv_obj_set_style_text_color(lbl_boot_log, lv_color_hex(0xFF4444), 0);
    }
    if (boot_line_count == 6) {
        memmove(boot_lines, boot_lines + 1, 5 * sizeof(*boot_lines));
        boot_line_count--;
    }
    snprintf(boot_lines[boot_line_count++], sizeof(*boot_lines), "%.22s", message);
    char text[6 * sizeof(*boot_lines)] = {0};
    size_t used = 0;
    for (unsigned i = 0; i < boot_line_count; i++)
        used += (size_t)snprintf(text + used, sizeof(text) - used, "%s%s", i ? "\n" : "", boot_lines[i]);
    lv_label_set_text(lbl_boot_log, text);
}

void gui_boot_complete(void) { atomic_store(&boot_finished, true); }
bool gui_boot_finished(void) { return atomic_load(&boot_finished) && !atomic_load(&boot_failed); }
bool gui_boot_failed(void) { return atomic_load(&boot_failed); }

static lv_obj_t *lbl_idle_status;
static lv_obj_t *lbl_request_title, *lbl_request_action;
static lv_obj_t *lbl_temp;
static lv_obj_t *lbl_heap;
static lv_obj_t *lbl_sd;

static lv_timer_t *metrics_timer = NULL;

#if GUI_MONITOR_DISPLAY_MODE != 1
static bool last_sd_error, last_sd_mounted;
static uint64_t last_sd_capacity;
static void update_sd_status(gui_metrics_t metrics) {
    last_sd_error = metrics.sd_error;
    last_sd_mounted = metrics.sd_mounted;
    last_sd_capacity = metrics.sd_capacity;
    if (metrics.sd_error) {
        lv_label_set_text(lbl_sd, "SD:ERR");
        lv_obj_set_style_text_color(lbl_sd, lv_color_hex(0xAA0000), 0);
    } else if (metrics.sd_mounted) {
        uint64_t mb = metrics.sd_capacity / (1024 * 1024);
        if (mb >= 1024ULL * 1024) {
            lv_label_set_text_fmt(lbl_sd, "SD:%llu T", (unsigned long long)(mb / (1024ULL * 1024)));
        } else if (mb >= 1024) {
            lv_label_set_text_fmt(lbl_sd, "SD:%llu G", (unsigned long long)(mb / 1024));
        } else {
            lv_label_set_text_fmt(lbl_sd, "SD:%llu M", (unsigned long long)mb);
        }
        lv_obj_set_style_text_color(lbl_sd, lv_color_hex(0x00AA00), 0);
    } else {
        lv_label_set_text(lbl_sd, "SD:N/A");
        lv_obj_set_style_text_color(lbl_sd, lv_color_hex(0xAA0000), 0);
    }
}
#endif

static void metrics_update_timer_cb(lv_timer_t * timer) {
    (void)timer;
    gui_metrics_t metrics = gui_platform_metrics();
    if (metrics.temperature_valid)
        lv_label_set_text_fmt(lbl_temp, "%d'C", (int)metrics.temperature_c);
    else
        lv_label_set_text(lbl_temp, "--'C");
    lv_label_set_text_fmt(lbl_heap, "RAM:%luK", (unsigned long)(metrics.free_heap / 1024));
#if GUI_MONITOR_DISPLAY_MODE == 1
    if (lbl_sd) lv_label_set_text_fmt(lbl_sd, "CPU:%luM T:%lu",
        (unsigned long)metrics.cpu_mhz, (unsigned long)metrics.task_count);
#else
    if (metrics.sd_error != last_sd_error || metrics.sd_mounted != last_sd_mounted ||
        metrics.sd_capacity != last_sd_capacity) update_sd_status(metrics);
#endif
}

void gui_screens_init(void) {
    // 1. Boot Screen (Retro BIOS POST Style — all real hardware data)
    scr_boot = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr_boot, lv_color_hex(0x000000), 0);
    
    gui_platform_init();
    gui_metrics_t metrics = gui_platform_metrics();
    lv_obj_t *lbl_logo = lv_label_create(scr_boot);
    lv_label_set_text(lbl_logo, "T-Dongle Key / boot");
    lv_obj_set_style_text_color(lbl_logo, lv_color_hex(0x00FFFF), 0);
    lv_obj_set_style_text_font(lbl_logo, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_letter_space(lbl_logo, -1, 0);
    lv_obj_align(lbl_logo, LV_ALIGN_TOP_LEFT, 2, 2);
    lbl_boot_log = lv_label_create(scr_boot);
    lv_obj_set_style_text_color(lbl_boot_log, lv_color_hex(0x00FF00), 0);
    lv_obj_set_style_text_font(lbl_boot_log, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_letter_space(lbl_boot_log, -1, 0);
    lv_obj_set_style_text_line_space(lbl_boot_log, 2, 0);
    lv_obj_align(lbl_boot_log, LV_ALIGN_TOP_LEFT, 2, 16);

    // 2. Idle Screen
    scr_idle = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr_idle, lv_color_hex(0x111111), 0);
    lv_obj_clear_flag(scr_idle, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(scr_idle, LV_SCROLLBAR_MODE_OFF);
    
    // === Row 1: Top Bar (Y: 2) ===
    lv_obj_t *lbl_title = lv_label_create(scr_idle);
#if GUI_MONITOR_DISPLAY_MODE == 1
    lv_label_set_text(lbl_title, ""); // Hide to make room for CPU info
#else
    lv_label_set_text(lbl_title, "T-Dongle");
#endif
    lv_obj_set_style_text_color(lbl_title, lv_color_hex(0x00FFFF), 0); // Cyan for product name
    lv_obj_set_style_text_font(lbl_title, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_letter_space(lbl_title, -1, 0); // Compress width
    lv_obj_align(lbl_title, LV_ALIGN_TOP_LEFT, 2, 4);
    
    lbl_sd = lv_label_create(scr_idle);
#if GUI_MONITOR_DISPLAY_MODE == 1
    // Initial placeholder, updated by timer
    lv_label_set_text(lbl_sd, "CPU:--- T:--");
    lv_obj_set_style_text_color(lbl_sd, lv_color_hex(0xAA00AA), 0); // Purple
#else
    update_sd_status(metrics);
#endif
    lv_obj_set_style_text_font(lbl_sd, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_letter_space(lbl_sd, -1, 0);
    lv_obj_align(lbl_sd, LV_ALIGN_TOP_RIGHT, -2, 4);

    lbl_temp = lv_label_create(scr_idle);
    lv_label_set_text(lbl_temp, "--'C");
    lv_obj_set_style_text_color(lbl_temp, lv_color_hex(0xFFA500), 0);
    lv_obj_set_style_text_font(lbl_temp, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_letter_space(lbl_temp, -1, 0);
#if GUI_MONITOR_DISPLAY_MODE == 1
    // Move to top left since we hid Dongle S3 text
    lv_obj_align(lbl_temp, LV_ALIGN_TOP_LEFT, 2, 4);
#else
    // Reserve the centre column; three-digit SD capacities need the right edge.
    lv_obj_align(lbl_temp, LV_ALIGN_TOP_MID, 0, 4);
#endif

    // === Row 2: Status Row (Y: 18) ===
    lbl_idle_status = lv_label_create(scr_idle);
    lv_label_set_text(lbl_idle_status, "USB ready");
    lv_obj_set_style_text_color(lbl_idle_status, lv_color_hex(0x00FF00), 0);
    lv_obj_set_style_text_font(lbl_idle_status, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_letter_space(lbl_idle_status, -1, 0);
    lv_obj_align(lbl_idle_status, LV_ALIGN_TOP_LEFT, 2, 18);

    lbl_heap = lv_label_create(scr_idle);
    lv_label_set_text(lbl_heap, "RAM:--K");
    lv_obj_set_style_text_color(lbl_heap, lv_color_hex(0xAAAAAA), 0);
    lv_obj_set_style_text_font(lbl_heap, &lv_font_unscii_8, 0);
    lv_obj_set_style_text_letter_space(lbl_heap, -1, 0);
    lv_obj_align(lbl_heap, LV_ALIGN_TOP_RIGHT, -2, 18);

    // Pause this shared timer while the panel sleeps.
    metrics_timer = lv_timer_create(metrics_update_timer_cb, 2000, NULL);

    // 3. FIDO Request Screen
    scr_fido = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(scr_fido, lv_color_hex(0xAA0000), 0); // Dark red background
    
    lbl_request_title = lv_label_create(scr_fido);
    lv_obj_set_style_text_color(lbl_request_title, lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_style_text_font(lbl_request_title, &lv_font_montserrat_12, 0);
    lv_obj_align(lbl_request_title, LV_ALIGN_TOP_MID, 0, 12);

    lbl_request_action = lv_label_create(scr_fido);
    lv_obj_set_style_text_color(lbl_request_action, lv_color_hex(0xFFFFFF), 0);
    lv_obj_set_style_text_align(lbl_request_action, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_font(lbl_request_action, &lv_font_montserrat_12, 0);
    lv_obj_align(lbl_request_action, LV_ALIGN_CENTER, 0, 10);
}

void gui_show_boot_logo(void) {
    if (lv_disp_get_scr_act(NULL) == scr_boot) return;
    gui_anim_stop();
    lv_disp_load_scr(scr_boot);
}

void gui_show_idle(const char *text, uint32_t color) {
    lv_label_set_text(lbl_idle_status, text);
    lv_obj_set_style_text_color(lbl_idle_status, lv_color_hex(color), 0);
    if (lv_screen_active() != scr_idle) {
        metrics_update_timer_cb(NULL);
        lv_screen_load(scr_idle);
    }
    gui_anim_start(scr_idle);
}

void gui_show_request(const char *title, bool awaiting_button, uint32_t color) {
    gui_anim_stop();
    lv_obj_set_style_bg_color(scr_fido, lv_color_hex(color), 0);
    lv_label_set_text(lbl_request_title, title);
    lv_label_set_text(lbl_request_action, awaiting_button ? "Press button" : "Check the host");
    if (lv_screen_active() != scr_fido) lv_screen_load(scr_fido);
}

// Pause/resume the periodic hardware-metrics timer. Caller MUST already hold
// xGuiSemaphore (LVGL timer APIs are not thread-safe). Pausing on sleep stops the
// background label updates that would otherwise keep repainting/flushing the panel
// while it is dark, saving CPU/SPI/power.
void gui_metrics_set_active(bool active) {
    if (!metrics_timer) return;
    if (active) {
        lv_timer_resume(metrics_timer);
    } else {
        lv_timer_pause(metrics_timer);
    }
}
