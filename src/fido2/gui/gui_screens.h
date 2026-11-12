#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void gui_screens_init(void);
void gui_show_boot_logo(void);
void gui_boot_reset(void);
void gui_boot_log(const char *message);
void gui_boot_complete(void);
bool gui_boot_finished(void);
bool gui_boot_failed(void);
void gui_show_idle(const char *text, uint32_t color);
void gui_show_request(const char *title, bool awaiting_button, uint32_t color);
void gui_metrics_set_active(bool active);

#ifdef __cplusplus
}
#endif
