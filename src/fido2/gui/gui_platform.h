#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Only hardware measurements and synchronization differ between ports. */
typedef struct {
    uint32_t cpu_mhz, free_heap, flash_bytes, task_count;
    bool temperature_valid, sd_mounted, sd_error;
    float temperature_c;
    uint64_t sd_capacity;
} gui_metrics_t;

void gui_platform_init(void);
gui_metrics_t gui_platform_metrics(void);
bool gui_platform_lock(uint32_t timeout_ms);
void gui_platform_unlock(void);
