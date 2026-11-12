#include "gui_platform.h"
#include <pthread.h>

static pthread_mutex_t gui_lock = PTHREAD_MUTEX_INITIALIZER;
/* Deliberate fixtures, never presented as measurements of the actual token. */
static gui_metrics_t metrics = {
    .cpu_mhz = 240, .free_heap = 192 * 1024, .flash_bytes = 4 * 1024 * 1024,
    .task_count = 14, .temperature_valid = true, .temperature_c = 32.0f,
    .sd_mounted = false, .sd_capacity = 0
};
void desktop_set_sd_fixture(bool mounted, bool error) {
    metrics.sd_mounted = mounted;
    metrics.sd_error = error;
    metrics.sd_capacity = mounted ? (128ULL << 30) : 0;
}
void gui_platform_init(void) {}
gui_metrics_t gui_platform_metrics(void) { return metrics; }
bool gui_platform_lock(uint32_t timeout_ms) {
    (void)timeout_ms;
    return pthread_mutex_lock(&gui_lock) == 0;
}
void gui_platform_unlock(void) { pthread_mutex_unlock(&gui_lock); }
