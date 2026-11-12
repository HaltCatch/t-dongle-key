/* Diagnostic only: loaded into RAM, never installed in the application partition. */
#include <sys/stat.h>
#include <time.h>
#include "esp_heap_caps.h"
#include "esp_system.h"

static int audit_fsync(int fd);
static ssize_t audit_write(int fd, const void *data, size_t length);
#define fsync audit_fsync
#define write audit_write
#include "../../../pico-keys-sdk/src/sd_logger.c"
#undef fsync
#undef write
extern int fsync(int fd);
extern ssize_t write(int fd, const void *buf, size_t length);

static atomic_bool inject_short, inject_full, inject_sync_error;
static atomic_uint syncs, short_writes;

static int audit_fsync(int fd) {
    if (atomic_load(&inject_sync_error)) {
        errno = EIO;
        return -1;
    }
    int rc = fsync(fd);
    if (!rc) atomic_fetch_add(&syncs, 1);
    return rc;
}

static ssize_t audit_write(int fd, const void *data, size_t length) {
    if (atomic_exchange(&inject_full, false)) return 0;
    if (length > 128 && atomic_exchange(&inject_short, false)) {
        atomic_fetch_add(&short_writes, 1);
        return write(fd, data, 128);
    }
    return write(fd, data, length);
}

bool picokey_sd_logger_pins(sd_logger_pins_t *pins) {
    *pins = (sd_logger_pins_t){.clk = 12, .cmd = 16, .d0 = 14};
    return true;
}

static esp_err_t mount_reader(sdmmc_card_t **card) {
    const esp_vfs_fat_sdmmc_mount_config_t config = {.max_files = 1};
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    sdmmc_slot_config_t slot = SDMMC_SLOT_CONFIG_DEFAULT();
    slot.width = 1;
    sd_logger_pins_t pins;
    picokey_sd_logger_pins(&pins);
    slot.clk = pins.clk;
    slot.cmd = pins.cmd;
    slot.d0 = pins.d0;
    slot.flags |= SDMMC_SLOT_FLAG_INTERNAL_PULLUP;
    return esp_vfs_fat_sdmmc_mount(MOUNT_PATH, &host, &slot, &config, card);
}

static unsigned newest_log(void) {
    DIR *dir = opendir(MOUNT_PATH);
    unsigned newest = 0;
    if (!dir) return 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        const char *name = entry->d_name;
        if (strspn(name, "0123456789") != 8 || strcasecmp(name + 8, ".TXT")) continue;
        unsigned index = strtoul(name, NULL, 10);
        if (index > newest) newest = index;
    }
    closedir(dir);
    return newest;
}

static FILE *read_log(unsigned index) {
    if (!index) return NULL;
    char path[32];
    snprintf(path, sizeof(path), MOUNT_PATH "/%08u.TXT", index);
    return fopen(path, "r");
}

static void inspect_production(void) {
    sdmmc_card_t *card;
    esp_err_t rc = mount_reader(&card);
    printf("AUDIT MOUNT rc=0x%x\n", (unsigned)rc);
    if (rc != ESP_OK) return;
    uint64_t total, free_bytes;
    rc = esp_vfs_fat_info(MOUNT_PATH, &total, &free_bytes);
    if (rc == ESP_OK) printf("AUDIT FAT total=%llu free=%llu\n",
        (unsigned long long)total, (unsigned long long)free_bytes);
    unsigned newest = newest_log();
    // A recovery boot or earlier diagnostic can be the newest file. Keep a
    // bounded history so it cannot hide the failing application's last events.
    unsigned first = newest > 7 ? newest - 7 : 1;
    for (unsigned index = first; index <= newest; ++index) {
        FILE *f = read_log(index);
        if (!f) continue;
        printf("AUDIT BOOT_FILE %08u.TXT\n", index);
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            const char *allowed[] = {"SD_LOG", "BOOT:", "USER_PRESENCE:", "GUI_PORT:",
                "RESOURCES:", "STORAGE:", "OTP_HID:", "USB_HID:", "E (", "W ("};
            for (size_t i = 0; i < sizeof(allowed)/sizeof(*allowed); ++i) {
                if (strstr(line, allowed[i])) {
                    printf("AUDIT FILE %s", line);
                    break;
                }
            }
        }
        printf("AUDIT FILE_END bytes=%ld error=%d\n", ftell(f), ferror(f));
        fclose(f);
    }
    esp_vfs_fat_sdcard_unmount(MOUNT_PATH, card);
}

static int discard_console(const char *fmt, va_list args) {
    (void)fmt;
    (void)args;
    return 0;
}

static void record(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    sd_log_vprintf(fmt, args);
    va_end(args);
}

static void verify_writer(void) {
    puts("AUDIT writer starting");
    sd_logger_early_init();
    ESP_LOGI("EARLY_TEST", "before SD mount");
    sd_logger_init();
    if (!atomic_load(&log_writable)) {
        puts("AUDIT FAIL writer not available");
        return;
    }
    puts("AUDIT writer ready");
    console_vprintf = discard_console;
    atomic_store(&inject_short, true);
    char payload[701];
    memset(payload, 'x', sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = 0;
    unsigned before = atomic_load(&syncs);
    for (unsigned i = 0; i < 200; ++i) {
        record("AUDIT_SEQUENCE %03u %s\n", i, payload);
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    unsigned during = atomic_load(&syncs) - before;
    vTaskDelay(pdMS_TO_TICKS(500));
    puts("AUDIT paced sequence written");
    unsigned normal_loss = atomic_load(&queue_lost) + atomic_load(&format_lost);

    // Force overload and an over-limit record, then let the marker reach FAT.
    for (unsigned i = 0; i < 300; ++i) record("AUDIT_BURST %s\n", payload);
    record("%05000d", 0);
    vTaskDelay(pdMS_TO_TICKS(750));
    unsigned dropped = atomic_load(&queue_lost);
    unsigned rejected = atomic_load(&format_lost);

    // Simulate a media failure and confirm it changes the visible status.
    atomic_store(&inject_sync_error, true);
    record("AUDIT_FAULT sync-error\n");
    for (unsigned i = 0; i < 50 && atomic_load(&log_writable); ++i)
        vTaskDelay(pdMS_TO_TICKS(20));
    if (atomic_load(&log_writable)) {
        puts("AUDIT FAIL sync error did not stop writer");
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(100));
    FILE *f = read_log(newest_log());
    unsigned records = 0, burst_saved = 0;
    bool marker = false, complete = true, early_saved = false;
    char line[1024], expected[1024], loss[112];
    snprintf(loss, sizeof(loss), "SD_LOG LOSS total_queue=%u total_format=%u\n", dropped, rejected);
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "EARLY_TEST: before SD mount")) early_saved = true;
            if (strncmp(line, "AUDIT_SEQUENCE ", 15) == 0) {
                snprintf(expected, sizeof(expected), "AUDIT_SEQUENCE %03u %s\n", records, payload);
                if (strcmp(line, expected)) complete = false;
                ++records;
            }
            if (strncmp(line, "AUDIT_BURST ", 12) == 0) {
                snprintf(expected, sizeof(expected), "AUDIT_BURST %s\n", payload);
                if (strcmp(line, expected)) complete = false;
                ++burst_saved;
            }
            if (!strcmp(line, loss)) marker = true;
        }
        complete &= !ferror(f);
        fclose(f);
    }
    atomic_store(&inject_full, true);
    bool full_detected = !write_all("x", 1) && errno == ENOSPC;
    bool pass = records == 200 && complete && early_saved && !normal_loss && during >= 2 &&
        atomic_load(&short_writes) == 1 && dropped && burst_saved + dropped == 300 &&
        rejected == 1 && marker && sd_logger_has_error() && full_detected;
    printf("AUDIT %s records=%u early_saved=%d normal_loss=%u live_syncs=%u short_write=%u burst_lost=%u format_lost=%u loss_marker=%d io_error=%d full_detected=%d\n",
        pass ? "PASS" : "FAIL", records, early_saved, normal_loss, during, atomic_load(&short_writes),
        dropped, rejected, marker, sd_logger_has_error(), full_detected);
}

void app_main(void) {
    vTaskDelay(pdMS_TO_TICKS(2500));
    puts("TDONGLE_SD_AUDIT_BEGIN");
    inspect_production();
    verify_writer();
    puts("TDONGLE_SD_AUDIT_END");
    fflush(stdout);
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();
}
