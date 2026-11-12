"""Exercise the real HID sender when USB completes before submission returns."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def sender_function(source, signature="int driver_write_hid(uint8_t itf, const_byte_array_t buffer) {"):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


@unittest.skipUnless(shutil.which("cc"), "requires a C compiler")
class HidCompletion(unittest.TestCase):
    def test_keyboard_capacity_and_non_ascii_boundary(self):
        source = (ROOT / "pico-keys-sdk/src/usb/hid/hid.c").read_text()
        start = source.index("static uint8_t keyboard_buffer[256];")
        end = source.index("\n#endif", start)
        source = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define MIN(a,b) ((a)<(b)?(a):(b))
#define HID_ASCII_TO_KEYCODE [65]={0,4}
#define KEYBOARD_MODIFIER_LEFTSHIFT 2
#define REPORT_ID_KEYBOARD 1
#define ITF_HID_KB 1
typedef struct { const uint8_t *data; size_t len; } const_byte_array_t;
static unsigned presses, releases;
static bool tud_hid_ready(void) { return true; }
static bool tud_hid_n_keyboard_report(uint8_t itf, uint8_t id, uint8_t mod, const uint8_t *keys) {
    (void)itf; (void)id; (void)mod;
    if (keys) ++presses; else ++releases;
    return true;
}
''' + source[start:end] + r'''
int main(void) {
    uint8_t data[256]; memset(data, 'A', sizeof(data));
    add_keyboard_buffer((const_byte_array_t){data, 255}, true);
    append_keyboard_buffer((const_byte_array_t){data, 1});
    for (unsigned i = 0; i < 600; ++i) send_hid_report(1);
    if (presses != 256 || releases != 256) return 1;
    presses = releases = 0;
    add_keyboard_buffer((const_byte_array_t){data, sizeof(data)}, true);
    for (unsigned i = 0; i < 600; ++i) send_hid_report(1);
    if (presses != 256 || releases != 256) return 2;
    presses = releases = 0;
    data[0] = 128; data[1] = 255;
    add_keyboard_buffer((const_byte_array_t){data, 3}, true);
    for (unsigned i = 0; i < 10; ++i) send_hid_report(1);
    if (presses != 1 || releases != 1) return 3;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="hid-keyboard-") as directory:
            cfile = Path(directory) / "test.c"
            binary = Path(directory) / "test"
            cfile.write_text(source)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", str(cfile), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_other_transport_computation_returns_busy_without_touch(self):
        source = (ROOT / "pico-keys-sdk/src/usb/hid/hid.c").read_text()
        function = sender_function(source, "static void reject_hid_during_other_transport_work(void) {")
        source = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define ITF_HID 0
#define ITF_HID_CTAP 0
#define TYPE_INIT 0x80
#define CTAPHID_CANCEL 0x91
#define CTAP1_ERR_CHANNEL_BUSY 6
#define WRITE_PENDING 1
typedef struct { uint32_t cid; struct { uint8_t cmd; } init; } CTAPHID_FRAME;
#define FRAME_TYPE(f) ((f)->init.cmd & 0x80)
static bool hid_reports_ready = true, other_busy = true, touch_pending = false;
static int last_write_result[1];
static struct { unsigned r_ptr, w_ptr; } hid_tx[1];
static struct { CTAPHID_FRAME frames[3]; unsigned next, count; } hid_reports;
static unsigned refusals;
static uint32_t ticks;
static uint32_t board_millis(void) { return ticks; }
#define queue_is_empty(q) (hid_reports.next == hid_reports.count)
static bool card_busy_on_other_interface(unsigned itf) { (void)itf; return other_busy; }
#define is_req_button_pending() touch_pending
static bool queue_try_peek(void *queue, CTAPHID_FRAME *out) {
    (void)queue;
    if (hid_reports.next == hid_reports.count) return false;
    *out = hid_reports.frames[hid_reports.next]; return true;
}
static bool queue_try_remove(void *queue, CTAPHID_FRAME *out) {
    if (!queue_try_peek(queue, out)) return false;
    ++hid_reports.next; return true;
}
static void hid_refuse(const CTAPHID_FRAME *request, unsigned error) {
    if (request->cid != 42 || error != CTAP1_ERR_CHANNEL_BUSY) __builtin_trap();
    ++refusals; last_write_result[0] = WRITE_PENDING;
}
''' + function + r'''
int main(void) {
    for (unsigned mode = 0; mode < 2; ++mode) {
        touch_pending = mode; refusals = 0; last_write_result[0] = 0;
        hid_reports.next = 0; hid_reports.count = 3;
        hid_reports.frames[0] = (CTAPHID_FRAME){42, {0x86}};
        hid_reports.frames[1] = (CTAPHID_FRAME){42, {CTAPHID_CANCEL}};
        hid_reports.frames[2] = (CTAPHID_FRAME){42, {0}};
        reject_hid_during_other_transport_work();
        if (!touch_pending) {
            if (refusals || hid_reports.next) return 5;
            ticks += 249;
            reject_hid_during_other_transport_work();
            if (refusals || hid_reports.next) return 6;
            ++ticks;
            reject_hid_during_other_transport_work();
        }
        if (refusals != 1 || hid_reports.next != 1) return 1;
        // In-flight endpoint backing must finish before draining other reports.
        reject_hid_during_other_transport_work();
        if (hid_reports.next != 1) return 2;
        last_write_result[0] = 0;
        reject_hid_during_other_transport_work();
        if (refusals != 1 || hid_reports.next != 3) return 3;
        other_busy = false; hid_reports.next = 0;
        reject_hid_during_other_transport_work();
        if (hid_reports.next != 0) return 4;
        other_busy = true;
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="hid-other-worker-") as directory:
            cfile = Path(directory) / "test.c"
            binary = Path(directory) / "test"
            cfile.write_text(source)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", str(cfile), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_immediate_completion_and_failed_submission(self):
        sender = sender_function((ROOT / "pico-keys-sdk/src/usb/hid/hid.c").read_text())
        source = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
typedef struct { const uint8_t *data; size_t len; } const_byte_array_t;
enum { WRITE_SUCCESS, WRITE_PENDING, WRITE_FAILED };
static int last_write_result[1];
static int submissions;
static bool reject_submission;
static bool tud_hid_n_report(uint8_t itf, uint8_t id, const uint8_t *data, uint16_t len) {
    (void)id; (void)data; (void)len;
    ++submissions;
    if (reject_submission) return false;
    /* Model a higher-priority USB task completing the transfer immediately. */
    last_write_result[itf] = WRITE_SUCCESS;
    return true;
}
''' + sender + r'''
int main(void) {
    uint8_t bytes[64] = {0};
    const_byte_array_t report = {bytes, sizeof(bytes)};
    if (driver_write_hid(0, report) != 64 || last_write_result[0] != WRITE_SUCCESS) return 1;
    if (driver_write_hid(0, report) != 64 || submissions != 2) return 2;
    last_write_result[0] = WRITE_PENDING;
    if (driver_write_hid(0, report) != 0 || submissions != 2) return 3;
    last_write_result[0] = WRITE_SUCCESS;
    reject_submission = true;
    if (driver_write_hid(0, report) != 0 || last_write_result[0] != WRITE_FAILED) return 4;
    reject_submission = false;
    if (driver_write_hid(0, report) != 64 || last_write_result[0] != WRITE_SUCCESS) return 5;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="hid-completion-") as directory:
            cfile = Path(directory) / "test.c"
            binary = Path(directory) / "test"
            cfile.write_text(source)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(cfile), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
