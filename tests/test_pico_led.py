"""Run the actual CYW43 renderer against a recorded GPIO, without a board."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PicoLed(unittest.TestCase):
    def test_confirmation_is_distinct_and_does_not_flood_gpio(self):
        with tempfile.TemporaryDirectory(prefix="pico-led-") as temp:
            directory = Path(temp)
            (directory / "pico").mkdir()
            (directory / "picokeys.h").write_text(r'''
#include <stdint.h>
#include <stdbool.h>
#define CYW43_WL_GPIO_LED_PIN 0
#define PHY_OPT_LED_STEADY 1
static struct { uint32_t opts; bool led_gpio_present; uint8_t led_gpio; } phy_data;
''')
            (directory / "pico/cyw43_arch.h").write_text(r'''
static int writes, state, selected_gpio;
static void cyw43_arch_init(void) {}
static void cyw43_arch_gpio_put(unsigned gpio, bool value) {
    writes++; state=value; selected_gpio=gpio;
}
''')
            source = ROOT / "pico-keys-sdk/src/led/led_cyw43.c"
            harness = '#include "' + str(source) + '"\n' + r'''
#include <assert.h>
led_driver_t *led_driver = &led_driver_cyw43;
static uint32_t mode;
uint32_t led_get_mode(void) { return mode; }
static void check(uint32_t now, bool expected) {
    assert(led_driver_cyw43.render_status(now)); assert(state == expected);
}
int main(void) {
    mode=MODE_MOUNTED;
    check(1000,true); check(1039,true); check(1040,false);
    for(uint32_t t=1041;t<4000;t++) check(t,false);
    assert(writes==2); check(4000,true);
    mode=MODE_BUTTON;
    check(4100,true); check(4249,true); check(4250,false);
    check(4399,false); check(4400,true); check(4549,true);
    check(4550,false); check(5099,false); check(5100,true);
    // Steady-idle preference must not suppress a physical confirmation cue.
    phy_data.opts=PHY_OPT_LED_STEADY; check(5250,false);
    mode=MODE_MOUNTED; check(5300,true); check(9000,true);
    mode=MODE_SUSPENDED; check(9001,false);
    mode=MODE_BUTTON; check(9002,true);
    mode=MODE_ALWAYS_OFF; check(9003,false);
    mode=MODE_ALWAYS_ON; check(9004,true);
    // A new waiting phase starts at the first pulse even across timer wrap.
    mode=MODE_BUTTON; check(UINT32_MAX-99,true); check(50,false);
    check(200,true); check(350,false);
    phy_data.led_gpio_present=true; phy_data.led_gpio=2;
    check(351,false); assert(selected_gpio==2);
    led_driver=0; int before=writes;
    assert(!led_driver_cyw43.render_status(352)); assert(writes==before);
    return 0;
}
'''
            test_source = directory / "test.c"
            test_source.write_text(harness)
            binary = directory / "test"
            subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(directory), "-I", str(ROOT / "pico-keys-sdk/src"),
                            str(test_source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
