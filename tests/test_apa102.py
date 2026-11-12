"""Exercise the real ESP APA102 driver with recorded GPIO writes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

class Apa102Bounds(unittest.TestCase):
    def test_brightness_limits_and_invalid_gpio(self):
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp);(d/'driver').mkdir()
            (d/'picokeys.h').write_text('''
#include <stdint.h>
#include <stdbool.h>
#define ESP_PLATFORM 1
#define PHY_OPT_DIMM 1
#define MIN(a,b) ((a)<(b)?(a):(b))
static struct { unsigned opts; bool led_gpio_present,led_brightness_present; uint8_t led_gpio,led_brightness; } phy_data;
''')
            (d/'button.h').write_text('')
            (d/'esp_log.h').write_text('#define ESP_LOGE(...) ((void)0)\n')
            (d/'driver/gpio.h').write_text('''
typedef int gpio_num_t;
#define GPIO_NUM_40 40
#define GPIO_NUM_39 39
#define GPIO_IS_VALID_OUTPUT_GPIO(p) ((p)>=0 && (p)<49)
#define GPIO_MODE_OUTPUT 1
#define GPIO_PULLUP_DISABLE 0
#define GPIO_PULLDOWN_DISABLE 0
#define GPIO_INTR_DISABLE 0
#define ESP_OK 0
typedef struct { uint64_t pin_bit_mask; int mode,pull_up_en,pull_down_en,intr_type; } gpio_config_t;
static int writes,configs,config_result;
static int gpio_config(const gpio_config_t *c) { (void)c;configs++;return config_result; }
static void gpio_set_level(int p,int v) { (void)p;(void)v;writes++; }
''')
            source=ROOT/'pico-keys-sdk/src/led/led_apa102.c'
            (d/'test.c').write_text('#include "'+str(source)+'"\n'+r'''
#include <assert.h>
#include <math.h>
int main(void) {
 phy_data.opts=PHY_OPT_DIMM;phy_data.led_brightness_present=true;
 led_driver_init_apa102();assert(apa102_ready && configs==1);
 for(unsigned b=0;b<=255;b++) {
  phy_data.led_brightness=b;
  led_driver_color_apa102(LED_COLOR_WHITE,UINT32_MAX,1.0f);
  assert((apa102_last_frame>>24)<=31);
  if(b==0) assert(apa102_last_frame==0);
  if(b>=MAX_BTNESS) assert(apa102_last_frame==0x1fffffff);
 }
 led_driver_color_apa102(255,UINT32_MAX,INFINITY);assert(apa102_last_frame==0);
 led_driver_color_apa102(LED_COLOR_WHITE,MAX_BTNESS,NAN);assert(apa102_last_frame==0);
 led_driver_color_apa102(LED_COLOR_WHITE,MAX_BTNESS,-1);assert(apa102_last_frame==0);
 int before=writes;
 led_driver_color_apa102(LED_COLOR_WHITE,0,1);assert(writes==before);
 phy_data.led_gpio_present=true;phy_data.led_gpio=255;
 led_driver_init_apa102();assert(!apa102_ready && writes==before);
 phy_data.led_gpio=39;led_driver_init_apa102();assert(!apa102_ready && writes==before);
 phy_data.led_gpio=40;config_result=-1;
 led_driver_init_apa102();assert(!apa102_ready && writes==before);
 return 0;
}
''')
            subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                '-fsanitize=address,undefined','-I',str(d),'-I',str(ROOT/'pico-keys-sdk/src'),
                str(d/'test.c'),'-o',str(d/'test')],check=True)
            subprocess.run([str(d/'test')],check=True,capture_output=True)
if __name__=='__main__': unittest.main()
