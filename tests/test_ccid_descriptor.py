"""Run native CCID descriptor adaptation without a USB controller."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]

class CcidDescriptor(unittest.TestCase):
    def test_descriptor_bounds_and_endpoint_errors(self):
        source=(ROOT/'pico-keys-sdk/src/usb/ccid/ccid.c').read_text()
        function=source[source.index('static uint16_t ccid_open('):source.index('// Support for parameterized reset')]
        harness=r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#define PICO_PLATFORM 1
#define TU_VERIFY(x,v) do { if(!(x)) return v; } while(0)
#define TU_ASSERT TU_VERIFY
#define TUSB_CLASS_SMART_CARD 11
#define TUSB_CLASS_VENDOR_SPECIFIC 255
typedef struct { uint8_t bLength,bDescriptorType,bInterfaceNumber,bAlternateSetting,bNumEndpoints,bInterfaceClass,bInterfaceSubClass,bInterfaceProtocol,iInterface; } tusb_desc_interface_t;
typedef struct { uint8_t bLength,bDescriptorType,bEndpointAddress,rest[4]; } tusb_desc_endpoint_t;
struct ccid_class_descriptor { uint8_t data[54]; };
static uint8_t itf_num;
static int calls,fail_vendor,fail_endpoint;
static uint8_t *notification;
static unsigned desc_len(void) { return sizeof(tusb_desc_interface_t)+54+TUSB_SMARTCARD_CCID_EPS*7; }
static uint16_t vendord_open(uint8_t port,const tusb_desc_interface_t *d,uint16_t len) {
 (void)port;calls++;assert(d->bInterfaceClass==255);assert(len==9+54+14);
 return fail_vendor ? 0 : len;
}
#if TUSB_SMARTCARD_CCID_EPS==3
static bool usbd_edpt_open(uint8_t port,const tusb_desc_endpoint_t *ep) {
 (void)port;assert(ep->bEndpointAddress==0x83);return !fail_endpoint;
}
static bool usbd_edpt_xfer(uint8_t port,uint8_t ep,uint8_t *data,uint16_t len) {
 (void)port;assert(ep==0x83 && len==2);notification=data;return true;
}
#endif
'''+function+r'''
int main(void) {
 uint8_t data[9+54+3*7]={0};
 tusb_desc_interface_t *d=(void*)data;
 assert(ccid_open(0,0,100)==0);
 for(unsigned n=0;n<desc_len();n++) assert(ccid_open(0,d,n)==0);
 assert(calls==0);
 d->bInterfaceClass=11;d->bNumEndpoints=TUSB_SMARTCARD_CCID_EPS;d->bInterfaceNumber=4;
 data[9+54+2*7+2]=0x83;
 for(unsigned n=9;n<desc_len();n++) assert(ccid_open(0,d,n)==0);
 assert(calls==0);
 fail_vendor=1;assert(ccid_open(0,d,sizeof(data))==0);fail_vendor=0;
#if TUSB_SMARTCARD_CCID_EPS==3
 fail_endpoint=1;assert(ccid_open(0,d,sizeof(data))==0);fail_endpoint=0;
#endif
 assert(ccid_open(0,d,sizeof(data))==desc_len());assert(itf_num==4);
#if TUSB_SMARTCARD_CCID_EPS==3
 assert(notification[0]==0x50 && notification[1]==3);
#else
 (void)fail_endpoint;(void)notification;
#endif
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp);(d/'test.c').write_text(harness)
            for endpoints in (2,3):
                subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined','-DTUSB_SMARTCARD_CCID_EPS='+str(endpoints),
                    str(d/'test.c'),'-o',str(d/'test')],check=True)
                subprocess.run([str(d/'test')],check=True,capture_output=True)
if __name__=='__main__': unittest.main()
