/*
MIT License

Copyright (c) 2022 Xinyuan-LilyGO

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#pragma once
#include "esp_lcd_st7735.h"

// LilyGO T-Dongle-S3, commit 03d51691e70271aeb988d0d1d930650595176736:
// examples/lcd/bsp_lcd/esp_lcd_st7735.c, vendor_specific_init_default.
// Reuse the panel's power/gamma setup through the driver's vendor_config API.
// The driver already performs hardware reset and SLPOUT with a 100 ms wait.
// Top that wait up to 120 ms; avoid the example's duplicate reset/sleep-out.
// Keep COLMOD under driver control and DISPON after the first complete frame.
static const st7735_lcd_init_cmd_t tdongle_lcd_init[] = {
    {0x00, NULL, 0, 20},
    {ST7735_FRMCTR1, (uint8_t[]){0x05, 0x3A, 0x3A}, 3, 0},
    {ST7735_FRMCTR2, (uint8_t[]){0x05, 0x3A, 0x3A}, 3, 0},
    {ST7735_FRMCTR3, (uint8_t[]){0x05, 0x3A, 0x3A, 0x05, 0x3A, 0x3A}, 6, 0},
    {ST7735_INVCTR, (uint8_t[]){0x03}, 1, 0},
    {ST7735_PWCTR1, (uint8_t[]){0x62, 0x02, 0x04}, 3, 0},
    {ST7735_PWCTR2, (uint8_t[]){0xC0}, 1, 0},
    {ST7735_PWCTR3, (uint8_t[]){0x0D, 0x00}, 2, 0},
    {ST7735_PWCTR4, (uint8_t[]){0x8D, 0x6A}, 2, 0},
    {ST7735_PWCTR5, (uint8_t[]){0x8D, 0xEE}, 2, 0},
    {ST7735_VMCTR1, (uint8_t[]){0x0E}, 1, 0},
    {ST7735_INVON, (uint8_t[]){0x00}, 1, 0},
    {ST7735_GMCTRP1, (uint8_t[]){0x10, 0x0E, 0x02, 0x03, 0x0E, 0x07, 0x02, 0x07, 0x0A, 0x12, 0x27, 0x37, 0x00, 0x0D, 0x0E, 0x10}, 16, 0},
    {ST7735_GMCTRN1, (uint8_t[]){0x10, 0x0E, 0x03, 0x03, 0x0F, 0x06, 0x02, 0x08, 0x0A, 0x13, 0x26, 0x36, 0x00, 0x0D, 0x0E, 0x10}, 16, 0},
    {ST7735_NORON, (uint8_t[]){0x00}, 1, 0},
};
