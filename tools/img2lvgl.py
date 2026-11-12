#!/usr/bin/env python3
"""
img2lvgl.py - A script to convert images to LVGL 8.3 C array format.
Usage: python3 img2lvgl.py input.png output.c array_name
"""
import sys
import os

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow library is not installed.")
    print("Please install it using: pip install Pillow")
    sys.exit(1)

def convert_to_rgb565(r, g, b):
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)

def generate_c_array(image_path, output_path, array_name):
    try:
        img = Image.open(image_path)
    except Exception as e:
        print(f"Error opening image: {e}")
        return

    # Convert to RGBA to handle transparency
    img = img.convert("RGBA")
    width, height = img.size
    
    # We will use TRUE_COLOR_ALPHA (3 bytes per pixel: [R,G,B in 565 format (2 bytes)] + [Alpha (1 byte)])
    # Wait, LVGL 8 TRUE_COLOR_ALPHA byte order for little-endian (ESP32):
    # Byte 0: Low byte of RGB565
    # Byte 1: High byte of RGB565
    # Byte 2: Alpha channel
    
    # But wait! We swapped bytes in our driver! `buf[i] = (buf[i] >> 8) | (buf[i] << 8);`
    # This means LVGL sends little endian, and our SPI driver swaps them to big endian for ST7735.
    # So we should generate standard Little Endian RGB565 here.
    
    out_c = []
    out_c.append(f"#include \"lvgl.h\"")
    out_c.append(f"")
    out_c.append(f"const uint8_t {array_name}_map[] = {{")
    
    pixels = img.load()
    for y in range(height):
        line_bytes = []
        for x in range(width):
            r, g, b, a = pixels[x, y]
            
            c565 = convert_to_rgb565(r, g, b)
            # Little endian: low byte first
            b0 = c565 & 0xFF
            b1 = (c565 >> 8) & 0xFF
            
            line_bytes.append(f"0x{b0:02X}, 0x{b1:02X}, 0x{a:02X}")
            
        out_c.append("    " + ", ".join(line_bytes) + ",")

    out_c.append(f"}};")
    out_c.append(f"")
    out_c.append(f"const lv_img_dsc_t {array_name} = {{")
    out_c.append(f"  .header.cf = LV_IMG_CF_TRUE_COLOR_ALPHA,")
    out_c.append(f"  .header.always_zero = 0,")
    out_c.append(f"  .header.reserved = 0,")
    out_c.append(f"  .header.w = {width},")
    out_c.append(f"  .header.h = {height},")
    out_c.append(f"  .data_size = {width * height * 3},")
    out_c.append(f"  .data = {array_name}_map,")
    out_c.append(f"}};")

    with open(output_path, "w") as f:
        f.write("\n".join(out_c))
        f.write("\n")
        
    print(f"Successfully converted {image_path} -> {output_path} (Array: {array_name})")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 img2lvgl.py <input.png> <output.c> <array_name>")
        sys.exit(1)
        
    generate_c_array(sys.argv[1], sys.argv[2], sys.argv[3])
