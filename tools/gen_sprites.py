import sys
try:
    from PIL import Image
except ImportError:
    print("PIL missing")
    sys.exit(1)

def to_rgb565(r, g, b):
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)

def export_c_array(img_path, name, out_file):
    img = Image.open(img_path).convert("RGBA")
    width, height = img.size
    rgb, alpha = bytearray(), bytearray()
    for r, g, b, a in img.getdata():
        if r < 50 and g < 50 and b < 50:
            r = g = b = 255
        rgb.extend(to_rgb565(r, g, b).to_bytes(2, "little"))
        alpha.append(255 if a >= 128 else 0)
    data = rgb + alpha
    out_file.write(f"LV_ATTRIBUTE_MEM_ALIGN static const uint8_t {name}_map[] = {{\n")
    for offset in range(0, len(data), 24):
        out_file.write("    " + ", ".join(f"0x{b:02X}" for b in data[offset:offset+24]) + ",\n")
    out_file.write("};\n")
    out_file.write(f"const lv_image_dsc_t {name} = {{\n")
    out_file.write("  .header.magic = LV_IMAGE_HEADER_MAGIC,\n")
    out_file.write("  .header.cf = LV_COLOR_FORMAT_RGB565A8,\n")
    out_file.write(f"  .header.w = {width},\n")
    out_file.write(f"  .header.h = {height},\n")
    out_file.write(f"  .header.stride = {width * 2},\n")
    out_file.write(f"  .data_size = sizeof({name}_map),\n")
    out_file.write(f"  .data = {name}_map,\n")
    out_file.write("};\n\n")

with open("src/fido2/gui/gui_sprites.c", "w") as f:
    f.write('#include "lvgl.h"\n\n')
    
    for i in range(10):
        export_c_array(f"tools/assets/sprites/golden-cat-page-{i}_Normal.png", f"img_gcat_{i}", f)
    for i in range(7):
        export_c_array(f"tools/assets/sprites/dinosaur-page-{i}_Normal.png", f"img_dino_{i}", f)
    for i in range(5):
        export_c_array(f"tools/assets/sprites/reindeer-sleigh-page-{i}_Normal.png", f"img_deer_{i}", f)
    for i in range(5):
        export_c_array(f"tools/assets/sprites/rubber-duck-page-{i}_Normal.png", f"img_duck_{i}", f)

print("Generated gui_sprites.c with 4 animals!")
