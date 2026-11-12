"""Guard the established device layout against accidental upstream migrations."""
import json
from pathlib import Path
import sys

build = Path(sys.argv[1])
args = json.loads((build / "flasher_args.json").read_text())
assert args["extra_esptool_args"]["chip"] == "esp32s3", args
assert int(args["app"]["offset"], 0) == 0x10000, args["app"]
assert int(args["partition-table"]["offset"], 0) == 0x8000
assert (build / args["app"]["file"]).stat().st_size <= 0x1E0000
config = json.loads((build / "config/sdkconfig.json").read_text())
assert config["ESP_MAIN_TASK_STACK_SIZE"] >= 8192, "Startup stack too small for stored OTP containers"
assert config["LV_COLOR_FORMAT_RGB565"] is True
assert config["LV_FONT_UNSCII_8"] is True
assert config["LV_FONT_MONTSERRAT_12"] is True
print("PASS: ESP32-S3, existing app/partition offsets, app fits, shared color/font configuration")
