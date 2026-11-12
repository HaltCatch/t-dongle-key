"""Incrementally mirror build inputs from Windows mounts to the WSL filesystem."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

source = Path(sys.argv[1]).resolve()
cache_base = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "tdongle"
identity = hashlib.sha256(str(source).encode()).hexdigest()[:16]
destination = (cache_base / identity / "source").resolve()
destination.mkdir(parents=True, exist_ok=True)
manifest = destination.parent / "source-manifest.json"
old = json.loads(manifest.read_text()) if manifest.exists() else {}
new = {}
trees = ["src", "desktop", "pico-fido/src", "pico-openpgp/src", "pico-keys-sdk/src",
         "pico-keys-sdk/config", "pico-keys-sdk/cmake", "third_party/lvgl",
         "pico-keys-sdk/third-party/mbedtls", "pico-keys-sdk/third-party/tinycbor",
         "pico-keys-sdk/third-party/libcvc"]
files = list(source.glob("*.cmake")) + [source / "CMakeLists.txt", source / "sdkconfig.defaults"]
files += list((source / "pico-keys-sdk").glob("*.cmake"))
for tree in trees:
    for directory, names, leaves in os.walk(source / tree):
        excluded = {".git", "docs", "tests", "__pycache__", ".github"}
        if tree != "third_party/lvgl":
            excluded.add("examples")
        names[:] = [name for name in names if name not in excluded]
        files.extend(Path(directory) / name for name in leaves if name != ".git")
for path in files:
    if not path.is_file():
        continue
    name = path.relative_to(source).as_posix()
    stat = path.stat()
    attributes = [stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]
    previous = old.get(name)
    unchanged = isinstance(previous, list) and previous[:3] == attributes
    if unchanged and os.environ.get("TDONGLE_VERIFY_SOURCE_CACHE") != "1":
        digest = previous[3]
    else:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    new[name] = attributes + [digest]
    target = destination / name
    previous_digest = previous[3] if isinstance(previous, list) else previous
    if previous_digest != digest or not target.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
for name in old.keys() - new.keys():
    target = (destination / name).resolve()
    if destination in target.parents and target.is_file():
        target.unlink()
if new != old:
    manifest.write_text(json.dumps(new, sort_keys=True))
print(destination)
