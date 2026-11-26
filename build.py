# -*- coding: utf-8 -*-
"""
Сборка syryx.exe из sysinfo.py (PyInstaller, один файл, без консоли).

Запуск:  python build.py
Результат: dist\\syryx.exe  + копия в корне папки (syryx.exe)

Требуется: pip install pyinstaller pillow
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
NAME = "syryx"
DESC = "Syryx"
VER = (1, 0, 0, 0)
ICON = os.path.join(HERE, "syryx.ico")
VERSION_FILE = os.path.join(HERE, "build", "version_info.txt")
DIST = os.path.join(HERE, "dist")
WORK = os.path.join(HERE, "build", "work")
SPEC = os.path.join(HERE, "build")


def make_icon():
    """Синяя плашка с «S» — рисуется Pillow и сохраняется как многоразмерный .ico."""
    from PIL import Image, ImageDraw, ImageFont

    size = 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # фон с вертикальным градиентом
    top, bottom = (46, 124, 240), (16, 60, 150)
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, size - 1, size - 1),
                                           radius=58, fill=255)
    grad = Image.new("RGB", (1, size))
    for y in range(size):
        k = y / (size - 1)
        grad.putpixel((0, y), tuple(
            int(top[i] + (bottom[i] - top[i]) * k) for i in range(3)))
    grad = grad.resize((size, size))
    img.paste(grad, (0, 0), mask)

    # надпись S
    font = None
    for name in ("segoeuib.ttf", "arialbd.ttf", "tahomabd.ttf"):
        try:
            font = ImageFont.truetype(name, 156)
            break
        except OSError:
            continue
    if font is None:
        font = ImageFont.load_default()
    text = "S"
    box = d.textbbox((0, 0), text, font=font)
    tx = (size - (box[2] - box[0])) / 2 - box[0]
    ty = (size - (box[3] - box[1])) / 2 - box[1]
    d.text((tx + 4, ty + 4), text, font=font, fill=(0, 0, 0, 70))
    d.text((tx, ty), text, font=font, fill=(255, 255, 255, 255))

    img.save(ICON, sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                          (64, 64), (128, 128), (256, 256)])
    return ICON


def make_version_file():
    os.makedirs(os.path.dirname(VERSION_FILE), exist_ok=True)
    v = f"{VER[0]}.{VER[1]}.{VER[2]}.{VER[3]}"
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={VER}, prodvers={VER},
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
    date=(0, 0)),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', 'Syryx'),
        StringStruct('FileDescription', '{DESC}'),
        StringStruct('FileVersion', '{v}'),
        StringStruct('InternalName', '{NAME}'),
        StringStruct('OriginalFilename', '{NAME}.exe'),
        StringStruct('ProductName', '{DESC}'),
        StringStruct('ProductVersion', '{v}'),
        StringStruct('LegalCopyright', 'Syryx')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    with open(VERSION_FILE, "w", encoding="utf-8") as f:
        f.write(content)
    return VERSION_FILE


def build():
    icon = make_icon()
    ver = make_version_file()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onefile", "--windowed", "--noupx",
        "--name", NAME,
        "--icon", icon,
        "--version-file", ver,
        "--distpath", DIST,
        "--workpath", WORK,
        "--specpath", SPEC,
        os.path.join(HERE, "sysinfo.py"),
    ]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True, cwd=HERE)

    exe = os.path.join(DIST, f"{NAME}.exe")
    if not os.path.exists(exe):
        raise SystemExit("Сборка не дала exe-файл")
    shutil.copy2(exe, os.path.join(HERE, f"{NAME}.exe"))

    size = os.path.getsize(exe) / (1 << 20)
    print(f"\nГотово: {exe}  ({size:.1f} МБ)")
    print(f"Копия:  {os.path.join(HERE, NAME + '.exe')}")


if __name__ == "__main__":
    build()
