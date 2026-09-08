#!/usr/bin/env bash
# File: tests/make_test_disk.sh
set -euo pipefail

IMAGE_NAME="test_drive.raw"
IMAGE_SIZE_MB=64

echo "[*] Creating 64 MB raw storage container..."
dd if=/dev/zero of="$IMAGE_NAME" bs=1M count="$IMAGE_SIZE_MB" status=none

echo "[*] Seeding live test artifacts into raw image (No sudo required)..."

# Inject JPEG signature at 1MB offset
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xFF\xDB\x00C\x00SampleImageDataHere\xFF\xD9' | dd of="$IMAGE_NAME" bs=1M seek=1 conv=notrunc status=none

# Inject WAV signature at 5MB offset
printf 'RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00D\xac\x00\x00\x88X\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00' | dd of="$IMAGE_NAME" bs=1M seek=5 conv=notrunc status=none

echo "[+] Fixture deployed safely: $(pwd)/$IMAGE_NAME"
echo "[+] Contains: 1 JPEG image, 1 RIFF WAV audio stream."
