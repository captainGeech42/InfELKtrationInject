#!/bin/bash

for asm_file in $(ls *.S); do
    echo "[~] building $asm_file"
    # https://stackoverflow.com/a/965072
    base="${asm_file%.*}"

    # build object file and extract .text
    gcc -m64 -c -o $base.o $asm_file && \
    objcopy -S -O binary -j .text $base.o $base.bin
done

echo "[~] done"