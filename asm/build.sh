#!/bin/bash

for asm_file in $(ls *.S); do
    base="${asm_file%.*}"
    gcc -o $base.exe -m64 $asm_file
done