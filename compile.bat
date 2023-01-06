@echo off

nasm -f win64 Win64.Alcatraz.asm -o alcatraz.obj 2>NUL
golink /entry _saveEntryPoint /console alcatraz.obj kernel32.dll
