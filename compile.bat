@echo off

set program=alcatraz

echo "IMPORTANT: Remember to edit the first program instruction in accordance with the comment in this file"
echo:
nasm -f win64 Win64.Alcatraz.asm -o %program%.obj 2>NUL
golink /entry _saveEntryPoint /console %program%.obj kernel32.dll

Rem IMPORTANT: the first instruction of alcatraz.exe (lea rbx, [rax]) needs to be edited to 'lea rbx, [rip]'
