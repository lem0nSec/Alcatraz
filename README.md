# Alcatraz
![](https://img.shields.io/badge/NASM-x64-brown) ![](https://img.shields.io/badge/GoLink-1.0.4.2-brightgreen)

:dart: Alcatraz is a basic **self-replicating Virus** I developed for educational and academic purposes. 

:hammer: I always wanted to create an 'old-school' program in pure Assembly, and here's the code!

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disclaimer

This code must not be used to cause damage. The author is not responsible for its usage or damages caused as a consequence of its usage. **The goal of this repository is to explain how a basic PE-file infector works, how it moves throughout the system, as well as how it identifies and self-replicates into executable images.**

Bear in mind that although the code may crash at some point due to the fact that it's still in TESTING phase, **running Alcatraz may cause harm to your system.**

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Wiki
A detailed explanation of the most salient parts of this code can be found in the [src](https://github.com/lem0nSec/Alcatraz/tree/main/src) directory.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Characteristics

:white_check_mark: Dinamically resolves Kernel32.dll APIs and creates a 'function table' in memory;

:white_check_mark: Searches for, proactively identifies and targets 64bit .exe files;

:white_check_mark: Can recursively search for files (Directory_mode / File_mode);

:white_check_mark: Self-replicates past the target entrypoint (.text section);

:x: Does not preserve the target file code;

:x: Still crashes on some .dll files (I will fix this asap).
