# Alcatraz
![](https://img.shields.io/badge/NASM-x64-brown) ![](https://img.shields.io/badge/GoLink-1.0.4.2-brightgreen) ![](https://img.shields.io/badge/License-GPL%20--%202.0-blue)

:dart: Alcatraz is a basic **self-replicating Virus** I developed for educational and academic purposes. 

:hammer: I always wanted to create an 'old-school' program in pure Assembly, so here's the code!

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Disclaimer

This code must not be used to cause damage. The author is not responsible for its usage or damages caused as a consequence of its usage. **The goal of this repository is to explain how a basic PE-file infector works, as well as how it can be detected and stopped.**

Bear in mind that although Alcatraz may crash at some point due to the fact that it's just not perfect (look at Characteristics below), **running Alcatraz may cause harm to your system files.**

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Wiki
A detailed description of the most salient parts of this code can be found in the [src](https://github.com/lem0nSec/Alcatraz/tree/main/src) directory.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Characteristics

:white_check_mark: Dinamically resolves Kernel32.dll APIs and creates a 'function table' in memory;

:white_check_mark: Searches for, proactively identifies and targets 64bit .exe files;

:white_check_mark: Can recursively search for files (Directory_mode / File_mode);

:white_check_mark: Self-replicates past the target entrypoint (.text section);

:x: The infection logic is not deterministic (some files might be unable to run Alcatraz code);

:x: Still crashes on some .dll files (I will fix this asap).
