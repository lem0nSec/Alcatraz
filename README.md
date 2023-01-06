# Alcatraz

:dart: Alcatraz is a basic **self-replicating Virus** I developed for educational and academic purposes. 

:hammer: I always wanted to create an 'old-school' program in pure Assembly, and here's the code!

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Disclaimer

This code must not be used to cause damage. The author is not responsible for its usage. The goal of this repository is to explain how a basic PE-file infector works, how it moves throughout the system, as well as how it identifies and self-replicates into executable images.

**Bear in mind that although the code may crash at some point due to the fact that it's still in TESTING phase, running Alcatraz may harm your system files.**

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

# Characteristics

:pushpin: Dinamically resolves Kernel32.dll APIs and stores them in memory;

:pushpin: Searches for, proactively identifies and targets 64bit .exe files;

:pushpin: Can recursively search for files (Directory_mode / File_mode);

:pushpin: Self-replicates past the target entrypoint (.text section).
