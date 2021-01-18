.globl main

// this patch is intended to be written at 0xa8ccba in filebeat.exe 7.10.1
// sha256 of filebeat.exe: CC98DFCE42FFAB9BD210AD94D40634326FF2469E0A40F6647353B011390666BC

main:

// i'm 95% sure registers can be clobbered no worries
// in case they can't, save these:
// rbp, rsp, rsi, rdi, r8-r15


// allocate a stack to use
// 0x66420000 is a pointer to ntdll!NtAllocateVirtualMemory, which will make the appropriate syscall
// ^^ is allocated by the main injected DLL, this code won't ever be executed if that static alloc fails
// NtAllocateVirtualMemory(-1, 0, 0, &stack, 0x3000, 0x4)
push    $0x4        // Protect (PAGE_READWRITE)
push    $0x3000     // AllocationType (MEM_COMMIT | MEM_RESERVE)
push    $0x2000     // RegionSize
mov     %rsp, %r9
xor     %r8, %r8    // ZeroBits
xor     %rdx, %rdx  // BaseAddress
xor     %rcx, %rcx  // ProcessHandle (NtCurrentProcess() == -1)
sub     $0x1, %rcx

mov     $0x66420000, %r10
call    *%r10

// new stack is in %rax
mov     %rax, %r10

// reset stack
pop     %r8
pop     %r8
pop     %r8

// save pointers to data we care about
// (and also setting args to call up to C)
// calling convention: rcx, rdx, r8
// function signature: void HttpIntercept(char* reqBytes, char* respBytes, char* apiKey)
// [rsp+0x18]: pointer to resp data
// [rsp+0x58]: pointer to pointer to to req data
// [rsp+0x88]: pointer to api key
mov     0x18(%rsp), %rdx    // resp data
mov     0x58(%rsp), %rcx    // req data
mov     (%rcx), %rcx
mov     0x88(%r8), %rcx     // api key

// preserve existing stack at the bottom of the allocated region
mov     %rsp, (%rax)
mov     %rbp, 0x8(%rax)

// setup the new stack
add     (%r9), %r10     // add the amount of memory allocated to the base addr
                        // this puts us at the top of the allocated region
sub     $0x20, %r10     // make some head room
mov     %r10, %rsp      // set the new stack frame     
xor     %rbp, %rbp

// save the location of the bottom of the region
push    %rax

// call the C code
// this addr will be dynamically inserted by the injection DLL
mov     $0xaabbccddeeff1122, %r9
call    *%r9

// restore stack
pop     %r9
mov     (%r9), %rsp
mov     0x8(%r9), %rbp

// restore registers if need be here

// existing code that got replaced
.byte 0x48
.byte 0x8b
.byte 0x44
.byte 0x24
.byte 0x38
.byte 0x48
.byte 0x8b
.byte 0x4c
.byte 0x24
.byte 0x30
.byte 0x48
.byte 0x8b
.byte 0x54
.byte 0x24
.byte 0x28