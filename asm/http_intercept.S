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
// NtAllocateVirtualMemory(-1, &stack, 0, &stack, 0x3000, 0x4)
push    $0x2000     // RegionSize
mov     %rsp, %r9
push    $0x0        // BaseAddress
mov     %rsp, %rdx
push    $0x4        // Protect (PAGE_READWRITE)
push    $0x3000     // AllocationType (MEM_COMMIT | MEM_RESERVE)
mov     %rsp, %r9
xor     %r8, %r8    // ZeroBits
xor     %rcx, %rcx  // ProcessHandle (NtCurrentProcess() == -1)
sub     $0x1, %rcx

// yes i know i dont know what i am doing but this fixes the stack alignment
push    $0xaa
push    $0xaa
push    $0xaa
push    $0xaa

mov     $0x66420000, %r10
call    *(%r10)

pop     %r8
pop     %r8
pop     %r8
pop     %r8

// reset stack
pop     %r8
pop     %r8

// save new stack to rax
pop     %rax

// save a copy of the base addr
mov     %rax, %r10

// finish stack reset
pop     %r8

// save pointers to data we care about
// (and also setting args to call up to C)
// calling convention: rcx, rdx, r8
// function signature: void HttpIntercept(char* reqBytes, char* respBytes, char* apiKey)
// [rsp+0x18]: pointer to resp data
// [rsp+0x58]: pointer to pointer to to req data
// [rsp+0x88]: pointer to api key
// TODO:
// there might be an edge case where the req data dereference fails if there wasn't a post body, i'm not sure
// the first request that generates a security log first generates at GET /, which looks different on the stack
mov     0x18(%rsp), %rdx    // resp data
mov     0x58(%rsp), %rcx    // req data
mov     (%rcx), %rcx
mov     0x88(%rsp), %r8     // api key

// preserve existing stack at the bottom of the allocated region
mov     %rsp, (%rax)
mov     %rbp, 0x8(%rax)

// setup the new stack
add     $0x2000, %r10   // add the amount of memory allocated to the base addr
                        // this puts us at the top of the allocated region
sub     $0x20, %r10     // make some head room
mov     %r10, %rsp      // set the new stack frame     
xor     %rbp, %rbp

// save the location of the bottom of the region
push    %rax

// call the C code
// the HTTP intercept C code is in the function table at offset 0x100
mov     $0x66420100, %r9
call    *(%r9)

// restore stack
pop     %r9
mov     (%r9), %rsp
mov     0x8(%r9), %rbp

// free allocated stack
// NtFreeVirtualMemory(-1, %r9, 0, 0x8000)
// function ptr is at 0x66420008
mov     %r9, %rdx       // BaseAddress
xor     %rcx, %rcx      // ProcessHandle
sub     $0x1, %rcx
xor     %r8, %r8        // RegionSize
mov     $0x8000, %r9    // FreeType (MEM_RELEASE)

mov     $0x66420008, %r10
call    *(%r10)

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

// jump back to existing code
mov     $0xa8ccc0, %r8
jmp     *%r8