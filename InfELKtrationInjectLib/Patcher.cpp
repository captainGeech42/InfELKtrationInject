#include "pch.h"
#include "Patcher.h"
#include "Logger.h"

bool Patcher::EnableRwxOnSection(LPVOID base, SIZE_T size) {
	DWORD oldProtections;
	MEMORY_BASIC_INFORMATION mbi;

	if (VirtualQuery(base, &mbi, sizeof(MEMORY_BASIC_INFORMATION))) {
		if (mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY) {
			// even though we are requesting PAGE_EXECUTE_READWRITE, i am 99% sure it get's COW'd by the second process making the request
			// the important thing is that we aren't W^X anymore
			Logger::Info("Permissions at 0x%p are already W&X", base);
			return true;
		}
		else {
			Logger::Info("Permissions at 0x%p aren't PAGE_EXECUTE_READWRITE (they are 0x%x), setting perms", base, mbi.Protect);
		}
	}
	else {
		Logger::Error("Failed to query memory permissions at 0x%p", base);
		Logger::LastError();
		return false;
	}

	if (VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &oldProtections)) {
		Logger::Info("Sucessfully changed memory perms at 0x%p", base);
		return true;
	}
	else {
		Logger::Error("Failed to change memory perms");
		Logger::LastError();
		return false;
	}
}

void Patcher::NopByte(DWORD_PTR addr) {
	*(BYTE*)addr = 0x90;
}

void Patcher::NopRange(DWORD_PTR addr, SIZE_T count) {
	for (int i = 0; i < count; i++) {
		Patcher::NopByte(addr + i);
	}
}

bool Patcher::TrampolineFunction(PatchTarget *target, SIZE_T padding) {
	errno_t ret;

	// allocate memory to move the function to
	target->reallocSize = target->origSize + padding;
	target->reallocBaseAddr = VirtualAlloc(NULL, target->reallocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!target->reallocBaseAddr) {
		Logger::Error("Failed to allocate memory for function trampoline");
		Logger::LastError();
		return false;
	}

	Logger::Info("Allocated 0x%x bytes at 0x%p for function trampoline", target->reallocSize, target->reallocBaseAddr);

	// copy the function over
	if ((ret = memcpy_s(target->reallocBaseAddr, target->reallocSize, target->origBaseAddr, target->origSize)) != 0) {
		Logger::Error("Failed to copy function from 0x%p to 0x%p, freeing allocated memory (error code: %d)", target->origBaseAddr, target->reallocBaseAddr, ret);

		VirtualFree(target->reallocBaseAddr, NULL, MEM_RELEASE);
		return false;
	}
	else {
		Logger::Info("Copied function from 0x%p to 0x%p", target->origBaseAddr, target->reallocBaseAddr);
	}

	// modify existing function
	// fun fact, this is 100% the worst way to do this but idk a better way (and im lazy)
	// movabs r8, 0xaabbccddeeff1122 => 49 b8 22 11 ff ee dd cc bb aa
	// jmp r8                        => 41 ff e0
	// int 3                         => cc
	*(SHORT*)target->origBaseAddr = (SHORT)0xb849;
	*(DWORD_PTR*)((DWORD_PTR*)(target->origBaseAddr) + 2) = (DWORD_PTR)target->reallocBaseAddr;
	*(DWORD*)((DWORD*)(target->origBaseAddr) + 10) = 0xcce0ff41;

	Logger::Info("Installed trampoline at 0x%p", target->reallocBaseAddr);

	return true;
}
