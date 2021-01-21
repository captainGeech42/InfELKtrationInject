#include "pch.h"
#include "Patcher.h"
#include "Logger.h"
#include "HttpIntercept.h"

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

bool Patcher::InstallPatch(PatchTarget *target) {
	errno_t ret;

	// allocate memory to move the function to
	target->patchAddr = VirtualAlloc(NULL, target->patchSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!target->patchAddr) {
		Logger::Error("Failed to allocate memory for patch");
		Logger::LastError();
		return false;
	}

	Logger::Info("Allocated 0x%x bytes at 0x%p for patch", target->patchSize, target->patchAddr);

	// copy the function over
	if ((ret = memcpy_s(target->patchAddr, target->patchSize, target->patchContents, target->patchSize)) != 0) {
		Logger::Error("Failed to copy patch contents from 0x%p to 0x%p, freeing allocated memory (error code: %d)", target->patchContents, target->patchAddr, ret);

		VirtualFree(target->patchAddr, NULL, MEM_RELEASE);
		return false;
	}
	else {
		Logger::Info("Copied patch contents from 0x%p to 0x%p", target->patchContents, target->patchAddr);
	}

	// modify existing function
	// movabs r8, 0xaabbccddeeff1122 => 49 b8 22 11 ff ee dd cc bb aa
	// jmp r8                        => 41 ff e0
	unsigned char patch[] = {
		0x49, 0xb8, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0x41, 0xff, 0xe0
	};
	*(DWORD_PTR*)(patch + 2) = (DWORD_PTR)target->patchAddr;
	memcpy_s(target->targetAddr, 13, patch, 13);

	Logger::Info("Installed trampoline at 0x%p", target->targetAddr);

	return true;
}

bool Patcher::ConfigureFunctionTable() {
	// inject code expected some functions to be available for them to use at 0x66420000
	// this function sets that table up
	// if allocating at 0x66420000 fails, return false (which blocks installing the patches)

	DWORD_PTR *table;
	HMODULE hTmp;

	const char* targetFunctions[] = {
		"NtAllocateVirtualMemory",
		"NtFreeVirtualMemory"
	};
	const int numFuncs = 2;

	// allocate memory for the function table
	table = (DWORD_PTR *)VirtualAlloc((LPVOID)FUNCTION_TABLE_ADDR, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!table) {
		Logger::Error("Failed to allocate function table");
		Logger::LastError();
		return false;
	}

	// get a handle to ntdll
	hTmp = GetModuleHandleA("ntdll");
	if (!hTmp) {
		Logger::Error("Failed to get ntdll module handle");
		Logger::LastError();
		return false;
	}

	// add all of the ntdll functions to the function table
	for (int i = 0; i < numFuncs; i++) {
		table[i] = (DWORD_PTR)GetProcAddress(hTmp, targetFunctions[i]);
		if (!table[i]) {
			Logger::Error("Failed to get address of %s", targetFunctions[i]);
			Logger::LastError();
			return false;
		}
	}

	// add the high level patch code to the table
	table[0x100/8] = (DWORD_PTR)HttpIntercept;

	Logger::Info("Successfully configured function table at 0x%p", FUNCTION_TABLE_ADDR);
	return true;
}
