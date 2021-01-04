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
