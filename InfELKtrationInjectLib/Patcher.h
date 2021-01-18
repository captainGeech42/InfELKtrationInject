#pragma once

#define FUNCTION_TABLE_ADDR 0x66420000

typedef struct {
	LPVOID targetAddr;				// target instruction location
	LPVOID patchAddr;				// set after Patcher::InstallPatch, location of patch
	SIZE_T patchSize;				// size of the patch
	unsigned char* patchContents;	// contents for the patch
} PatchTarget;

class Patcher
{
public:
	static bool EnableRwxOnSection(LPVOID base, SIZE_T size);
	static inline void NopByte(DWORD_PTR addr);
	static void NopRange(DWORD_PTR addr, SIZE_T count);
	static bool InstallPatch(PatchTarget *target);
	static bool ConfigureFunctionTable();
};
