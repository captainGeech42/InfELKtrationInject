#pragma once

typedef struct {
	LPVOID origBaseAddr; // original function location
	SIZE_T origSize; // original function size
	LPVOID reallocBaseAddr; // new function location (after Patcher::TrampolineFunction)
	SIZE_T reallocSize; // max size available at new function location
	SIZE_T reallocUsed; // amount of mem actually being used at new function location
} PatchTarget;

class Patcher
{
public:
	static bool EnableRwxOnSection(LPVOID base, SIZE_T size);
	static inline void NopByte(DWORD_PTR addr);
	static void NopRange(DWORD_PTR addr, SIZE_T count);
	static bool TrampolineFunction(PatchTarget *target, SIZE_T padding = 300);
};
