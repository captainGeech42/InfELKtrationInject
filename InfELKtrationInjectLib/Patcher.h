#pragma once
class Patcher
{
public:
	static bool EnableRwxOnSection(LPVOID base, SIZE_T size);
	static inline void NopByte(DWORD_PTR addr);
	static void NopRange(DWORD_PTR addr, SIZE_T count);
};

