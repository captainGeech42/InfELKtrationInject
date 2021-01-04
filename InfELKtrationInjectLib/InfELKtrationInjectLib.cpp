#include "pch.h"
#include "InfELKtrationInjectLib.h"
#include "Logger.h"
#include "Patcher.h"

#include <iostream>

void injectMain() {
	Logger::Info("Initializing injection code");

	DWORD_PTR textBase = 0x401000;
	SIZE_T textSize = 0x2137000;

	Patcher::EnableRwxOnSection((LPVOID)0x401000, 0x2137000);
	Patcher::NopRange(0xac6d5a, 3);
	
	Logger::Info("Exiting");
}