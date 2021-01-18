#include "pch.h"
#include "InfELKtrationInjectLib.h"
#include "Logger.h"
#include "Patcher.h"

#include <iostream>

void injectMain() {
	PatchTarget esClientPublishEvents;

	Logger::Info("Initializing injection code");

	DWORD_PTR textBase = 0x401000;
	SIZE_T textSize = 0x2137000;

	Patcher::EnableRwxOnSection((LPVOID)0x401000, 0x2137000);
	Patcher::NopRange(0xac6d5a, 3);

	esClientPublishEvents.origBaseAddr = (LPVOID)0xac6d60;
	esClientPublishEvents.origSize = 0xc4f;

	Patcher::TrampolineFunction(&esClientPublishEvents);
	
	Logger::Info("Exiting");
}