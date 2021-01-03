#include "pch.h"
#include "InfELKtrationInjectLib.h"
#include <fileapi.h>

#include <iostream>

void injectMain() {
	HANDLE hFile;

	std::cout << "inject main" << std::endl;

	hFile = CreateFileA("C:\\test.txt", GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	WriteFile(hFile, "test", 4, NULL, NULL);

	CloseHandle(hFile);
}