#include "pch.h"
#include "Logger.h"
#include <iostream>
#include <processthreadsapi.h>

void Logger::writeLogMessage(const char* type, const char* format, va_list arg) {
	SYSTEMTIME systemTime;

	GetSystemTime(&systemTime);

	printf_s("%d/%02d/%02d %02d:%02d:%02d [%s] ", systemTime.wYear,
		systemTime.wMonth,
		systemTime.wDay,
		systemTime.wHour,
		systemTime.wMinute,
		systemTime.wSecond,
		type);
	vprintf_s(format, arg);
	printf("\n");
}

void Logger::Info(const char* format, ...) {
	va_list args;

	va_start(args, format);

	Logger::writeLogMessage("INFO", format, args);

	va_end(args);
}

void Logger::Warning(const char* format, ...) {
	va_list args;

	va_start(args, format);

	Logger::writeLogMessage("WARNING", format, args);

	va_end(args);
}

void Logger::Error(const char* format, ...) {
	va_list args;

	va_start(args, format);

	Logger::writeLogMessage("ERROR", format, args);

	va_end(args);
}

void Logger::LastError() {
	DWORD eNum;
	char error[256];

	eNum = GetLastError();
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, eNum, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), error, 256, NULL);

	error[strcspn(error, ".\r\n")] = 0;

	Logger::Error("Error message (%d): %s", eNum, error);
}
