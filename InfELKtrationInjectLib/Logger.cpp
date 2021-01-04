#include "pch.h"
#include "Logger.h"
#include <iostream>
#include <processthreadsapi.h>

void Logger::writeLogMessage(const char* type, const char* format, va_list arg) {
	SYSTEMTIME systemTime;
	DWORD pid;
	char logFilepath[1024];
	FILE* fp;

	pid = GetCurrentProcessId();

	snprintf(logFilepath, 1024, "C:\\inject_logs\\filebeat_inject_%d.log", pid);

	if (fopen_s(&fp, logFilepath, "a") != 0) return;
	if (!fp) return;

	GetSystemTime(&systemTime);

	fprintf_s(fp, "%d/%02d/%02d %02d:%02d:%02d [%s] ", systemTime.wYear,
		systemTime.wMonth,
		systemTime.wDay,
		systemTime.wHour,
		systemTime.wMinute,
		systemTime.wSecond,
		type);
	vfprintf_s(fp, format, arg);
	fprintf(fp, "\n");

	fclose(fp);
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
