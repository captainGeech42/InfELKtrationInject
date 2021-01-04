#pragma once

#include <iostream>

class Logger
{
public:
	static void Info(const char* format, ...);
	static void Warning(const char* format, ...);
	static void Error(const char* format, ...);
	static void LastError();

private:
	static void writeLogMessage(const char* type, const char* format, va_list arg);
};
