#include "pch.h"
#include "HttpIntercept.h"

void HttpIntercept(char* reqBytes, char* respBytes, char* apiKey) {
	Logger::Info("Executing HTTP interception code");

	Logger::Info("API Key: %s", apiKey);

	int a = 3;
	a = 3 + 7;
}
