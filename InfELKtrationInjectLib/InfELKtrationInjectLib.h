#pragma once

#ifdef INFELKTRATIONINJECTLIB_EXPORTS
#define INFELKTRATIONLIB_API __declspec(dllexport)
#else
#define INFELKTRATIONLIB_API __declspec(dllimport)
#endif

extern "C" INFELKTRATIONLIB_API void injectMain();