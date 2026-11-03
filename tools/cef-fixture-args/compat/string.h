/* Minimal freestanding declarations needed by the unchanged native policy. */
#ifndef MADEIRA_CEF_FIXTURE_STRING_H
#define MADEIRA_CEF_FIXTURE_STRING_H
#include <stddef.h>
extern "C" int strcmp(const char *,const char *);
extern "C" int strncmp(const char *,const char *,size_t);
#endif
