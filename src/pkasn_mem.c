#include "pkasn_mem.h"
#ifdef UTIMACO_BUILD
#include <os_mem.h>
void* pk_mem_new(int len)
{
	return os_mem_new(len, OS_MEM_TYPE_SECURE);
}
int pk_mem_zeroise(void* dst, int len)
{
	return os_mem_set(dst, 0x00, len);
}
int pk_mem_cpy(void* dst, void* src, int len)
{
	return pk_mem_cpy(dst, src, len);
}
#else
#include <stdlib.h>
#include <string.h>
void* pk_mem_new(int length)
{
	return malloc(length);
}
void* pk_mem_set(void* dst, unsigned char chr, int len)
{
	return memset(dst, chr, len);
}
void* pk_mem_cpy(void* dst, void* src, int len)
{
	return memcpy(dst, src, len);
}
#endif

