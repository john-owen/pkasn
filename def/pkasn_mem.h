/**************************************************************************************************
 *
 * $File Identification                    $
 * $Filename          : pkasn_mem.h        $
 * $Module version    : 1.0.0.0            $
 * $Module name       : pkasn              $
 *
 * Author             : John Owen
 *                      Countermac Limited
 *
 * Description        : Malloc/Free Wrapper
 *
 **************************************************************************************************/
#ifndef __PKASN_MEM_H
#define __PKASN_MEM_H

extern void* pk_mem_new(int length);
extern void* pk_mem_set(void* dst, unsigned char chr, int len);
extern void* pk_mem_cpy(void* dst, void* src, int len);

#endif
