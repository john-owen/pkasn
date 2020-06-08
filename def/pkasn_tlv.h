/**************************************************************************************************
 *
 * $File Identification                    $
 * $Filename          : pkasn_tlv.h         $
 * $Module version    : 1.0.0.0            $
 * $Module name       : pkasn               $
 *
 * Author             : John Owen
 *                      Countermac Limited
 *
 * Description        : Implementation of the core TLV (Tag Length Value) parser
 *
 **************************************************************************************************/
#ifndef __PKASN_TLV_H
#define __PKASN_TLV_H

#ifndef NULL
#define NULL (void *)0
#endif

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS 0
#endif

 /******************************************************************************
 *
 * Internal Defines
 *
 ******************************************************************************/
 // Module Parameters
#define MIN_TLV_SIZE			3
#define ASN1_UTC_TIME_LEN		13
#define MAX_DER_SIZE			10000

 // ASN Tag Types 
#define ASN_BOOLEAN_TYPE 				0x01
#define ASN_INTEGER_TYPE 				0x02
#define ASN_UNSIGNED_INTEGER_TYPE 		0xF2
#define ASN_BITSTRING_TYPE 				0x03   
#define ASN_OCTETSTR_TYPE 				0x04
#define ASN_NULL_TYPE 					0x05
#define ASN_OID_TYPE 					0x06	          
#define ASN_UTF8STR_TYPE 				0x0c	         
#define ASN_UNIVSTR_TYPE 				0x12	          
#define ASN_PRINTSTR_TYPE 				0x13          
#define ASN_TELETEXSTR_TYPE 			0x14	          
#define ASN_IA5STR_TYPE 				0x16 
#define ASN_UTCTIME_TYPE 				0x17
#define ASN_BMPSTRING_TYPE 				0x1E  
#define ASN_SEQUENCE_TYPE 				0x30
#define ASN_SET_TYPE 					0x31           
#define ASN_CONTEXT_SPECIFIC_0			0xA0
#define ASN_CONTEXT_SPECIFIC_1			0xA1 
#define ASN_CONTEXT_SPECIFIC_2			0xA2 
#define ASN_CONTEXT_SPECIFIC_3			0xA3
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_0	0x80
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_1	0x81
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_2	0x82
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_3	0x83
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_4	0x84
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_5	0x85
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_6	0x86
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_7	0x87
#define ASN_IMPLICIT_CONTEXT_SPECIFIC_8	0x88

struct tlv_map {
	unsigned char tag;
	unsigned int length;
	unsigned char* value;
};

extern int map_tlv(unsigned char* p_tlv, int* l_tlv, struct tlv_map* tlv_map);
extern int serialize_tlv(struct tlv_map* tlv_map, unsigned char** pp_der_out,
	unsigned int* l_der_out, unsigned int return_len);

#endif
