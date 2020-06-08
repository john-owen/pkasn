#include "pkasn_tlv.h"
#include "pkasn_error_codes.h"
#include "pkasn_mem.h"

// Internal Functions
int compose_der_tlv(unsigned char tag, unsigned int data_len, unsigned char* data, unsigned char** pvalue);
int parse_der_tlv(unsigned char expected_tag, unsigned char* der_tlv, unsigned char* boundary, unsigned char** pp_value, unsigned int* p_value_len);

int map_tlv(unsigned char* p_tlv, int* l_tlv, struct tlv_map* tlv_map)
{
	unsigned int value_len;
	unsigned char *pvalue;
	unsigned char* pboundary;

	//pboundary - the memory address cut off point
	pboundary = p_tlv + *l_tlv;

	// Parse TBS Sequence
	if (0 != parse_der_tlv(p_tlv[0], p_tlv, pboundary, &pvalue, &value_len))
		return E_PKASN_ASN;

	tlv_map->tag = p_tlv[0];
	tlv_map->length = value_len;
	tlv_map->value = pvalue;
	pvalue += value_len; // Next

	// Set processed length of der
	*l_tlv = pvalue - p_tlv;

	return EXIT_SUCCESS;
}

int serialize_tlv(struct tlv_map* tlv_map, unsigned char** pp_der_out,
	unsigned int* p_l_der_out, unsigned int return_len)
{
	unsigned int err = 0;
	unsigned char* pvalue = NULL;
	//(Negative Lengths are Errors)
	int l_der = 0;
	
	//Calculate Length
	if (0 > (l_der = compose_der_tlv(tlv_map->tag, tlv_map->length, tlv_map->value, NULL)))
		return E_PKASN_ASN;

	if (return_len) return l_der;

	// Allocate memory if necessary
	if (*pp_der_out == NULL) {
		if ((*pp_der_out = (unsigned char*)pk_mem_new(l_der)) == 0)
			return E_PKASN_MALLOC;
		pk_mem_set(*pp_der_out, 0x00, l_der);
	}
	if (*p_l_der_out > 0) {
		if (*p_l_der_out < (unsigned int)l_der) return E_PKASN_ASN; //Not enough Memory Allocated
	}

	pvalue = *pp_der_out;

	// Write TLV
	if (0 != (compose_der_tlv(tlv_map->tag, tlv_map->length, tlv_map->value, &pvalue)))
		return E_PKASN_ASN;

	// Set written length
	*p_l_der_out = pvalue - *pp_der_out;

	return EXIT_SUCCESS;
}

int compose_der_tlv(unsigned char tag, unsigned int data_len, unsigned char *data, unsigned char** pvalue) {
	unsigned char ext_len = 0;
	unsigned int unsign = 0;
	unsigned int tag_len = 0;

	if (pvalue == NULL) {
		// Calc buffer space required
		if (tag == ASN_NULL_TYPE) {
			//A NULL type contains a tag 0x05 & single unsigned char of 0x00.
			return 2;
		}

		if (tag == ASN_UNSIGNED_INTEGER_TYPE) {
			if (data != NULL) {
				if (((unsigned int)data[0]) > 127) data_len++;
			}
		}

		if (data_len < 128) {
			return 2 + data_len;
		}
		else if ((data_len > 127) && (data_len <= 255)) {
			return 3 + data_len;
		}
		else if ((data_len > 255) && (data_len <= MAX_DER_SIZE))
		{
			return 4 + data_len;
		}
		else {
			return E_PKASN_ASN;
		}
	}

	tag_len = data_len;
	// INTEGER values can be positive, negative, or zero, and can have any magnitude
	// The special UNSIGNED INTEGER Tag to adds a 0x00 unsigned char(when necessary), 
	// to force a integer to be intepreted as positive
	if (tag == ASN_UNSIGNED_INTEGER_TYPE) {
		if (((unsigned int)data[0]) > 127) {
			tag_len++;
			if (*pvalue[0] == 0x00) {
				unsign = 1;
			}
			else {
				*pvalue[0] = 0x00;
				unsign = 1;
			}
		}
		tag = ASN_INTEGER_TYPE;
	}

	if ((tag == ASN_SEQUENCE_TYPE) && (data_len == 0)) {
		//A NULL SEQUNCE type contains a tag 0x30 & single unsigned char of 0x00.
		pk_mem_cpy(*pvalue, &tag, 1);
		store_int1(0, *pvalue + 1);
		*pvalue = *pvalue + 2;
	} else if (tag == ASN_NULL_TYPE) {
		//A NULL type contains a tag 0x05 & single unsigned char of 0x00.
		pk_mem_cpy(*pvalue, &tag, 1);
		store_int1(0, *pvalue + 1);
		*pvalue = *pvalue + 2;
	}
	else if (tag_len < 128) { // Short Form Length encoding
		pk_mem_cpy(*pvalue, &tag, 1);
		store_int1(tag_len, *pvalue + 1);
		if (data != NULL) {
			if (unsign) *pvalue = *pvalue + 1;
			pk_mem_cpy(*pvalue + 2, data, data_len);
			*pvalue = *pvalue + 2 + data_len;
		}
		else {
			*pvalue = *pvalue + 2;
		}
	}
	// Long Form Length Encoding
	else if ((tag_len > 127) && (tag_len <= 255)) {
		pk_mem_cpy(*pvalue, &tag, 1);
		ext_len = 0x81;
		pk_mem_cpy(*pvalue + 1, &ext_len, 1);
		store_int1(tag_len, *pvalue + 2);
		if (data != NULL) {
			if (unsign) *pvalue = *pvalue + 1;
			pk_mem_cpy(*pvalue + 3, data, data_len);
			*pvalue = *pvalue + 3 + data_len;
		}
		else {
			*pvalue = *pvalue + 3;
		}
	}
	else if ((tag_len > 255) && (tag_len <= MAX_DER_SIZE)) {
		pk_mem_cpy(*pvalue, &tag, 1);
		ext_len = 0x82;
		pk_mem_cpy(*pvalue + 1, &ext_len, 1);
		store_int2(tag_len, *pvalue + 2);
		if (data != NULL) {
			if (unsign) *pvalue = *pvalue + 1;
			pk_mem_cpy(*pvalue + 4, data, data_len);
			*pvalue = *pvalue + 4 + data_len;
		}
		else {
			*pvalue = *pvalue + 4;
		}
	}
	else {
		return E_PKASN_ASN;
	}

	return EXIT_SUCCESS;
}

int parse_der_tlv(unsigned char expected_tag, unsigned char *der_tlv, unsigned char* boundary, unsigned char** pp_value, unsigned int* p_value_len)
{
	unsigned int offset = 0;
	unsigned int len_byte_count;

	// Prelim boundary Check 
	if (der_tlv >= boundary)
		return E_PKASN_ASN;

	// Check expected tag
	if (expected_tag != der_tlv[offset++])
		return E_PKASN_ASN;

	// Check short-form encoding. First length unsigned char encodes length (if high-bit not set)
	if (((der_tlv[offset] & 0x80) >> 7) == 0) {

		*p_value_len = der_tlv[offset];
		*pp_value = der_tlv + 2;

		if ((*pp_value + *p_value_len) > boundary)
			return E_PKASN_ASN;

		return EXIT_SUCCESS;

	}

	// Get extended length encoding
	switch (len_byte_count = (der_tlv[offset++] & 0x7F)) {
		case 1: *p_value_len = load_int1(der_tlv + offset); break;
		case 2: *p_value_len = load_int2(der_tlv + offset); break;
		case 3: *p_value_len = load_int3(der_tlv + offset); break;
		case 4: *p_value_len = load_int4(der_tlv + offset); break;
		default: return E_PKASN_ASN; // Not supported
	}

	// Set *pp_value
	*pp_value = (der_tlv + 2) + len_byte_count;
	if ((*pp_value + *p_value_len) > boundary)
		return E_PKASN_ASN;

	// Done.
	return EXIT_SUCCESS;
}
