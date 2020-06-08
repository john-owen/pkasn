#ifndef __PKASN_H_ERROR_CODES__
	#define __PKASN_H_ERROR_CODES__

#define E_PKASN_PERMISSION_DENIED        0xB1210001      // permission denied
#define E_PKASN_NULL_PARAM               0xB1210002      // invalid parameter
#define E_PKASN_PARAM                    0xB1210003      // invalid parameter
#define E_PKASN_PARAM_LEN                0xB1210004      // invalid parameter length
#define E_PKASN_MALLOC                   0xB1210005      // memory allocation failed
#define E_PKASN_MODE                     0xB1210006      // invalid mode
#define E_PKASN_ITEM_NOT_FOUND           0xB1210007      // item not found
#define E_PKASN_MODULE_DEP               0xB1210008      // unresolved module dependency
#define E_PKASN_FILE_IO                  0xB1210009      // file I/O error
#define E_PKASN_ASN						 0xB1210010		 // Unspecified ASN composition/parse error
#define E_PKASN_TODO					 0xB1210011		 // TODO!
#define E_PKASN_DECODE					 0xB1210012		 // ASN de-serialize error
#define E_PKASN_ENCODE					 0xB1210013		 // ASN serialize error
#define E_PKASN_UNSUPPORTED				 0xB1210014		 // A feature currently unsupported
#define E_PKASN_UNPERSONALISED			 0xB1210015		 // Personalisation Required
#define E_PKASN_SIGNER_KEY 				 0xB1210016		 // Signer key not present in signing request
#define E_PKASN_DECODE_LEN_TOO_SHORT	 0xB1210017		 // 
#define E_PKASN_DECODE_LEN_TOO_LONG		 0xB1210018		 // 

// --- END ERROR CODES ---

#endif
