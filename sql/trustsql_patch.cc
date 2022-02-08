/*
 * trustsql_patch.cc
 *
 *  Created on: 2019. 3. 12.
 *      Author: trustdb inc.
 */

#include "trustsql_patch.h"

#include "string.h"
#include "sql_class.h"
#include "create_options.h"
#include "handler.h"
#include "mysqld_error.h"
#include "stdio.h"
#include "stdlib.h"
#include "my_global.h"
//#include "my_dbug.h"

#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/ec.h"
#include "openssl/sha.h"
#include "openssl/obj_mac.h"
#include "openssl/bn.h"

#ifdef _DEBUG
    #pragma comment (lib, "libcryptoMDd.lib")
    #pragma comment (lib, "libsslMDd.lib")
#else
    #pragma comment (lib, "libcryptoMD.lib")
    #pragma comment (lib, "libsslMD.lib")
#endif

#ifdef CLOG_ON
	FILE *log_fp;

void tldgr_openlog() {
	log_fp = fopen(TRUSTSQL_LOGFILE,"a");
}

void tldgr_writelog(const char * message,...) {
	va_list ap;
	if(log_fp!=NULL) {
		va_start(ap,message);
		vfprintf(log_fp,message,ap);
		va_end(ap);
	}
}
#endif

#ifdef TRUSTSQL_BUILD


//extern static bool report_unknown_option(THD *thd, engine_option_value *val,bool suppress_warning);

void hex2bin(const char* in, size_t len, unsigned char* out);

LEX_CSTRING make_sig_name(THD *thd, const LEX_CSTRING *table_name, int num) {

  char buff[MAX_FIELD_NAME+10], *buf;
  LEX_CSTRING strTemp;

  sprintf(buff,"%s_SFN_%02d",table_name->str,num);
  strTemp.length = table_name->length+7;
  buf = (char*)alloc_root(thd->mem_root,  strTemp.length+1);
  memcpy(buf, &buff[0], strTemp.length);
  buf[strTemp.length]=0;
  strTemp.str = buf;
  CLOG_TPRINTLN("Generated SIG NAME = %s",strTemp.str);
  return strTemp;
}



LEX_CSTRING Table_trust_options::get_field_option(THD *thd , LEX_CSTRING field_name) {
	LEX_CSTRING option;
	Sig_field_info *sfi;
	LEX_CSTRING *name;
	StringBuffer<1024> buf;
	CHARSET_INFO *cs= system_charset_info;
	LEX_CSTRING retStr;
	char *temp;

    CLOG_TPRINTLN(" target field_name = %s",field_name.str);

	sfi = sig_field_info_list;
	for(int i=0; i< sig_field_infos_no; i++, sfi++) { 
		if (lex_string_cmp(system_charset_info, &sfi->sig_column_name,&field_name) == 0) {
			buf.set("SIGN(",sizeof("SIGN(")-1,cs);
			name = sfi->input_fields;
			buf.append(name->str, name->length,cs);
			name++;
			for(int j=1; j<sfi->input_fields_no; j++,name++) {
				if((buf.length()+name->length) <1023) {
					buf.append(",",sizeof(",")-1,cs);
					buf.append(name->str, name->length,cs);
				}
			}
			buf.append(")",sizeof(")")-1,cs);
			CLOG_TPRINTLN("LENGTH= %d",buf.length());
			temp = (char*)alloc_root(thd->mem_root,  buf.length());
			retStr.length = buf.length();
			memcpy(temp, buf.ptr(), buf.length());
			retStr.str=temp;
			return retStr;
		}
    }
	return {"",sizeof("")};
}

LEX_CSTRING Table_trust_options::get_order_option(THD *thd, LEX_CSTRING field_name) {
	LEX_CSTRING option;
	Sig_field_info *sfi;
	LEX_CSTRING *name;

    CLOG_TPRINTLN(" target field_name = %s",field_name.str);

	sfi = sig_field_info_list;
	for(int i=0; i< sig_field_infos_no; i++, sfi++) {
		if(sfi->sig_field_type==sign_ordered_field) {
			if (lex_string_cmp(system_charset_info, &sfi->sig_column_name,&field_name) == 0) {
				return {"TRUSTED ORDERER SIGN.",sizeof("TRUSTED ORDERER SIGN.")-1};
			}
		}
		if(sfi->order_column_name.str!=0) {
			if(lex_string_cmp(system_charset_info, &field_name,&sfi->order_column_name) == 0) {
				return {"TRUSTED ORDERED NO.",sizeof("TRUSTED ORDERED NO.")-1};
			}
		}			
    }
	return {0,0};

}



bool LEX_sig_field_info::add_sig_input_field(THD *thd, Item *item) {
	CLOG_FUNCTIOND("bool Lex_trust_options::add_sig_input_field(THD *thd, Item *item)");
    input_fields.push_back(item, thd->mem_root);
	return true;
}

bool LEX_sig_field_info::set_fixed_field_verification_key_value(LEX_CSTRING *key_value) {
	CLOG_FUNCTIOND("bool Lex_trust_options::set_fixed_field_verification_key_value(LEX_CSTRING key_value)");

	verification_key_type = FIXED_KEY;
	fixed_verification_key = *key_value ;
}


bool LEX_trust_options::add_sig_field_info(THD *thd, LEX_sig_field_info *sig_field) {
	CLOG_FUNCTIOND("bool Lex_trust_options::add_sig_field_info(THD *thd, LEX_sig_field_info sig_field)");
    list_lex_sig_field_info.push_back(sig_field, thd->mem_root);
	return true;
}

#if 0 // Support only uncompressed PublicKey
bool verify_string(THD *thd, LEX_CSTRING inText, LEX_CSTRING pubKey, LEX_CSTRING signVal) {
    SHA256_CTX      c;
    EC_KEY          *ecKey = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;;
    int             nidEcc;
    unsigned char   m[SHA256_DIGEST_LENGTH];
    unsigned char   sig[256];                   // Must greater than ECDSA_size(ecKey)
    char   *pub_x;
    char   *pub_y;
    int             iRet;
    BIGNUM	*bignum_x;
    BIGNUM	*bignum_y;
    const char *pos;

    CLOG_FUNCTIOND("bool verify_string(THD *thd, LEX_CSTRING inText, LEX_CSTRING pubKey, LEX_CSTRING signVal)");
    CLOG_TPRINTLN("INPUT TEXT = %s",inText.str);
    CLOG_TPRINTLN("PUB KEY    = %s",pubKey.str);
    CLOG_TPRINTLN("signVal    = %s",signVal.str);

	// Generate Hash for signing
	SHA256_Init(&c);
	SHA256_Update(&c, inText.str, inText.length);
	SHA256_Final(m, &c);
	CLOG_TPRINTLN(" SHA256_FINAL = %s",m);

	OPENSSL_cleanse(&c, sizeof(c));

	pub_x = ( char*) my_malloc(65, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));
	pub_y = ( char*) my_malloc(65, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));

	pos = pubKey.str;
	pos+=2;	// compressed
	memcpy(pub_x,pos,64);
	pos+=64;
	memcpy(pub_y,pos,64);
	pub_x[64]=0;
	pub_y[64]=0;

	CLOG_TPRINTLN("PUB-X=");
	CLOG_DISPBUFFER(pub_x,64);
	CLOG_TPRINTLN("PUB-Y=");
	CLOG_DISPBUFFER(pub_y,64);


	if (ctx == NULL) {
		ctx = BN_CTX_new();
		BN_CTX_start(ctx);
		bignum_x = BN_CTX_get(ctx);
		bignum_y = BN_CTX_get(ctx);
	}
	iRet=BN_hex2bn(&bignum_x,pub_x);
	iRet=BN_hex2bn(&bignum_y,pub_y);

	nidEcc = OBJ_txt2nid("secp256k1");
	ecKey = EC_KEY_new_by_curve_name(nidEcc);

	group = EC_KEY_get0_group(ecKey);
	pub_key = EC_POINT_new(group);

	/*
	if(!EC_POINT_set_affine_coordinates_GFp(group, pub_key, bignum_x, bignum_y, ctx)) {
		ZLOG_TPRINTLN("EC_POINT_set_affine_coordinates_GFp() fail!");
		goto err;
	}
*/
	if(!EC_KEY_set_public_key_affine_coordinates(ecKey, bignum_x,bignum_y)) {
		CLOG_TPRINTLN("EC_KEY_set_public_key_affine_coordinates() fail!");
		goto err;
	}

//	if(!EC_KEY_set_public_key(ecKey, pub_key ))
//		goto err;
	hex2bin((char*)signVal.str,signVal.length, sig);

	iRet = ECDSA_verify(0, m, SHA256_DIGEST_LENGTH, (unsigned char*)sig, signVal.length/2, ecKey);

	if(iRet!=1) goto err;

	my_free(pub_x);
	my_free(pub_y);
	BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	EC_POINT_free(pub_key);
	return false;
err:
	my_free(pub_x);
	my_free(pub_y);
	BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	EC_POINT_free(pub_key);
    return true;
}
#endif

// Support uncompressed, compressed PublicKey
//bool verify_string(THD *thd, LEX_CSTRING inText, LEX_CSTRING pubkey, LEX_CSTRING signVal) {

//	return false;
//}

#if 1
bool verify_string(THD *thd, LEX_CSTRING inText, LEX_CSTRING pubKey, LEX_CSTRING signVal) {
    SHA256_CTX      c;
    EC_KEY          *ecKey = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;;
    int             nidEcc;
    unsigned char   m[SHA256_DIGEST_LENGTH];
    unsigned char   sig[256];                   // Must greater than ECDSA_size(ecKey)
    char   *pub_x=NULL;
    char   *pub_y=NULL;
    int             iRet;
    BIGNUM	*bignum_x;
    BIGNUM	*bignum_y;
    const char *pos;
    unsigned char prefix[1];

    CLOG_FUNCTIOND("bool verify_string(THD *thd, LEX_CSTRING inText, LEX_CSTRING pubKey, LEX_CSTRING signVal)");
    CLOG_TPRINTLN("INPUT TEXT = %s",inText.str);
    CLOG_TPRINTLN("PUB KEY    = %s",pubKey.str);
    CLOG_TPRINTLN("signVal    = %s",signVal.str);

    SHA256_Init(&c);
	SHA256_Update(&c, inText.str, inText.length);
	SHA256_Final(m, &c);
    CLOG_TPRINTLN(" SHA256_FINAL = %s",m);
    OPENSSL_cleanse(&c, sizeof(c));

    nidEcc = OBJ_txt2nid("secp256k1");
   	ecKey = EC_KEY_new_by_curve_name(nidEcc);
   	group = EC_KEY_get0_group(ecKey);
   	pub_key = EC_POINT_new(group);

    hex2bin(pubKey.str, 2, prefix);
    if(prefix[0]==4) {
		// uncompressed key
		pub_x = ( char*) my_malloc(65, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));
		pub_y = ( char*) my_malloc(65, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));
		pos = pubKey.str;
		pos+=2;	// compressed
		memcpy(pub_x,pos,64);
		pos+=64;
		memcpy(pub_y,pos,64);
		pub_x[64]=0;
		pub_y[64]=0;

		if (ctx == NULL) {
			ctx = BN_CTX_new();
			BN_CTX_start(ctx);
			bignum_x = BN_CTX_get(ctx);
			bignum_y = BN_CTX_get(ctx);
		}
		iRet=BN_hex2bn(&bignum_x,pub_x);
		iRet=BN_hex2bn(&bignum_y,pub_y);
    } else if((prefix[0]==2) || (prefix[0]==3)) {
    	// compressed key
    	unsigned char x_compressed[32];
    	unsigned char xy_uncompressed[65];
    	pos = pubKey.str;
    	pos+=2; // prefix
    	hex2bin(pos,64,x_compressed);
    	bignum_x = BN_new();
    	bignum_y = BN_new();

    	BN_bin2bn(&x_compressed[0],sizeof(x_compressed),bignum_x);

    	int results = EC_POINT_set_compressed_coordinates_GFp(group, pub_key,bignum_x,(prefix[0]==2 ? 0:1), NULL);

    	size_t returnsize = EC_POINT_point2oct(group, pub_key,
    	                                POINT_CONVERSION_UNCOMPRESSED,
    	                                &xy_uncompressed[0], 65, NULL); //
    	BN_bin2bn(&xy_uncompressed[1],32,bignum_x);
    	BN_bin2bn(&xy_uncompressed[33],32,bignum_y);
    } else {
    	goto err;
    }

	/*
	if(!EC_POINT_set_affine_coordinates_GFp(group, pub_key, bignum_x, bignum_y, ctx)) {
		ZLOG_TPRINTLN("EC_POINT_set_affine_coordinates_GFp() fail!");
		goto err;
	}
*/
	if(!EC_KEY_set_public_key_affine_coordinates(ecKey, bignum_x,bignum_y)) {
		CLOG_TPRINTLN("EC_KEY_set_public_key_affine_coordinates() fail!");
		goto err;
	}

//	if(!EC_KEY_set_public_key(ecKey, pub_key ))
//		goto err;
	hex2bin((char*)signVal.str,signVal.length, sig);

	iRet = ECDSA_verify(0, m, SHA256_DIGEST_LENGTH, (unsigned char*)sig, signVal.length/2, ecKey);

	if(iRet!=1) goto err;
	if(pub_x!=NULL) my_free(pub_x);
	if(pub_y!=NULL)my_free(pub_y);
	if(ctx!=NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if(pub_key!=NULL) EC_POINT_free(pub_key);
	return false;
err:
	if(pub_x!=NULL) my_free(pub_x);
	if(pub_y!=NULL)my_free(pub_y);
	if(ctx!=NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if(pub_key!=NULL) EC_POINT_free(pub_key);
    return true;
}
#endif

#if 0 // Only support decompressed key
bool verify_fields_sign(THD *thd, Sig_field_info *sig_info, List<Item> &field_list, List<Item> &field_value_list, LEX_CSTRING *signature_value) {

	List_iterator_fast<Item> it_fields(field_list);
	List_iterator_fast<Item> it_values(field_value_list);
	Item *field;
	Item *value;

	LEX_CSTRING *input_field;
	LEX_CSTRING input_value;
	uint input_fields_no;
    StringBuffer<4096> input_buf;

    SHA256_CTX      c;
    EC_KEY          *ecKey = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;;
    int             nidEcc;
    unsigned char   m[SHA256_DIGEST_LENGTH];
    unsigned char   sig[256];                   // Must greater than ECDSA_size(ecKey)
    char   *pub_x;
    char   *pub_y;
    int             iRet;
    BIGNUM	*bignum_x;
    BIGNUM	*bignum_y;
    const char *pos;

    CLOG_FUNCTIOND("bool verify_fields_sign(THD *thd, ...)");

	input_fields_no = sig_info->input_fields_no;
	input_field = sig_info->input_fields;

	for(int i=0; i<input_fields_no; i++, input_field++) {
		CLOG_TPRINTLN("[%d] sign input field = %s",i,input_field->str);
		it_fields.rewind();
		it_values.rewind();

		while (field = it_fields++) {
			CLOG_TPRINTLN(" Input field = %s",field->name.str);
			value = it_values++;
			if(value==0) {
				CLOG_TPRINTLN(" Field name %s no vlaue", field->name.str);
				continue;
			}			
			input_value = value->val_str()->lex_cstring();

			if (lex_string_cmp(system_charset_info, input_field, &field->name) == 0) {
				input_buf.append(input_value.str,input_value.length);
				CLOG_TPRINTLN("Appended Field Name = %s, value = %s",field->name.str, input_value.str);
				break;
			}
		}
		CLOG_TPRINTLN(" FULL INPUT_TEXT = %s LENGTH = %d",input_buf.ptr(), input_buf.length());
	}

	// find verification key from input fields if key_type is INTERNAL_COLUMN_KEY
	if(sig_info->verification_key_type==INTERNAL_COLUMN_KEY) {
		it_fields.rewind();
		it_values.rewind();
		while (field = it_fields++) {
			CLOG_TPRINTLN(" Input field = %s",field->name.str);
			value = it_values++;
			if(value==0) continue;
			input_value = value->val_str()->lex_cstring();
			if (lex_string_cmp(system_charset_info, &field->name, &sig_info->verification_column_name)== 0) {
				CLOG_TPRINTLN("VERIFICATION KEY Internal Column Name = %s, value = %s",field->name.str, input_value.str);
				sig_info->fixed_verification_key = input_value;
				break;
			}
		}
	}

	if(input_buf.length()>4096) goto err;


	// Generate Hash for signing
	SHA256_Init(&c);
	SHA256_Update(&c, input_buf.ptr(), input_buf.length());
	SHA256_Final(m, &c);
	CLOG_TPRINTLN(" SHA256_FINAL = %s",m);

	OPENSSL_cleanse(&c, sizeof(c));

	pub_x = ( char*) my_malloc(65, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));
	pub_y = ( char*) my_malloc(65, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));

	CLOG_TPRINTLN("VERIFICATION KEY = %s",sig_info->fixed_verification_key.str);
	pos = sig_info->fixed_verification_key.str;
	pos+=2;	// compressed
	memcpy(pub_x,pos,64);
	pos+=64;
	memcpy(pub_y,pos,64);
	pub_x[64]=0;
	pub_y[64]=0;

	CLOG_TPRINTLN("PUB-X=");
	CLOG_DISPBUFFER(pub_x,64);
	CLOG_TPRINTLN("PUB-Y=");
	CLOG_DISPBUFFER(pub_y,64);

	if (ctx == NULL) {
		ctx = BN_CTX_new();
		BN_CTX_start(ctx);
		bignum_x = BN_CTX_get(ctx);
		bignum_y = BN_CTX_get(ctx);
	}
	iRet=BN_hex2bn(&bignum_x,pub_x);
	iRet=BN_hex2bn(&bignum_y,pub_y);

	nidEcc = OBJ_txt2nid("secp256k1");
	ecKey = EC_KEY_new_by_curve_name(nidEcc);

	group = EC_KEY_get0_group(ecKey);
	pub_key = EC_POINT_new(group);

	/*
	if(!EC_POINT_set_affine_coordinates_GFp(group, pub_key, bignum_x, bignum_y, ctx)) {
		ZLOG_TPRINTLN("EC_POINT_set_affine_coordinates_GFp() fail!");
		goto err;
	}
*/
	if(!EC_KEY_set_public_key_affine_coordinates(ecKey, bignum_x,bignum_y)) {
		CLOG_TPRINTLN("EC_KEY_set_public_key_affine_coordinates() fail!");
		goto err;
	}

//	if(!EC_KEY_set_public_key(ecKey, pub_key ))
//		goto err;
	hex2bin((char*)signature_value->str,signature_value->length, sig);

	iRet = ECDSA_verify(0, m, SHA256_DIGEST_LENGTH, (unsigned char*)sig, signature_value->length/2, ecKey);

	if(iRet!=1) goto err;
	my_free(pub_x);
	my_free(pub_y);
	BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	EC_POINT_free(pub_key);
	return false;
err:
	my_free(pub_x);
	my_free(pub_y);
	BN_CTX_end(ctx);
    BN_CTX_free(ctx);
	EC_POINT_free(pub_key);
    return true;
}
#endif

// support decompressed & Compressed key
//bool verify_fields_sign(THD *thd, Sig_field_info *sig_info, List<Item> &field_list, List<Item> &field_value_list, LEX_CSTRING *signature_value) {

//	return false;
//}
#if 1
bool verify_fields_sign(THD *thd, Sig_field_info *sig_info, List<Item> &field_list, List<Item> &field_value_list, LEX_CSTRING *signature_value) {

	List_iterator_fast<Item> it_fields(field_list);
	List_iterator_fast<Item> it_values(field_value_list);
	Item *field;
	Item *value;

	LEX_CSTRING *input_field;
	LEX_CSTRING input_value;
	uint input_fields_no;
    StringBuffer<4096> input_buf;

    SHA256_CTX      c;
    EC_KEY          *ecKey = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = NULL;
    BN_CTX *ctx = NULL;;
    int             nidEcc;
    unsigned char   m[SHA256_DIGEST_LENGTH];
    unsigned char   sig[256];                   // Must greater than ECDSA_size(ecKey)
    char   *pub_x=NULL;
    char   *pub_y=NULL;
    int             iRet;
    BIGNUM	*bignum_x=NULL;
    BIGNUM	*bignum_y=NULL;
    const char *pos;
    unsigned char prefix[1];

    CLOG_FUNCTIOND("bool verify_fields_sign(THD *thd, ...)");

	input_fields_no = sig_info->input_fields_no;
	input_field = sig_info->input_fields;

	for(int i=0; i<input_fields_no; i++, input_field++) {
		CLOG_TPRINTLN("[%d] sign input field = %s",i,input_field->str);
		it_fields.rewind();
		it_values.rewind();

		while (field = it_fields++) {
			CLOG_TPRINTLN(" Input field = %s",field->name.str);
			value = it_values++;
			if(value==0) {
				CLOG_TPRINTLN(" Field name %s no vlaue", field->name.str);
				continue;
			}
			input_value = value->val_str()->lex_cstring();

			if (lex_string_cmp(system_charset_info, input_field, &field->name) == 0) {
				input_buf.append(input_value.str,input_value.length);
				CLOG_TPRINTLN("Appended Field Name = %s, value = %s",field->name.str, input_value.str);
				break;
			}
		}
		CLOG_TPRINTLN(" FULL INPUT_TEXT = %s LENGTH = %d",input_buf.ptr(), input_buf.length());
	}

	// find verification key from input fields if key_type is INTERNAL_COLUMN_KEY
	if(sig_info->verification_key_type==INTERNAL_COLUMN_KEY) {
		it_fields.rewind();
		it_values.rewind();
		while (field = it_fields++) {
			CLOG_TPRINTLN(" Input field = %s",field->name.str);
			value = it_values++;
			if(value==0) continue;
			input_value = value->val_str()->lex_cstring();
			if (lex_string_cmp(system_charset_info, &field->name, &sig_info->verification_column_name)== 0) {
				CLOG_TPRINTLN("VERIFICATION KEY Internal Column Name = %s, value = %s",field->name.str, input_value.str);
				sig_info->fixed_verification_key = input_value;
				break;
			}
		}
	}

	if(input_buf.length()>4096) goto err;


	// Generate Hash for signing
	SHA256_Init(&c);
	SHA256_Update(&c, input_buf.ptr(), input_buf.length());
	SHA256_Final(m, &c);
	CLOG_TPRINTLN(" SHA256_FINAL = %s",m);

	OPENSSL_cleanse(&c, sizeof(c));

	nidEcc = OBJ_txt2nid("secp256k1");
	ecKey = EC_KEY_new_by_curve_name(nidEcc);
	group = EC_KEY_get0_group(ecKey);
	pub_key = EC_POINT_new(group);

	CLOG_TPRINTLN("VERIFICATION KEY = %s",sig_info->fixed_verification_key.str);
	pos = sig_info->fixed_verification_key.str;

	hex2bin(sig_info->fixed_verification_key.str, 2, prefix);
	if(prefix[0]==4) {
		// uncompressed key
		pub_x = ( char*) my_malloc(65, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));
		pub_y = ( char*) my_malloc(65, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));
		pos = sig_info->fixed_verification_key.str;
		pos+=2;	// compressed
		memcpy(pub_x,pos,64);
		pos+=64;
		memcpy(pub_y,pos,64);
		pub_x[64]=0;
		pub_y[64]=0;

		if (ctx == NULL) {
			ctx = BN_CTX_new();
			BN_CTX_start(ctx);
			bignum_x = BN_CTX_get(ctx);
			bignum_y = BN_CTX_get(ctx);
		}
		iRet=BN_hex2bn(&bignum_x,pub_x);
		iRet=BN_hex2bn(&bignum_y,pub_y);
	} else if((prefix[0]==2) || (prefix[0]==3)) {
		// compressed key
		unsigned char x_compressed[32];
		unsigned char xy_uncompressed[65];
		pos = sig_info->fixed_verification_key.str;
		pos+=2; // prefix
		hex2bin(pos,64,x_compressed);
		bignum_x = BN_new();
		bignum_y = BN_new();

		BN_bin2bn(&x_compressed[0],sizeof(x_compressed),bignum_x);

		int results = EC_POINT_set_compressed_coordinates_GFp(group, pub_key,bignum_x,(prefix[0]==2 ? 0:1), NULL);

		size_t returnsize = EC_POINT_point2oct(group, pub_key,
										POINT_CONVERSION_UNCOMPRESSED,
										&xy_uncompressed[0], 65, NULL); //
		BN_bin2bn(&xy_uncompressed[1],32,bignum_x);
		BN_bin2bn(&xy_uncompressed[33],32,bignum_y);
	} else {
		goto err;
	}

	/*
	if(!EC_POINT_set_affine_coordinates_GFp(group, pub_key, bignum_x, bignum_y, ctx)) {
		ZLOG_TPRINTLN("EC_POINT_set_affine_coordinates_GFp() fail!");
		goto err;
	}
*/
	if(!EC_KEY_set_public_key_affine_coordinates(ecKey, bignum_x,bignum_y)) {
		CLOG_TPRINTLN("EC_KEY_set_public_key_affine_coordinates() fail!");
		goto err;
	}

//	if(!EC_KEY_set_public_key(ecKey, pub_key ))
//		goto err;
	hex2bin((char*)signature_value->str,signature_value->length, sig);

	iRet = ECDSA_verify(0, m, SHA256_DIGEST_LENGTH, (unsigned char*)sig, signature_value->length/2, ecKey);

	if(iRet!=1) goto err;
	if(pub_x!=NULL) my_free(pub_x);
	if(pub_y!=NULL)my_free(pub_y);
	if(ctx!=NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if(pub_key!=NULL) EC_POINT_free(pub_key);
	return false;
err:
	if(pub_x!=NULL) my_free(pub_x);
	if(pub_y!=NULL)my_free(pub_y);
	if(ctx!=NULL) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	if(pub_key!=NULL) EC_POINT_free(pub_key);
    return true;
}
#endif

bool verify_record_sign(THD *thd, TABLE *table, List<Item> &fields, List<Item> &values) {
	Table_trust_options *trust_options;
	unsigned char  sig_field_infos_no;
	Sig_field_info *sig_field_info;
	Sig_field_info sf_info;
	
	List_iterator_fast<Item> fields_it(fields);
	List_iterator_fast<Item> values_it(values);
	Item *field;
	Item *value;

	List<TABLE> tbl_list;
	bool all_fields_have_values= true;
	unsigned char buff[4096], *bptr;
	LEX_CSTRING target_sig_field;
	LEX_CSTRING input_field,input_value;
	LEX_CSTRING signature_value;
	Field **lp_ptr;

	CLOG_FUNCTIOND("bool verify_record_sign(THD *thd, TABLE *table, Field **ptr, List<Item> &values)");
	
	trust_options = table->s->trust_options;
	sig_field_infos_no = trust_options->sig_field_infos_no;
	sig_field_info = trust_options->sig_field_info_list;

	DBUG_ASSERT(sig_field_infos_no!=0);

	for(int i=0; i<sig_field_infos_no; i++, sig_field_info++) {
		target_sig_field = sig_field_info->sig_column_name;
		CLOG_TPRINTLN("Target_sig_field = % s", target_sig_field.str);
		// Step 1. the filed have a value.
		fields_it.rewind();
		values_it.rewind();
		while(field=fields_it++) {		
			CLOG_TPRINTLN(" Input field = %s",field->name.str);
			value=values_it++;
			if(value==0) {
				CLOG_TPRINTLN(" %s has no vlaue", field->name.str);
				continue;
			}

			input_field = field->name;
			input_value = value->val_str()->lex_cstring();
			CLOG_TPRINTLN(" Field name %s strValue = %s strLength = %d", input_field.str, input_value.str, input_value.length);
			if (lex_string_cmp(system_charset_info, &target_sig_field, &field->name) == 0) {
				signature_value = input_value;
				CLOG_TPRINTLN("Sign value = %s",signature_value.str);
				if(verify_fields_sign(thd, sig_field_info, fields, values, &signature_value)) {
					goto err;
				}
				break;
			}
		}
	}

	return 0;
err:
//	push_warning_printf(thd, Sql_condition::WARN_LEVEL_WARN, TRUSTSQL_INSERT_SIGN_VERIFY_FAIL,
//                          ER_THD(thd, TRUSTSQL_INSERT_SIGN_VERIFY_FAIL),
//						  target_sig_field.str);
	push_warning_printf(thd, Sql_condition::WARN_LEVEL_WARN, 5000,
							"Signature Verification Fail : %s",
						  target_sig_field.str);

    return thd->really_abort_on_warning();
}



/**
  check Trusted Constraints & build an image for storing it.

  @param          thd             Thread handle
  @param[in,out]  comment         Comment
  @param          max_len         Maximum allowed comment length
  @param          err_code        Error message
  @param          name            Name of commented object

  @return Operation status
    @retval       true            Error found
    @retval       false           On Success
*/

bool tldgr_create_tld_image(THD *thd, const LEX_CSTRING *db, const LEX_CSTRING *table_name, List<Create_field> &create_fields, KEY **key_info, uint *key_count, LEX_CUSTRING *tld_image) {

	CLOG_FUNCTIOND("bool tldgr_create_tld_image(...)");

	CLOG_STEP("1","check Constraints for Trust Integrity");
	if(tldgr_trust_options_precheck(thd, table_name, create_fields, key_info, key_count))
		goto err;

	CLOG_STEP("2","build tld image");


   *tld_image= tldgr_const4t_build_image(thd->lex->trust_options, create_fields, key_info, key_count);

	if(tld_image)
		  return false;

err:
    return true;
}

/*
  Check constraints for Trusted

  DESCRIPTION
    Check constraints for Trusted_Sign structure for table creation.

  NOTES

  RETURN VALUES
    FALSE    OK
    TRUE     error
*/

bool tldgr_trust_options_precheck(THD *thd, const LEX_CSTRING *table_name, List<Create_field> &create_fields, KEY **key_info, uint *key_count)
{
	Table_trust_options *trust_options = thd->lex->trust_options;
	List<LEX_sig_field_info> sig_field_infos = thd->lex->trust_options->list_lex_sig_field_info;
	List_iterator_fast<Create_field> cf_it(create_fields);
	List_iterator_fast<LEX_sig_field_info> sfi_it(sig_field_infos);
    Create_field *cfield;
	LEX_sig_field_info *sfield;
	KEY *key;
	LEX_CSTRING order_field_name;
	LEX_CSTRING time_field_name;
	uint order_feildnr;
	bool target_found;
	int num;

	CLOG_FUNCTIOND("bool tldgr_trust_options_precheck(...)");

	// Condition 1. sig_column_name should be in the create_fields list.
	while(sfield=sfi_it++) {		
		target_found=false;
		CLOG_TPRINTLN(" target sfield_name= %s",sfield->sig_column_name.str);
		while(cfield=cf_it++) {
			CLOG_TPRINTLN(" cfield_name=%s",cfield->field_name.str);
			if (lex_string_cmp(system_charset_info, &sfield->sig_column_name, &cfield->field_name) == 0) {
				target_found=true;
				break;
			}
		}
		if(target_found==false) {			
			my_error(5001,MYF(0));
			goto err;
		}
		cf_it.rewind();		
	}
	// Condition 2. if the sig_column_name don't have constraint name, give it with default naming.
	sfi_it.rewind();
	num=0;
	while(sfield=sfi_it++) {		
		num++;
		if(!sfield->sig_name.str) {
			sfield->sig_name = make_sig_name(thd, table_name,num);
		}
	}
	if(num==0) {
		// no sinature field -> fail	
		my_error(5006,MYF(0));		
		goto err;
	}
	// Condition 3. if TRUSTED ORDERED Table, there should be only one TRUSTED ORDER Constraints.
	if(thd->lex->trust_options->Trusted_table_type==2) {   // TO do 2 -> Table_trust)options::TRUSTED_ORDERD_TYPE
		sfi_it.rewind();
		order_feildnr=0;
		target_found=false;
		while(sfield=sfi_it++) {
			if(sfield->sig_field_type==sign_ordered_field) {
				if(target_found==true) {
					my_error(5002,MYF(0));
					goto err;
				} else {
					order_field_name = sfield->order_column_name;
					time_field_name = sfield->time_column_name;
					target_found=true;
				}
			}
		}
		if(target_found==false) {			
			my_error(5003,MYF(0));
			// No Ordered Sign
			goto err;
		}
		// Condition 4. order_field_name should be in the create_fields list.
		cf_it.rewind();
		target_found=false;
		order_feildnr=0;
		while(cfield=cf_it++) {
			if (lex_string_cmp(system_charset_info, &order_field_name, &cfield->field_name) == 0) {
				target_found=true;
				break;
			}
			order_feildnr++;
		}
		if(target_found==false)  {
			my_error(5004,MYF(0));
			goto err;
		}
		// Condition 5. if time_column_name exist, the_column_name should be in the create_fields list.
		if(!time_field_name.str) {
			cf_it.rewind();
			target_found=false;
			while(cfield=cf_it++) {
				if (lex_string_cmp(system_charset_info, &time_field_name, &cfield->field_name) == 0) {
					target_found=true;
					break;
				}
			}
			if(target_found==false)  {
				my_error(5005,MYF(0));
				goto err;
			}
		}

#if 0	// Order column need just UNIQUE.
		// Order Column should be a PRIMARY KEY type.
		target_found=false;
		key = *key_info;
		LEX_CSTRING primary_str= { "PRIMARY", sizeof("PRIMARY") };
		for(int i=0; i<*key_count; i++, key++) {
			if (lex_string_cmp(system_charset_info, &key->name, &primary_str) == 0) {
				if(key->key_part->fieldnr==order_feildnr) {
					target_found=true;
				}
			}
		}

		if(target_found==false) {			
			my_error(5006,MYF(0));
			goto err;//
		}
#endif
	}

	/* condition 5. table options
	 *  TRUSTDB Table Option Checks.
		[Mandatory Options]
		Trusted Table
			table_issuer_pub_key
			table_schema
			table_schema_sign
		Ordered Table
			tosa_pub_key
			tosa_master_pub_key

		[Not Mandatory Options]
		trusted_reference_pub_key
		trusted_reference_sign
		trigger_before_insert_sign
		trigger_after_insert_sign
	*/

	if(trust_options->table_issuer_pub_key.str==0) { my_error(5007,MYF(0),"Fail - TABLE_ISSUER_PUB_KEY missed"); goto err; }
	if(trust_options->table_schema.str==0) { my_error(5008,MYF(0),"Fail - TABLE_SCHEMA missed"); goto err; }
	if(trust_options->table_schema_sign.str==0) { my_error(5009,MYF(0),"Fail - TABLE_SCHEMA_SIGN missed"); goto err; }

	if(thd->lex->create_info.is_Trusted_Ordered()) {
		if(trust_options->tosa_pub_key.str==0) { my_error(5010,MYF(0),"Fail - TOSA_PUB_KEY missed"); goto err; }
		if(trust_options->tosa_master_pub_key.str==0) { my_error(5011,MYF(0),"Fail - TOSA_MASTER_PUB_KEY missed"); goto err; }
	}

	// Table Sign Check
	if(verify_string(thd, trust_options->table_schema, trust_options->table_issuer_pub_key, trust_options->table_schema_sign)) {
		my_error(5012,MYF(0));
		goto err;
	}

	return false;
err:
	//my_error(ER_DUP_FIELDNAME, MYF(0), sql_field->field_name.str);
	return true;
}


/**
  Create a frm (table definition) file

  @param aaa                    bbbb
  @

  @return the generated frm image as a LEX_CUSTRING,
  or null LEX_CUSTRING (str==0) in case of an error.
*/

LEX_CUSTRING tldgr_const4t_build_image(LEX_trust_options *trust_options, List<Create_field> &create_fields, KEY **key_info, uint *key_count) {
	//	  List_iterator_fast<Item> inputf_it(trust_options->dsa_input_fields);
	uchar tldHeader[TRUSTSQL_TLC_HEADER_SIZE];
	uchar *frm_ptr, *pos;
	LEX_CUSTRING frm= {0,0};
	size_t extra_size=0;
	size_t create_statement_size=0;
	List_iterator_fast<LEX_sig_field_info> sfi_it(trust_options->list_lex_sig_field_info);
	List_iterator_fast<Create_field> cf_it(create_fields);
	Create_field *cf;
	List_iterator_fast<Item> if_it;
	LEX_sig_field_info *sfield;
	Item *ifield;
	unsigned int sfield_no=0;
	unsigned int ifield_no=0;

	CLOG_FUNCTIOND("LEX_CUSTRING tldgr_const4t_build_image(...)");

	CLOG_STEP("1","build Header");
	bzero((char*)tldHeader,TRUSTSQL_TLC_HEADER_SIZE);

	tldHeader[0]=(uchar) 254;
	tldHeader[1]= 1;
	tldHeader[2]= (uchar)TRUSTSQL_TLC_VERSION;
	tldHeader[3]= (uchar)trust_options->Trusted_table_type;
	
	CLOG_TPRINTLN("tldHeader[0]= (0x%08X)",tldHeader[0]);
	CLOG_TPRINTLN("tldHeader[1]= (0x%08X)",tldHeader[1]);
	CLOG_TPRINTLN("tldHeader[2]= (0x%08X) -> TRUSTSQL_TLC_VERSION",tldHeader[2]);
	CLOG_TPRINTLN("tldHeader[3]= (0x%08X)", tldHeader[3]);

	tldHeader[4]= 0; // Digital Signature Algorithm ID default ECC
	CLOG_TPRINTLN("tldHeader[4]= (0x%08X) -> Digital Signature Algorithm ID",tldHeader[4]);

	pos = &tldHeader[16];

	/* Sequence
		1.table_issuer_pub_key
		2.trusted_reference_pub_key
		3.tosa_pub_key
		4.tosa_master_pub_key
		5.table_schema	-> table_schma located in extra
		6.table_schema_sign
		7.trusted_reference_sign
		8.trigger_before_insert_sign
		9.trigger_after_insert_sign
	 */
	CLOG_TPRINTLN("tldHeader[8]   ~    L(2)V(N)= TI_PUB, TO_M, TO_S, TI_SIGN");
   	int2store(pos,trust_options->table_issuer_pub_key.length);
	pos+=2;
	memcpy(pos,trust_options->table_issuer_pub_key.str,trust_options->table_issuer_pub_key.length);
	pos+=trust_options->table_issuer_pub_key.length;
	CLOG_TPRINTLN("1.table_issuer_pub_key=%s",trust_options->table_issuer_pub_key.str);
	
	int2store(pos,trust_options->trusted_reference_pub_key.length);
	pos+=2;
	memcpy(pos,trust_options->trusted_reference_pub_key.str,trust_options->trusted_reference_pub_key.length);
	pos+=trust_options->trusted_reference_pub_key.length;
	CLOG_TPRINTLN("2.trusted_reference_pub_key=%s",trust_options->trusted_reference_pub_key.str);

	int2store(pos,trust_options->tosa_pub_key.length);
	pos+=2;
	memcpy(pos,trust_options->tosa_pub_key.str,trust_options->tosa_pub_key.length);
	pos+=trust_options->tosa_pub_key.length;
	CLOG_TPRINTLN("3.tosa_pub_key=%s",trust_options->tosa_pub_key.str);

	int2store(pos,trust_options->tosa_master_pub_key.length);
	pos+=2;
	memcpy(pos,trust_options->tosa_master_pub_key.str,trust_options->tosa_master_pub_key.length);
	pos+=trust_options->tosa_master_pub_key.length;
	CLOG_TPRINTLN("4.tosa_master_pub_key=%s",trust_options->tosa_master_pub_key.str);

	int2store(pos,trust_options->table_schema_sign.length);
	pos+=2;
	memcpy(pos,trust_options->table_schema_sign.str,trust_options->table_schema_sign.length);
	pos+=trust_options->table_schema_sign.length;
	CLOG_TPRINTLN("5.table_schema_sign=%s",trust_options->table_schema_sign.str);

	int2store(pos,trust_options->trusted_reference_sign.length);
	pos+=2;
	memcpy(pos,trust_options->trusted_reference_sign.str,trust_options->trusted_reference_sign.length);
	pos+=trust_options->trusted_reference_sign.length;
	CLOG_TPRINTLN("6.trusted_reference_sign=%s",trust_options->trusted_reference_sign.str);

	int2store(pos,trust_options->trigger_before_insert_sign.length);
	pos+=2;
	memcpy(pos,trust_options->trigger_before_insert_sign.str,trust_options->trigger_before_insert_sign.length);
	pos+=trust_options->trigger_before_insert_sign.length;
	CLOG_TPRINTLN("7.trigger_before_insert_sign=%s",trust_options->trigger_before_insert_sign.str);

	int2store(pos,trust_options->trigger_after_insert_sign.length);
	pos+=2;
	memcpy(pos,trust_options->trigger_after_insert_sign.str,trust_options->trigger_after_insert_sign.length);
	pos+=trust_options->trigger_after_insert_sign.length;
	CLOG_TPRINTLN("8.trigger_after_insert_sign=%s",trust_options->trigger_after_insert_sign.str);

	/* TLEDGER - TO DO
	* TDSA_T TP1 TP2 TABLE_SIZ ORDER INFO....	   *
	*/
    assert(trust_options->Trusted_table_type!=0);

	CLOG_STEP("2","Calculate extra");
	extra_size = 2 + 1; // SIGFIED Total Length + SIG_FIELD_NO	  
	while(sfield=sfi_it++) {
		extra_size +=1;  // sig_field_length
		extra_size+=sfield->sig_column_name.length; // sig_field_name
		extra_size +=1;  // sig name length
		extra_size+=sfield->sig_name.length; // sig_field_name
		sfield_no++;
		if((trust_options->Trusted_table_type==1)||((trust_options->Trusted_table_type==2)&&(sfield->sig_field_type == sign_only_field))) {
			extra_size +=2; // input field NO
			// use sig input fields
			if_it = sfield->input_fields;  			
			while(ifield=if_it++) {
				extra_size +=1; // input field name Length
				extra_size += ifield->name.length;  // input field name
			}
		} else if((trust_options->Trusted_table_type==2)&&(sfield->sig_field_type == sign_ordered_field)) {
			extra_size +=2; // input field NO
			// use all fields  자기 자신은 제외 해야지..
			cf_it.rewind();
			while(cf=cf_it++) {
				// exclude sign field with option
				if (lex_string_cmp(system_charset_info, &sfield->sig_column_name, &cf->field_name) != 0) {
					extra_size +=1; // input field name Length
					extra_size += cf->field_name.length; // input field name
				}
			}		
		}	
		
		extra_size+=1; // verification key type;
		extra_size+=1; // verification key length	

		// Here, To do... Copy Table issuer Key if type is :0 Table issuer or Orderer or, Copy Reference Table  & Column if type is 2.		
		if(sfield->verification_key_type==FIXED_KEY) {
			extra_size+=sfield->fixed_verification_key.length ; // verification key
		} else if(sfield->verification_key_type==INTERNAL_COLUMN_KEY) {
			extra_size+=sfield->verification_column_name.length; // verification key
		} else if(sfield->verification_key_type==TABLE_ISSUER_KEY) {
			if(sfield->sig_field_type==sign_only_field) 
				extra_size+=trust_options->table_issuer_pub_key.length ; //
			else if(sfield->sig_field_type==sign_ordered_field) 
				extra_size+=trust_options->tosa_pub_key.length ; //
		} else if(sfield->verification_key_type==REFERENCE_KEY) {
			// To do referenced tablename & column
		}

		if(trust_options->Trusted_table_type==2) {
			extra_size+=1; // Sig field type
			if(sfield->sig_field_type==sign_ordered_field) {
				extra_size+=1; // order field length
				extra_size+=sfield->order_column_name.length;
				if(!sfield->time_column_name.str) {
					extra_size+=1; // if time_column_name is null   put only length
				} else {
					extra_size+=1; // order field length
					extra_size+=sfield->time_column_name.length;
				}
			}
		}			
	}
	
	CLOG_TPRINTLN("SIG extra_size = %d sfield_no = %d",extra_size,sfield_no);

	// put length of Table_Image+Sig_Info at TLDGR_TLC_HEADER_SIZE-2)
	int2store(tldHeader+(TRUSTSQL_TLC_HEADER_SIZE-2),trust_options->table_schema.length+2+extra_size);

	frm.length = TRUSTSQL_TLC_HEADER_SIZE + trust_options->table_schema.length + 2 + extra_size;
	CLOG_TPRINTLN("total FRM LENGTH = %d",frm.length);

	CLOG_STEP("3","my_malloc");
	frm_ptr= (uchar*) my_malloc(frm.length, MYF(MY_WME | MY_ZEROFILL |
												MY_THREAD_SPECIFIC));
	bzero((char*)frm_ptr,frm.length);
	sfi_it.rewind();

	CLOG_STEP("4","Copy Header to frm");
	memcpy(frm_ptr, tldHeader, TRUSTSQL_TLC_HEADER_SIZE);

	CLOG_STEP("5","build extra image");
	pos = frm_ptr + TRUSTSQL_TLC_HEADER_SIZE;
	int2store(pos,trust_options->table_schema.length);
	pos+=2;
	memcpy(pos,trust_options->table_schema.str,trust_options->table_schema.length);
	pos+=trust_options->table_schema.length;
	CLOG_TPRINTLN("table_schema=%s",trust_options->table_schema.str);

	CLOG_TPRINTLN("tldHeader[6] = SIFG_Info Offset=%d",(pos-(frm_ptr+TRUSTSQL_TLC_HEADER_SIZE)));
   	int2store(frm_ptr+6, (pos-(frm_ptr+TRUSTSQL_TLC_HEADER_SIZE)));

	int2store(pos, extra_size); // SIGF_TL(2) : tot_len of all sig_infos
	pos+=2;
	*pos = (uchar)sfield_no;    // SIGF_NO(1) : Sig field Number   
	pos+=1;
	while(sfield=sfi_it++) {
		*pos = (uchar)sfield->sig_column_name.length;  // SNF_L(1)
		pos+=1;
		memcpy(pos,sfield->sig_column_name.str,sfield->sig_column_name.length); // SNF(N)
		CLOG_TPRINTLN("sig_column_name =%s",sfield->sig_column_name.str);
		pos+= sfield->sig_column_name.length;
		*pos = (uchar)sfield->sig_name.length;  // SNN_L(1) Constraint Name
		pos+=1;
		memcpy(pos,sfield->sig_name.str,sfield->sig_name.length); // SNN(N)
		CLOG_TPRINTLN("sig_name =%s",sfield->sig_name.str);
		pos+= sfield->sig_name.length;

		if((trust_options->Trusted_table_type==1)||((trust_options->Trusted_table_type==2)&&(sfield->sig_field_type == sign_only_field))) {
			if_it = sfield->input_fields;
			ifield_no=0;
			while(ifield=if_it++) ifield_no++;
			if_it.rewind();
			int2store(pos,ifield_no);  // INF_NUM(2)
			pos+=2; 	
			while(ifield=if_it++) {
				*pos = (uchar)ifield->name.length;	// IN_L
				pos+=1;
				memcpy(pos,ifield->name.str,ifield->name.length); // INN
				CLOG_TPRINTLN("input =%s",ifield->name.str);
				pos+=ifield->name.length;
			}
		} else if((trust_options->Trusted_table_type==2)&&(sfield->sig_field_type == sign_ordered_field)) {
			// use all fields
			cf_it.rewind();
			ifield_no=0;
			while(cf=cf_it++) ifield_no++;
			cf_it.rewind();
			ifield_no--;    // exclude sign field with option
			int2store(pos,ifield_no);  // INF_NUM(2)
			pos+=2; 	
			while(cf=cf_it++) {
				// exclude sign field with option
				if (lex_string_cmp(system_charset_info, &sfield->sig_column_name , &cf->field_name) != 0) {
					*pos = (uchar)cf->field_name.length;	// IN_L
					pos+=1;
					memcpy(pos,cf->field_name.str,cf->field_name.length); // INN
					CLOG_TPRINTLN("input =%s",cf->field_name.str);
					pos+=cf->field_name.length;
				}
			}
		}

		*pos = sfield->verification_key_type; 
		pos+=1;
		if(sfield->verification_key_type==FIXED_KEY) {
			*pos = sfield->fixed_verification_key.length;
			pos+=1;
			memcpy(pos,sfield->fixed_verification_key.str,sfield->fixed_verification_key.length);
			pos+=sfield->fixed_verification_key.length;
			CLOG_TPRINTLN("verification key  =%s",sfield->fixed_verification_key.str);
		} else if(sfield->verification_key_type==INTERNAL_COLUMN_KEY) {
			*pos = sfield->verification_column_name.length;
			pos+=1;
			memcpy(pos,sfield->verification_column_name.str,sfield->verification_column_name.length);
			pos+=sfield->verification_column_name.length;
			CLOG_TPRINTLN("verification_column_name key  =%s",sfield->verification_column_name.str);				
		} else if(sfield->verification_key_type==TABLE_ISSUER_KEY) {
			if(sfield->sig_field_type==sign_only_field) { 
				*pos = trust_options->table_issuer_pub_key.length;
				pos+=1;
				memcpy(pos,trust_options->table_issuer_pub_key.str,trust_options->table_issuer_pub_key.length);
				pos+=trust_options->table_issuer_pub_key.length;
			} else if(sfield->sig_field_type==sign_ordered_field) { 
				*pos = trust_options->tosa_pub_key.length;
				pos+=1;
				memcpy(pos,trust_options->tosa_pub_key.str,trust_options->tosa_pub_key.length);
				pos+=trust_options->tosa_pub_key.length;
			}
		} else {

			//TODO Reference table name & column.

		}

		if(trust_options->Trusted_table_type==2) {
			*pos = sfield->sig_field_type;
			pos+=1;
			if(sfield->sig_field_type==sign_ordered_field) {
				CLOG_TPRINTLN("tldHeader[8] = Order Column Name Offset=%d",(pos-(frm_ptr+TRUSTSQL_TLC_HEADER_SIZE)));
				int2store(frm_ptr+8, (pos-(frm_ptr+TRUSTSQL_TLC_HEADER_SIZE)));
				*pos = sfield->order_column_name.length;
				pos+=1; 			
				memcpy(pos,sfield->order_column_name.str,sfield->order_column_name.length);
				pos+=sfield->order_column_name.length;

				if(!sfield->time_column_name.str) {
					*pos = 0;
					pos+=1;
				} else {
					*pos = sfield->time_column_name.length;
					pos+=1;
					memcpy(pos,sfield->time_column_name.str,sfield->time_column_name.length);
					pos+=sfield->time_column_name.length;
				}
			}	
		}			
	}

	CLOG_TPRINTLN("built Trusted Frm Image:");
	CLOG_DISPBUFFER(frm_ptr,frm.length);
	frm.str= frm_ptr;
	  
	return frm;
}



bool init_share_from_tld_image(THD *thd, TABLE_SHARE*share,const uchar *tld_image, size_t tld_length) {
	ulong tot_len;
	ulong tot_sig_len;
	char *temp_str;
	const uchar *sig_field_pos;
	const uchar *tldgr_extra_pos;
	ulong extra_pos;
	uint sig_field_no;
	st_tldg_sig_info *sinfo;
	char *sig_name,*inf_name;
	uint input_no;
	LEX_CSTRING *input_fields;
	Sig_field_info *sig_field_info;
	const uchar * pos;
	uint len;

    CLOG_FUNCTIOND("bool init_share_from_tld_image(THD *thd, TABLE_SHARE*share,const uchar *tld_image size_t tld_length)");

   	share->trust_options = (Table_trust_options*) alloc_root(&share->mem_root,sizeof(Table_trust_options));	
	CLOG_TPRINTLN("trust_options (0x%08X) alloc_root()", &share->trust_options);
	
	share->trust_options->Tlc_version = tld_image[2];
	CLOG_TPRINTLN("Tlc_version = 0x%08X(%d)",share->trust_options->Tlc_version);

    share->trusted_table_type= tld_image[3];
	share->trust_options->Trusted_table_type = tld_image[3];
	CLOG_TPRINTLN("Trusted Table Type = (%d)",share->trusted_table_type);

	share->trust_options->Dsa_algorithm_type = tld_image[4];
	CLOG_TPRINTLN("Dsa_algorithm_type = %d",share->trust_options->Dsa_algorithm_type);

	temp_str = ( char*)alloc_root(&share->mem_root,sizeof("SECP256K1"));
	memcpy(temp_str,"SECP256K1",sizeof("SECP256K1"));
	share->trust_options->Dsa_mechanism.mechanism_name.str = temp_str;
	share->trust_options->Dsa_mechanism.mechanism_name.length=sizeof("SECP256K1");
	share->trust_options->Dsa_mechanism.mechanism_id=0;
	share->trust_options->Dsa_mechanism.parameter1=0;
	share->trust_options->Dsa_mechanism.parameter2=0;

	pos = &tld_image[16];

	/* Sequence
		1.table_issuer_pub_key
		2.trusted_reference_pub_key
		3.tosa_pub_key
		4.tosa_master_pub_key
		  table_schema	-> Move to End of TLC
		5.table_schema_sign
		6.trusted_reference_sign
		7.trigger_before_insert_sign
		8.trigger_after_insert_sign
	 */
	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		temp_str = ( char*)alloc_root(&share->mem_root,len+1);
		memcpy(temp_str,pos,len);
		temp_str[len]=0;
		pos+=len;
		share->trust_options->table_issuer_pub_key.str=temp_str;
		share->trust_options->table_issuer_pub_key.length=len;
	}

	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		temp_str = ( char*)alloc_root(&share->mem_root,len+1);
		memcpy(temp_str,pos,len);
		temp_str[len]=0;
		pos+=len;
		share->trust_options->trusted_reference_pub_key.str=temp_str;
		share->trust_options->trusted_reference_pub_key.length=len;
	}

	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		temp_str = ( char*)alloc_root(&share->mem_root,len+1);
		memcpy(temp_str,pos,len);
		temp_str[len]=0;
		pos+=len;
		share->trust_options->tosa_pub_key.str=temp_str;
		share->trust_options->tosa_pub_key.length=len;
	}
	
	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		temp_str = ( char*)alloc_root(&share->mem_root,len+1);
		memcpy(temp_str,pos,len);
		temp_str[len]=0;
		pos+=len;
		share->trust_options->tosa_master_pub_key.str=temp_str;
		share->trust_options->tosa_master_pub_key.length=len;
	}

	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		temp_str = ( char*)alloc_root(&share->mem_root,len+1);
		memcpy(temp_str,pos,len);
		temp_str[len]=0;
		pos+=len;
		share->trust_options->table_schema_sign.str=temp_str;
		share->trust_options->table_schema_sign.length=len;
	}

	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		temp_str = ( char*)alloc_root(&share->mem_root,len+1);
		memcpy(temp_str,pos,len);
		temp_str[len]=0;
		pos+=len;
		share->trust_options->trusted_reference_sign.str=temp_str;
		share->trust_options->trusted_reference_sign.length=len;
	}

	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		temp_str = ( char*)alloc_root(&share->mem_root,len+1);
		memcpy(temp_str,pos,len);
		temp_str[len]=0;
		pos+=len;
		share->trust_options->trigger_before_insert_sign.str=temp_str;
		share->trust_options->trigger_before_insert_sign.length=len;
	}

	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		temp_str = ( char*)alloc_root(&share->mem_root,len+1);
		memcpy(temp_str,pos,len);
		temp_str[len]=0;
		pos+=len;
		share->trust_options->trigger_after_insert_sign.str=temp_str;
		share->trust_options->trigger_after_insert_sign.length=len;
	}

	sig_field_pos = &tld_image[TRUSTSQL_TLC_HEADER_SIZE];

    len=uint2korr(sig_field_pos);
    sig_field_pos+=2;
    if(len!=0) {
    	temp_str = ( char*)alloc_root(&share->mem_root,len+1);
    	memcpy(temp_str,sig_field_pos,len);
    	temp_str[len]=0;
    	sig_field_pos+=len;
    	share->trust_options->table_schema.str=temp_str;
    	share->trust_options->table_schema.length=len;
    }

    tot_sig_len = uint2korr(sig_field_pos);
	sig_field_pos+=2;
	sig_field_no = (unsigned char) *sig_field_pos;
	sig_field_pos+=1;
	CLOG_TPRINTLN("Total Sig Info Len = %d",tot_sig_len);
	CLOG_TPRINTLN("Total Sig Field Num = %d",sig_field_no);
   	share->trust_options->sig_field_infos_no = sig_field_no;

	sig_field_info = (Sig_field_info*)alloc_root(&share->mem_root,sizeof(Sig_field_info)*(sig_field_no)); // sig_field_no-> Share Member?
	bzero((char*)sig_field_info, sizeof(Sig_field_info)*(sig_field_no));
	share->trust_options->sig_field_info_list = sig_field_info;

    for(int i=0; i<sig_field_no; i++,sig_field_info++) {
		// Sig field name
		sig_field_info->sig_column_name.length = *sig_field_pos;
		sig_field_pos+=1;
		temp_str = (char*)alloc_root(&share->mem_root,(sig_field_info->sig_column_name.length+1));
		memcpy(temp_str,sig_field_pos,sig_field_info->sig_column_name.length);
		temp_str[sig_field_info->sig_column_name.length]=0;
		sig_field_info->sig_column_name.str = temp_str;
		sig_field_pos+=sig_field_info->sig_column_name.length;
		CLOG_TPRINTLN("SIG FIELD NAME[%d] = %s",i,temp_str);
		sig_field_info->sig_name.length = *sig_field_pos;
		sig_field_pos+=1;
		temp_str = (char*)alloc_root(&share->mem_root,(sig_field_info->sig_name.length+1));
		memcpy(temp_str,sig_field_pos,sig_field_info->sig_name.length);
		temp_str[sig_field_info->sig_name.length]=0;
		sig_field_info->sig_name.str = temp_str;
		sig_field_pos+=sig_field_info->sig_name.length;
		CLOG_TPRINTLN("SIG NAME[%d] = %s",i,temp_str);

		input_no = uint2korr(sig_field_pos);
		sig_field_info->input_fields_no = input_no;
		CLOG_TPRINTLN("input fields number = %d",input_no);
		sig_field_pos+=2;
		input_fields = (LEX_CSTRING*)alloc_root(&share->mem_root,sizeof(LEX_CSTRING)*input_no);
		sig_field_info->input_fields=input_fields;
		for(int j=0; j<input_no; j++,input_fields++) {			
			input_fields->length = (size_t)*sig_field_pos;
			sig_field_pos+=1;
			temp_str = (char*)alloc_root(&share->mem_root,input_fields->length+1);
			memcpy(temp_str,sig_field_pos,input_fields->length);
			temp_str[input_fields->length]=0;
			CLOG_TPRINTLN("SIG INPUT FIELD NAME[%d] = %s",j,temp_str);
			input_fields->str = temp_str;
			sig_field_pos+=input_fields->length;
		}
		sig_field_info->verification_key_type = (Verification_key_type)*sig_field_pos;
		sig_field_pos+=1;
		if((sig_field_info->verification_key_type==TABLE_ISSUER_KEY)||(sig_field_info->verification_key_type==FIXED_KEY)) {
			sig_field_info->fixed_verification_key.length = *sig_field_pos;
			sig_field_pos+=1;
			temp_str = (char*)alloc_root(&share->mem_root,sig_field_info->fixed_verification_key.length+1);
			memcpy(temp_str,sig_field_pos,sig_field_info->fixed_verification_key.length);
			CLOG_DISPBUFFER(temp_str, 131);
			temp_str[sig_field_info->fixed_verification_key.length]=0;
			CLOG_DISPBUFFER(temp_str, 131);
			CLOG_TPRINTLN("SIG VERIFICATION KEY[%d] = %s",i,temp_str);
			sig_field_info->fixed_verification_key.str = temp_str;
			sig_field_pos+=sig_field_info->fixed_verification_key.length;
		} else if(sig_field_info->verification_key_type==INTERNAL_COLUMN_KEY) {		
			sig_field_info->verification_column_name.length = *sig_field_pos;
			sig_field_pos+=1;
			temp_str = (char*)alloc_root(&share->mem_root,sig_field_info->verification_column_name.length+1);
			memcpy(temp_str,sig_field_pos,sig_field_info->verification_column_name.length);
			temp_str[sig_field_info->verification_column_name.length]=0;
			CLOG_TPRINTLN("SIG verification_column_name [%d] = %s",i,temp_str);
			sig_field_info->verification_column_name.str = temp_str;
			sig_field_pos+=sig_field_info->verification_column_name.length;
		} else if(sig_field_info->verification_key_type==REFERENCE_KEY) {		

		} else {
			// TODO ASSERT		
		}
				
		if(	share->trust_options->Trusted_table_type == 2) {
			sig_field_info->sig_field_type = (Sig_field_type)*sig_field_pos;
			sig_field_pos+=1;
			
			if(sig_field_info->sig_field_type==sign_ordered_field) {
				sig_field_info->order_column_name.length = *sig_field_pos;
				sig_field_pos+=1;
				temp_str = (char*)alloc_root(&share->mem_root,sig_field_info->order_column_name.length+1);
				memcpy(temp_str,sig_field_pos,sig_field_info->order_column_name.length);
				temp_str[sig_field_info->order_column_name.length]=0;
				CLOG_TPRINTLN("SIG order_column_name [%d] = %s",i,temp_str);
				sig_field_info->order_column_name.str = temp_str;
				sig_field_pos+=sig_field_info->order_column_name.length;
				CLOG_TPRINTLN("SIG order_column_name A = %s",sig_field_info->order_column_name.str);

				sig_field_info->time_column_name.length = *sig_field_pos;
				sig_field_pos+=1;
				if(sig_field_info->time_column_name.length!=0) {
					temp_str = (char*)alloc_root(&share->mem_root,sig_field_info->time_column_name.length+1);
					memcpy(temp_str,sig_field_pos,sig_field_info->time_column_name.length);
					temp_str[sig_field_info->time_column_name.length]=0;
					CLOG_TPRINTLN("SIG time_column_name [%d] = %s",i,temp_str);
					sig_field_info->time_column_name.str = temp_str;
					sig_field_pos+=sig_field_info->time_column_name.length;
					CLOG_TPRINTLN("SIG time_column_name A = %s",sig_field_info->time_column_name.str);
				}
			}
    	}
				
    }

	return false;
err:
	//my_error(ER_DUP_FIELDNAME, MYF(0), sql_field->field_name.str);
	return true;
}



/**
  Create a TLD (Trusted Ledger Definition) file

  @param aaa                    bbbb
  @

  @return

  저장은 하는데 어떻게 언제 읽어들여야 할지에 대한 분석 및 읽어들이는 방법의 구현이 필요하다.
  먼저 desc table이나, select 구문을 이용하여 코드를 살펴보아야 한다.


*/

bool tldgr_add_const4t_table(THD *thd, const char *frm, size_t frm_length, const char *path, const char *db, const char *table_name){
	char	 file_name[FN_REFLEN+1];
	int error;
	int create_flags= O_RDWR | O_TRUNC;

	CLOG_FUNCTIOND("bool tldgr_add_const4t_table(...)");
    CLOG_TPRINTLN("path= %s,  db=%s, table_name=%s",path, db, table_name);

    strxnmov(file_name, sizeof(file_name)-1, path, TRUSTSQL_CNF_FILE_EXT, NullS);
    CLOG_TPRINTLN("full file name = %s",file_name);

    CLOG_STEP("1","create file");
    // 아래 함수에서는 my_register_filename(..)을 호출해서 등록작업을 한다. 나중에 이를 해야 할지 하게된다면 어떻게 활용해야 할지
    // 고민이 필요하다.
	File file= mysql_file_create(key_file_frm, file_name, CREATE_MODE, create_flags, MYF(0));

    if (unlikely((error= file < 0))) {
    	if (my_errno == ENOENT)
    		my_error(9999/*ER_BAD_DB_ERROR*/, MYF(0), db);
	    //else
	    //	my_error(9999/*ER_CANT_CREATE_TABLE*/, MYF(0), db, table, my_errno);
    } else {
	 CLOG_STEP("2","write file");
	 error= (int)mysql_file_write(file, (uchar *)frm, frm_length, MYF(MY_WME | MY_NABP));
     /*
	 if (!error && !tmp_table && opt_sync_frm) {
		 ZLOG_STEP("3","file sync, ....");
		 error= mysql_file_sync(file, MYF(MY_WME)) ||
			  my_sync_dir_by_file(file_name, MYF(MY_WME));
	 }
	 */
	 CLOG_STEP("4","file close()");
	 error|= mysql_file_close(file, MYF(MY_WME));
   }
   if(error)
	   goto err;

	return false;
err:
/*
 * 이거 머 정리를 해야 할듯.. 실패시 해야 하는 작업인거 같아.
  share->db_plugin= NULL;
  share->error= OPEN_FRM_CORRUPTED;
  share->open_errno= my_errno;
  delete handler_file;
  plugin_unlock(0, se_plugin);
  my_hash_free(&share->name_hash);

  if (!thd->is_error())
    open_table_error(share, OPEN_FRM_CORRUPTED, share->open_errno);

  thd->mem_root= old_root;
  DBUG_RETURN(HA_ERR_NOT_A_TABLE);
*/
	return true;
}

/**
  parses list of options for tredger.
  @param thd              thread handler
  @param option_list      list of options given by user
  @param rules            list of option description by trusted ledger logic
  @param unparsed_option_list	option list not parsed in this function
  @param suppress_warning second parse so we do not need warnings
  @param root             MEM_ROOT where allocate memory

  @retval TRUE  Error
  @retval FALSE OK
*/

bool tldgr_parse_option_list(THD* thd, engine_option_value **option_list) {
	engine_option_value *val;
	CLOG_FUNCTIOND("bool tldgr_prase_optiopn_list(...)");

	for (val= *option_list; val; val= val->next)
	{
	  /* skip duplicates (see engine_option_value constructor above) */
	  if (val->parsed && !val->value.str)
		continue;
	  CLOG_TPRINTLN(" ----> option = %s  option_parsed = %d value = %s", val->name.str, val->parsed, val->value.str);

	  if (!my_strnncoll(system_charset_info,
	  			  (uchar*)create_trusted_table_options[0].name, create_trusted_table_options[0].name_length,
	  			  (uchar*)val->name.str, val->name.length)) {
	  				  thd->lex->trust_options->dsa_scheme = val->value;
	  } else if (!my_strnncoll(system_charset_info,
			  (uchar*)create_trusted_table_options[1].name, create_trusted_table_options[1].name_length,
			  (uchar*)val->name.str, val->name.length)) {
				  thd->lex->trust_options->table_issuer_pub_key = val->value;
	  } else if (!my_strnncoll(system_charset_info,
			  (uchar*)create_trusted_table_options[2].name, create_trusted_table_options[2].name_length,
			  (uchar*)val->name.str, val->name.length)) {
				  thd->lex->trust_options->trusted_reference_pub_key = val->value;
	  } else if (!my_strnncoll(system_charset_info,
			  (uchar*)create_trusted_table_options[3].name, create_trusted_table_options[3].name_length,
			  (uchar*)val->name.str, val->name.length)) {
				  thd->lex->trust_options->tosa_pub_key = val->value;
	   } else if (!my_strnncoll(system_charset_info,
			  (uchar*)create_trusted_table_options[4].name, create_trusted_table_options[4].name_length,
			  (uchar*)val->name.str, val->name.length)) {
		   	   	   thd->lex->trust_options->tosa_master_pub_key = val->value;
	   } else if (!my_strnncoll(system_charset_info,
			   (uchar*)create_trusted_table_options[5].name, create_trusted_table_options[5].name_length,
			   (uchar*)val->name.str, val->name.length)) {
				  thd->lex->trust_options->table_schema  = val->value;
	   } else if (!my_strnncoll(system_charset_info,
			  (uchar*)create_trusted_table_options[6].name, create_trusted_table_options[6].name_length,
			  (uchar*)val->name.str, val->name.length)) {
				  thd->lex->trust_options->table_schema_sign = val->value;
	   } else if (!my_strnncoll(system_charset_info,
	   		  (uchar*)create_trusted_table_options[7].name, create_trusted_table_options[7].name_length,
	   		  (uchar*)val->name.str, val->name.length)) {
	   			  thd->lex->trust_options->trusted_reference_sign = val->value;
	   } else if (!my_strnncoll(system_charset_info,
	   	   	  (uchar*)create_trusted_table_options[8].name, create_trusted_table_options[8].name_length,
	   	   	  (uchar*)val->name.str, val->name.length)) {
	   	   		  thd->lex->trust_options->trigger_before_insert_sign = val->value;
	   } else if (!my_strnncoll(system_charset_info,
	   	   	  (uchar*)create_trusted_table_options[9].name, create_trusted_table_options[9].name_length,
	   	   	  (uchar*)val->name.str, val->name.length)) {
	   	   		  thd->lex->trust_options->trigger_after_insert_sign = val->value;
	   } else {
		   continue;
	   }
	   val->parsed=true;
	}
	return FALSE; //DBUG_RETURN(FALSE); 이거 DBUG로 만들어 주어야 함...
}


/**
  Check if a given table exists, without doing a full discover, if possible

  @retval true    Table exists (even if the error occurred, like bad frm)
  @retval false   Table does not exist (one can do CREATE TABLE table_name)

  @note if frm exists and the table in engine doesn't, *hton will be set,
        but the return value will be false.

  @note if frm file exists, but the table cannot be opened (engine not
        loaded, frm is invalid), the return value will be true, but
        *hton will be NULL.
*/

static my_bool file_ext_exists(char *path, size_t path_len, const char *ext)
{
  strmake(path + path_len, ext, FN_REFLEN - path_len);
  return !access(path, F_OK);
}

bool trusted_table_exists(THD* thd, const LEX_CSTRING *db, const LEX_CSTRING *table_name) {
    CLOG_FUNCTIOND("bool trusted_table_exists(THD* thd, const LEX_CSTRING *db, const LEX_CSTRING *table_name)");
	char path[FN_REFLEN + 1];
	size_t path_len = build_table_filename(path, sizeof(path) - 1,
										 db->str, table_name->str, "", 0);

	if (file_ext_exists(path, path_len, TRUSTSQL_CNF_FILE_EXT))
	{
		return true;
	}
	return false;
}


/**
  Check if a given table exists, trusted and verified without doing a full discover, if possible

  @retval true    Table exists (even if the error occurred, like bad frm)
  @retval false   Table does not exist (one can do CREATE TABLE table_name)

  @note if frm exists and the table in engine doesn't, *hton will be set,
        but the return value will be false.
*/


int check_table_definition_trusted(THD *thd, LEX_CSTRING *db_name, LEX_CSTRING *table_name, LEX_CSTRING child_issuer_key) {
	File file;
	uchar *buf;
	uchar head[FRM_HEADER_SIZE];
	size_t frmlen, read_length;
	uint len;
	char path[FN_REFLEN + 1];
	uchar tldgr_head[TRUSTSQL_TLC_HEADER_SIZE+2]; // Header + Table Image Len
	uchar *file_buffer;
	const char *pos;
	char *temp_str;
	uint errorno;
	LEX_CSTRING issuer_pub_key={0,0};
	LEX_CSTRING table_image={0,0};
	LEX_CSTRING table_image_sign={0,0};
	LEX_CSTRING table_child_pub_key={0,0};
	CLOG_FUNCTIOND("int check_table_definition_trusted(THD *thd, LEX_CSTRING db_name, LEX_CSTRING table_name)");

	
	size_t path_len = build_table_filename(path, sizeof(path) - 1,
										 db_name->str, table_name->str, ".frm", 0);
	CLOG_TPRINTLN(" FRM path = %s",path);
	
	file= mysql_file_open(key_file_frm, path, O_RDONLY | O_SHARE, MYF(0));
	if (file < 0)
	{
		errorno=1;
		goto err;
	}

 	CLOG_STEP("2","File Read");
	if (mysql_file_read(file, head, 2, MYF(MY_NABP)))
 	{
		errorno=2;
	  	goto err;
 	}

	if(head[1]!='T') {
		errorno=3;
	  	goto err;
	}

	mysql_file_close(file, MYF(MY_WME));

	path_len = build_table_filename(path, sizeof(path) - 1,
											 db_name->str, table_name->str, TRUSTSQL_CNF_FILE_EXT, 0);
    CLOG_TPRINTLN("TLC path  = %s",path);
	
 	file= mysql_file_open(key_file_frm, path, O_RDONLY | O_SHARE, MYF(0));
	if (file < 0)
	{
		errorno=4;
	  	goto err;
	}
	
	CLOG_STEP("2","File Read");
	if (mysql_file_read(file, tldgr_head, sizeof(tldgr_head), MYF(MY_NABP)))
	{
		errorno=5;
	  	goto err;
	}

	pos = (char *)&tldgr_head[16];

	// Table Issuer's Public Key
	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		issuer_pub_key.str = pos;
		issuer_pub_key.length=len;		
		pos+=len;
	}

	// Master Trusted Orderer's Public Key
	len=uint2korr(pos);
	pos+=2+len;
	// SUB Trusted Orderer's Public Key
	len=uint2korr(pos);
 	pos+=2+len;

	// Table Image Sign
	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		table_image_sign.str =pos;
		table_image_sign.length=len;		
		pos+=len;
	}	

	// Table Chid Public Key
	len=uint2korr(pos);
	pos+=2;
	if(len!=0) {
		table_child_pub_key.str = pos;
		table_child_pub_key.length=len;		
		pos+=len;
	}

	len = uint2korr(&tldgr_head[TRUSTSQL_TLC_HEADER_SIZE]);
	temp_str = (char *) my_malloc(len, MYF(MY_WME | MY_ZEROFILL | MY_THREAD_SPECIFIC));

	if (mysql_file_read(file, (uchar*)temp_str, len, MYF(MY_NABP)))
	{
		errorno=6;
		goto err;
	}

	table_image.str=temp_str;
	table_image.length=len;

	if(verify_string(thd, table_image, issuer_pub_key, table_image_sign)) {
		errorno=7;
		goto err;
	}

	if(table_child_pub_key.length!=0) {
		// Compare Parent's child pub key with Child's issuer Key.
		CLOG_TPRINTLN("Compare Parent's child pub key with Child's issuer Key!");
		CLOG_TPRINTLN("child Table Issuer Key = %s",table_child_pub_key.str);
		CLOG_TPRINTLN("Parent Table child Key = %s",child_issuer_key.str);
		if (lex_string_cmp(system_charset_info, &table_child_pub_key,&child_issuer_key) != 0) {
			errorno=8;
			goto err;
		}
	}

	my_free(temp_str);
	mysql_file_close(file, MYF(MY_WME));

	return false;

err:
	my_free(temp_str);
	mysql_file_close(file, MYF(MY_WME));
	return false;
	/* TODO -  TRUSTED-REFERNECE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1
	 * TODO -  TRUSTED-REFERNECE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1
	 * TODO -  TRUSTED-REFERNECE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1
	 * TODO -  TRUSTED-REFERNECE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!1
	push_warning_printf(thd, Sql_condition::WARN_LEVEL_WARN, 5100+errorno,
								"Trusted Refernece Violation : %s.%s can't be verifeid",db_name->str,table_name->str);
    return thd->really_abort_on_warning();
    */
}

void transform_trigger_for_sign(THD *thd, String *inputText, String *transformedText) {
	CLOG_FUNCTIOND("String *transform_text_for_sign(THD *thd, String *inputText)");
    char *in, *trans;
    int len,newlen;

	len = inputText->length();
	in = (char *) alloc_root(thd->mem_root, len+1);
	memset(in,0,len);
	memcpy(in,inputText->c_ptr(),len);
	in[len]=0;
	// Rule -> It is just DONGWON's Rule but looks OK.
	// 1. CR changed to single space '_' LF changed to single space '_'
	// 2. Tab changed to single space '_'
	trans = in;
	for(int i=0; i<len; i++) {
		CLOG_TPRINTLN("[%d] %x %c",i,*trans,*trans);
		if(*trans=='\r') {
		//	CLOG_TPRINTLN("REP to Space = [%d] %x %c",i,*trans,*trans);
			*trans=' ';
		} else if(*trans=='\n') {
		//	CLOG_TPRINTLN("REP to Space = [%d] %x %c",i,*trans,*trans);
			*trans=' ';
		} else if(*trans=='\t') {
		//	CLOG_TPRINTLN("REP to Space = [%d] %x %c",i,*trans,*trans);
			*trans=' ';
		}
		trans++;
	}

	// 3. Double Space '__' changed to single space '_'
	trans = in;
	for(int i=0; i<len; i++) {
		if((*trans==' ')&&((*(trans+1))==' ')) {
			char * temp;
			temp = trans;
			for(int j=0; j<len; j++) {
				*temp = *(temp+1);
				temp++;
				if(*temp==0) break;
			}
		} else
			trans++;
		if(*trans==0) break;
	}

	trans = in;
	newlen=0;
	for(; *trans!=0; trans++ ) {
		newlen++;
	}
	transformedText->set(in,newlen, inputText->charset());
}


Item *transform_text_for_sign(THD *thd, Item *inval) {
	CLOG_FUNCTIOND("bool transform_text_for_sign(THD *thd, Item *inval)");
    char *in, *trans;
    int len,newlen;

	len = inval->val_str()->length();
	in = (char *) alloc_root(thd->mem_root, len+1);
	memset(in,0,len);
	memcpy(in,inval->val_str()->ptr(),len);
	in[len]=0;
	// Rule -> It is just DONGWON's Rule but looks OK.
	// 1. CR changed to single space '_' LF changed to single space '_'
	// 2. Tab changed to single space '_'
	trans = in;
	for(int i=0; i<len; i++) {
		if(*trans=='\r')
			*trans=' ';
		else if(*trans=='\n')
			*trans=' ';
		else if(*trans=='\t')
			*trans=' ';
		trans++;
	}

	// 3. Double Space '__' changed to single space '_'
	trans = in;
	for(int i=0; i<len; i++) {
		if((*trans==' ')&&((*(trans+1))==' ')) {
			char * temp;
			temp = trans;
			for(int j=0; j<len; j++) {
				*temp = *(temp+1);
				temp++;
				if(*temp==0) break;
			}
		} else
			trans++;
		if(*trans==0) break;
	}

	trans = in;
	newlen=0;
	for(; *trans!=0; trans++ ) {
		newlen++;
	}	

	return thd->make_string_literal(in,newlen,MY_REPERTOIRE_ASCII);
}


FILE* Trusted_last_order::open_gid_log(const LEX_CSTRING *path, const LEX_CSTRING *db_name) {
	char fullName[FN_REFLEN + 1];

	char *name = strxmov(fullName,path->str,"/",db_name->str);
	CLOG_TPRINTLN(" gid log fiel = %s", name);
	this->fptr = fopen(name,"rb+");

	return this->fptr;
}

int Trusted_last_order::close_gid_log() {


}

int Trusted_last_order::read_last_order(unsigned long *last_order, unsigned int *record_index) {


}

int Trusted_last_order::get_last_order(unsigned long *last_order, unsigned int *record_no) {


}

int Trusted_last_order::add_new_order(unsigned long new_order) {


}


void hex2bin(const char* in, size_t len, unsigned char* out) {
  static const unsigned char TBL[] = {
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  58,  59,  60,  61,
    62,  63,  64,  10,  11,  12,  13,  14,  15,  71,  72,  73,  74,  75,
    76,  77,  78,  79,  80,  81,  82,  83,  84,  85,  86,  87,  88,  89,
    90,  91,  92,  93,  94,  95,  96,  10,  11,  12,  13,  14,  15
  };
  static const unsigned char *LOOKUP = TBL - 48;
  const char* end = in + len;
  while(in < end) *(out++) = LOOKUP[*(in++)] << 4 | LOOKUP[*(in++)];
}

#endif
