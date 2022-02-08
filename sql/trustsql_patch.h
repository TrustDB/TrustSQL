/*
 * trustsql_patch.h
 *
 *  Created on: 2019. 3. 12.
 *      Author: trustdb inc.
 */

#ifndef SQL_TRUSTSQL_PATCH_H_
#define SQL_TRUSTSQL_PATCH_H_

#include "mariadb.h"
#include "violite.h"                            /* SSL_type */
#include "sql_trigger.h"
#include "thr_lock.h"                  /* thr_lock_type, TL_UNLOCK */
#include "mem_root_array.h"
#include "sql_cmd.h"
#include "sql_alter.h"                // Alter_info
#include "sql_window.h"
#include "sql_trigger.h"
#include "sp.h"                       // enum stored_procedure_type
#include "sql_tvc.h"
#include "sql_class.h"
#include "sql_lex.h"
#include "handler.h"
//#include "clog.h"


#define TRUSTSQL_BASE_VERSION	"TRUSTSQL-1.0"
#define TRUSTSQL_VERSION_ID		010000
#define TRUSTSQL_BASE_MARIADB_VERSION "mariadb-10.3"
#define TRUSTSQL_BASE_MARIADB_VERSION_ID 100311
#define TRUSTSQL_TLC_VERSION		1

#define TRUSTSQL_TLC_HEADER_SIZE	1024
#define TRUSTSQL_MAX_SIG_FIELDS	255
#define TRUSTSQL_MAX_CREATE_IMAGE_SIZE	4096

#define TRUSTSQL_CNF_FILE_EXT ".tlc"
#define TRUSTSQL_FLAG_OFFSET  1

#define TRUSTSQL_GID_LOG_SIZE	4096

#define TRUSTSQL_LOGFILE "trustsql.log"

struct st_tldg_sig_info {
	LEX_CSTRING sig_name;
	unsigned int input_no;
	LEX_CSTRING *input_field_name;
};

// See. PKCS#11... below is just temporary mechanism parameters.
struct st_dsa_mechanism {
	LEX_CSTRING mechanism_name;
	unsigned int mechanism_id;
	unsigned int parameter1;
	unsigned int parameter2;
};


static ha_create_table_option create_trusted_table_options[] = {
		{HA_OPTION_TYPE_STRING,"DSA_SCHEME",sizeof("DSA_SCHEME"),  0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TABLE_ISSUER_PUB_KEY",sizeof("TABLE_ISSUER_PUB_KEY"),  0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TRUSTED_REFERENCE_PUB_KEY",sizeof("TRUSTED_REFERENCE_PUB_KEY"),  0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TOSA_PUB_KEY",sizeof("TOSA_PUB_KEY"),    0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TOSA_MASTER_PUB_KEY",sizeof("TOSA_MASTER_PUB_KEY"),    0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TABLE_SCHEMA",sizeof("TABLE_SCHEMA_SIGN"),        0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TABLE_SCHEMA_SIGN",sizeof("TABLE_SCHEMA_SIGN"),        0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TRUSTED_REFERENCE_SIGN",sizeof("TRUSTED_REFERENCE_SIGN"),        0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TRIGGER_BEFORE_INSERT_SIGN",sizeof("TRIGGER_BEFORE_INSERT_SIGN"),        0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TRIGGER_AFTER_INSERT_SIGN",sizeof("TRIGGER_AFTER_INSERT_SIGN"),        0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_ULL,0,0,                                   0,0,0,0,0,0,0 }
};

enum  Verification_key_type { TABLE_ISSUER_KEY, FIXED_KEY, INTERNAL_COLUMN_KEY, REFERENCE_KEY};
enum  Sig_field_type { sign_only_field, sign_ordered_field, sign_timed_field };

class Sig_field_info : public Sql_alloc {
public:
	LEX_CSTRING sig_name;
	LEX_CSTRING sig_column_name;
	unsigned int input_fields_no;
	LEX_CSTRING *input_fields;
	enum  Verification_key_type verification_key_type;
	LEX_CSTRING fixed_verification_key;
	LEX_CSTRING reference_table_name;
	LEX_CSTRING reference_table_column_name;
	enum Sig_field_type sig_field_type;
	LEX_CSTRING order_column_name;
	LEX_CSTRING time_column_name;
	LEX_CSTRING verification_column_name;
};


class LEX_sig_field_info : public Sql_alloc {
public:
	LEX_CSTRING sig_name;
	LEX_CSTRING sig_column_name;
	List<Item>  input_fields;
	enum  Verification_key_type verification_key_type;
	LEX_CSTRING fixed_verification_key = {0,0};
	LEX_CSTRING reference_table_name;
	LEX_CSTRING reference_table_column_name;
	enum Sig_field_type sig_field_type;
	LEX_CSTRING order_column_name = {0,0};
	LEX_CSTRING time_column_name = {0,0};
	LEX_CSTRING verification_column_name = {0,0};
	
	void set_sig_name(LEX_CSTRING *sname, LEX_CSTRING *fname) {
		sig_name = *sname;
		sig_column_name= *fname;
	}

	void set_sig_name(LEX_CSTRING *fname) {
		sig_column_name= *fname;
	}

	void set_order_column_name(LEX_CSTRING *sname, LEX_CSTRING *oname) {
		sig_name = *sname;
		order_column_name= *oname;
		sig_field_type = sign_ordered_field;
	}

	void set_time_column_name(LEX_CSTRING *sname, LEX_CSTRING *tname) {
			sig_name = *sname;
			order_column_name= *tname;
			sig_field_type = sign_ordered_field;
	}

	void set_order_column_name(LEX_CSTRING *oname) {
		order_column_name= *oname;
		sig_field_type = sign_ordered_field;
	}

	void set_time_column_name(LEX_CSTRING *tname) {
		time_column_name= *tname;
	}


	void set_verification_column_name(LEX_CSTRING *vname) {
		verification_column_name= *vname;
		verification_key_type = INTERNAL_COLUMN_KEY;
	}
	

	bool add_sig_input_field(THD *thd, Item *item);
	bool set_fixed_field_verification_key_value(LEX_CSTRING * key_value);
};

class Trusted_last_order : public Sql_alloc {
private:
	LEX_CSTRING db_name={0,0};
	unsigned long last_order=0;
	unsigned int record_no=0;
	FILE *fptr=NULL;

public:
	FILE* open_gid_log(const LEX_CSTRING *path, const LEX_CSTRING *db_name);
	int close_gid_log();
	int read_last_order(unsigned long *last_order, unsigned int *record_no);
	int get_last_order(unsigned long *last_order, unsigned int *record_no);
	int add_new_order(unsigned long new_order);
};


class Table_trust_options : public Sql_alloc {
public:
	ha_create_table_option *table_options=create_trusted_table_options; // table level options TOS_M_PRK,TOS_S_PRK,TI_PRK, TI_SIGN
	
	unsigned char Tlc_version;
	unsigned int  Dsa_algorithm_type;  // we need to make it abstract function, verify, sign and so on...
	st_dsa_mechanism Dsa_mechanism;

	uint Trusted_table_type;	// 0 : It's not trusted Table  1: Trusted only 2: Trusted & Ordered 3: Trusted & Timed 4: Trusted & Ordered & Timed

	LEX_CSTRING dsa_scheme={0,0};	// dsa_scheme
	LEX_CSTRING table_issuer_pub_key={0,0};			// verify table schema sign
	LEX_CSTRING trusted_reference_pub_key={0,0};	// verify trusted reference relation.
	LEX_CSTRING tosa_pub_key={0,0};			// verify trusted order & time stamp.
	LEX_CSTRING tosa_master_pub_key={0,0};	// change tosa_pub_key
	LEX_CSTRING table_schema={0,0};			// table create statement
	LEX_CSTRING table_schema_sign={0,0};	// table_issuer's sign to table_schema
	LEX_CSTRING trusted_reference_sign={0,0};	// trusted reference sign to table_schema
	LEX_CSTRING trigger_before_insert_sign={0,0};	// before insert statement sign by table_issuer private key
	LEX_CSTRING trigger_after_insert_sign={0,0};	// before insert statement sign by table_issuer private key

	unsigned char  sig_field_infos_no;
	Sig_field_info *sig_field_info_list;

	Trusted_last_order trusted_last_orer;
	LEX_CSTRING get_field_option(THD *thd, LEX_CSTRING field_name);
	LEX_CSTRING get_order_option(THD *thd, LEX_CSTRING field_name);

	// we need to make it abstract function, verify, sign and so on...
};


class LEX_trust_options : public Table_trust_options {
public:	
	List<LEX_sig_field_info> list_lex_sig_field_info;
	LEX_trust_options(uint t_type) {
		Trusted_table_type=t_type;
	}

	bool add_sig_field_info(THD *thd, LEX_sig_field_info *sig_field);
};

// 
bool verify_record_sign(THD *thd, TABLE *table, List<Item> &fields, List<Item> &values);


bool tldgr_create_tld_image(THD *thd, const LEX_CSTRING *db, const LEX_CSTRING *table_name, List<Create_field> &create_fields, KEY **key_info, uint *key_count,LEX_CUSTRING *tld_image);

bool tldgr_trust_options_precheck(THD *thd, const LEX_CSTRING *table_name, List<Create_field> &create_fields, KEY **key_info, uint *key_count);

LEX_CUSTRING tldgr_const4t_build_image(LEX_trust_options *trust_options, List<Create_field> &create_fields, KEY **key_info, uint *key_count);

bool tldgr_add_const4t_table(THD *thd, const char *frm, size_t frm_length, const char *path, const char *db, const char *table_name);

//bool init_tldg_from_full_binary_frm_image(TABLE_SHARE*share,const uchar *frm_image);

bool init_share_from_tld_image(THD *thd, TABLE_SHARE*share, const uchar *tld_image, size_t tld_length);

//bool tldgr_parse_option_list(THD* thd, engine_option_value **option_list, ha_create_table_option *rules, engine_option_value **unparsed_option_list,bool suppress_warning, MEM_ROOT *root);
bool tldgr_parse_option_list(THD* thd, engine_option_value **option_list);

bool trusted_table_exists(THD* thd, const LEX_CSTRING *db, const LEX_CSTRING *table_name);

void transform_trigger_for_sign(THD *thd, String *inputText, String *transformedText);

Item *transform_text_for_sign(THD *thd, Item *inval);

bool verify_string(THD *thd, LEX_CSTRING inText, LEX_CSTRING pubKey, LEX_CSTRING signVal);

int check_table_definition_trusted(THD *thd, LEX_CSTRING *db_name, LEX_CSTRING *table_name, LEX_CSTRING child_issuer_key);

void hex2bin(const char* in, size_t len, unsigned char* out);

void tldgr_openlog();

void tldgr_writelog(const char *fmt, ...);


#endif /* SQL_TRUSTSQL_PATCH_H_ */
