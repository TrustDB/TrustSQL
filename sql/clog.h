/*
 * clog.h
 * Console log out
 * Created on: 2018. 3. 26.
 */

#include <stdio.h>
//#include "trustsql_patch.h"
#ifndef SRC_CLOG_H_
#define SRC_CLOG_H_

// Console Debug On/Off
#ifdef TRUSTSQL_DEBUG
#define CLOG_ON 0
#else
#define CLOG_ON 1
#endif

#if CLOG_ON==1
extern void tldgr_openlog();
extern void tldgr_writelog(const char *fmt, ...);

#define CLOG_OPEN()				tldgr_openlog();
#define CLOG_FUNCTION()         printf("[%24s] (L%04d) CALL      ============== File Name = %s\n",__func__,__LINE__,__FILE__);
#define CLOG_FUNCTIOND(d)       printf("[%24s] (L%04d) CALL -----> %s  [%s]\n",__func__,__LINE__,d,__FILE__);
#define CLOG_FUNCTIONDI(d)      printf("[%24s] (L%04d) CALL INNO-> %s  [%s]\n",__func__,__LINE__,d,__FILE__);


#define CLOG_STEP(a,b)          printf("[%24s] (L%04d) STEP%6s  %s\n",__func__,__LINE__,a,b);
#define CLOG_TPRINTLN(...)      printf("[%24s] (L%04d)             -. ",__func__,__LINE__); printf(__VA_ARGS__); printf("\n");
#define CLOG_PRINT(...)         printf("[%24s] (L%04d)             ",__func__,__LINE__); printf(__VA_ARGS__);
#define CLOG_PRINTLN(...)       printf("[%24s] (L%04d)             ",__func__,__LINE__); printf(__VA_ARGS__); printf("\n");

#define CLOG_DISPBUFFER(a,b) 	{													\
									   printf("\t [HEXDMMP]    %d Bytes\n",b);		\
									   printf("\t 0x00000000 : ");					\
									   for(int i=0; i<b; i++) {						\
											printf("%02X", (unsigned char)a[i]);	\
											if(((i+1)%0x10) == 0) {					\
												printf("\t\t");						\
												for(int j=0; j<0x10; j++) {			\
													printf("%c", (unsigned char)a[i-0x10+j]);		\
												}										\
												printf("\n");							\
												printf("\t 0x%08X : ",i+1);			\
											}											\
										}												\
										printf("\n");									\
									}

#define CLOG_DISPSTR(a) 	{													\
									   printf("\t [HEXDMMP] \n");		\
									   printf("\t 0x00000000 : ");					\
									   int i=0;   \
                                       while(true) {						\
									   	    if(a[i]==0) break;    \
											printf("%02X", (unsigned char)a[i]);	\
											if(((i+1)%0x10) == 0) {					\
												printf("\t\t");						\
												for(int j=0; j<0x10; j++) {			\
													printf("%c", (unsigned char)a[i-0x10+j]);		\
												}										\
												printf("\n");							\
												printf("\t 0x%08X : ",i+1);			\
											}    \
											i++;   \
										}												\
										printf("\n");									\
									}
#else
#define CLOG_FUNCTION()
#define CLOG_FUNCTIOND(d)
#define CLOG_FUNCTIONDI(d)


#define CLOG_STEP(a,b)
#define CLOG_TPRINTLN(...)
#define CLOG_PRINT(...)
#define CLOG_PRINTLN(...)

#define CLOG_DISPBUFFER(a,b)
#define CLOG_DISPSTR(a)
#endif

#endif /* SRC_CLOG_H_ */
