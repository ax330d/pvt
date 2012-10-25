/*
 +----------------------------------------------------------------------+
 |  PVT - PHP Vulnerability Tracer                                      |
 +----------------------------------------------------------------------+
 | Copyright (c) 2011  Arthur Gerkis                                    |
 +----------------------------------------------------------------------+
 | This source file is subject to version 3.01 of the PHP license,      |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.php.net/license/3_01.txt                                  |
 | If you did not receive a copy of the PHP license and are unable to   |
 | obtain it through the world-wide-web, please send a note to          |
 | license@php.net so we can mail you a copy immediately.               |
 +----------------------------------------------------------------------+
 | Author: Arthur Gerkis                                                |
 +----------------------------------------------------------------------+
*/

#ifndef PVT_BACKTRACE
#define PVT_BACKTRACE

#define DF_LEN 6

void trace_functions(void);
void trace_function_entry(HashTable *func_table, const char *fname, int type, const char *filename, int linenum);
void trace_function_exit(char *fname, char *filename, int type, int line);
zval *debug_backtrace_get_args(void ***curpos TSRMLS_DC);
void pvt_trace_variables(void);

#endif
