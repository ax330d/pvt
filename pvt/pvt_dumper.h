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

#ifndef PVT_DUMPER
#define PVT_DUMPER

void *format_zval(zval *z, zend_bool raw);
void *format_znode(znode *n, zend_uint base_address);
char *func_type(int int_type) 
char *opname(zend_uchar opcode);
static void dump_op(zend_op_array *op_array, zend_op *opi, int num, zend_uint base_address);
void dump_opcode(char *func_name, char *file_name, zend_op_array *op_array TSRMLS_DC);

#endif
