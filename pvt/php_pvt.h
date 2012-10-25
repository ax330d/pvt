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

#ifndef PHP_PVT_H
#define PHP_PVT_H

#include "php.h"
#include "zend_compile.h"
#include "zend_API.h"
#include "zend.h"
#include "php_ini.h"
#include "zend_hash.h"


extern zend_module_entry pvt_module_entry;
#define pvt_module_ptr &pvt_module_entry

#include "php_config.h"

#ifdef ZTS
#include "TSRM.h"
#endif

#include "php_globals.h"
#include "ext/standard/info.h"

#include "zend_alloc.h"

#include "zend_types.h"
#include "zend_operators.h"
#include "zend_globals.h"
#include "zend_execute.h"
#include "zend_extensions.h"

#include "ext/standard/html.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_smart_str.h"

#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <malloc.h>


#if !defined(ZEND_ENGINE_2_1) && (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 1 || PHP_MAJOR_VERSION > 5)
#   define ZEND_ENGINE_2_1
#   include "zend_vm.h"
#endif
#if !defined(ZEND_ENGINE_2_2) && (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 2 || PHP_MAJOR_VERSION > 5)
#   define ZEND_ENGINE_2_2
#endif
#if !defined(ZEND_ENGINE_2_3) && (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3 || PHP_MAJOR_VERSION > 5)
#   define ZEND_ENGINE_2_3
#endif

// flags used in the op array list
#define OP1_USED   1<<0
#define OP2_USED   1<<1
#define RES_USED   1<<2

#define NONE_USED  0
#define ALL_USED   0x7

#define OP1_OPLINE   1<<3
#define OP2_OPLINE   1<<4
#define OP1_OPNUM    1<<5
#define OP2_OPNUM    1<<6
#define OP_FETCH     1<<7
#define EXT_VAL      1<<8
#define NOP2_OPNUM   1<<9
#define OP2_BRK_CONT 1<<10
#define OP1_CLASS    1<<11
#define RES_CLASS    1<<12

#define SPECIAL    0xff

#define PVT_OP_TVAR         2
#define PVT_OP_NUM          3
#define PVT_OP_OPNUM        4
#define PVT_OP_JMPADDR      5

// special op-type flags
#define PVT_IS_OPLINE 1<<13
#define PVT_IS_OPNUM  1<<14
#define PVT_IS_CLASS  1<<15
#define OP2_INCLUDE   1<<16

#if PHP_VERSION_ID >= 50399
#   define PVT_ZNODE znode_op
#   define PVT_ZNODE_ELEM(node,var) node.var
#   define PVT_TYPE(t) t##_type
#   define PVT_EXTENDED_VALUE(o) extended_value
#else
#   define PVT_ZNODE znode
#   define PVT_ZNODE_ELEM(node,var) node.u.var
#   define PVT_TYPE(t) t.op_type
#   define PVT_EXTENDED_VALUE(o) o.u.EA.type
#endif

#define MICRO_IN_SEC 1000000.00
#define PVT_VERSION "0.2"
#define PVT_EXTNAME "pvt"
#define PVT_DBG_TIME 0

PHP_MINIT_FUNCTION(pvt);
PHP_MSHUTDOWN_FUNCTION(pvt);
PHP_RINIT_FUNCTION(pvt);
PHP_RSHUTDOWN_FUNCTION(pvt);
PHP_MINFO_FUNCTION(pvt);
ZEND_MODULE_POST_ZEND_DEACTIVATE_D(pvt);

typedef struct pvt_arg {
    int    c;
    char **args;
} pvt_arg;

#define pvt_arg_init(arg) {    \
    arg->args = NULL;          \
    arg->c    = 0;             \
}

#define pvt_arg_dtor(arg) {        \
    int i;                         \
    for (i = 0; i < arg->c; i++) { \
        free(arg->args[i]);        \
    }                              \
    if (arg->args) {               \
        free(arg->args);           \
    }                              \
    free(arg);                     \
}

/* Tracing functions and drawing graphs */
typedef struct dot_funcs_index {
    int len;
    int *file_id;
    zend_bool *empty;
} dot_funcs_index;

typedef struct dot_funcs_stack {
    int i;
    int len;
    int *func_id;
} dot_funcs_stack;

typedef struct dot_funcs {
    int len;
    int *func_id;
    int *file_id;
    int *line;
    int *type;
    int *stack;
    int *hide;
    int *is_dyn;
    int *is_evil;
    char **file_name;
    char **func_name;
} dot_funcs;

typedef struct eval_db {
    int len;
    int *strlen;
    int *lineno;
    char **filename;
} eval_db;

typedef struct stats_db {
    int max_stack;
    int max_fileid;
    int func_amount;
    int func_calls;
    int file_amount;
} stats_db;

void get_and_dump_args(char *function_name, int lineno, char *filename, zend_function_state *finfo, zval *arg_array TSRMLS_DC);

ZEND_BEGIN_MODULE_GLOBALS(pvt)
    /* Values from php.ini */
    char            *pvt_log_file;
    zend_bool       pvt_log_one_folder;
    char            *pvt_log_write_mode;
    char            *log_folder;

    zend_bool       pvt_graph_fold;
    zend_bool       pvt_count_stat;

    zend_bool       pvt_trace_func;
    zend_bool       pvt_dump_ops;
    
    zend_bool       pvt_dump_vars;
    char            *pvt_dump_vars_list;
    zend_bool       pvt_dump_vars_all;
    zend_bool       pvt_dump_vars_separate;

    zend_bool       pvt_eval_hook;
    char            *pvt_eval_marker;
    zend_bool       pvt_eval_hook_all;
    unsigned int    pvt_eval_hook_len;
    zend_bool       pvt_eval_unique;

    zend_bool       pvt_catch_marker;
    char            *pvt_catch_marker_val;
    char            *pvt_catch_funcs;
    zend_bool       pvt_catch_all;
    unsigned int    pvt_catch_len;

    FILE    *log_file_path;
    FILE    *trace_file_f;
    FILE    *trace_file_f_dot;
    FILE    *trace_file_v;
    FILE    *trace_file_p;
    FILE    *trace_file_e;
    FILE    *trace_file_c;
    FILE    *trace_file_dbg;
    FILE    *timing_dbg;

    HashTable*  function_summary;
    HashTable*  file_summary;
    HashTable*  block_summary;
    
    int     function_index;
    int     file_index;
    int     block_index;
    double  pvt_start_time;

    dot_funcs       *funcs;
    dot_funcs_index *dot_funcs_i;
    dot_funcs_stack *funcs_stack;
    eval_db         *evalued;
    stats_db        *stats;
ZEND_END_MODULE_GLOBALS(pvt)

/* Declare global structure. */

#ifdef ZTS
#define PVT_G(v) TSRMG(pvt_globals_id, zend_pvt_globals *, v)
#else
#define PVT_G(v) (pvt_globals.v)
#endif

#endif /* #ifndef PHP_PVT_H */
