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

#include "php_pvt.h"
#include "pvt_helpers.h"
#include "pvt_logotype.h"

typedef struct _zfunc_type {
    int type;
    char *name;
} zend_functypes;

static const zend_functypes zfunc_type[] = {
    { 1, "ZEND_INTERNAL_FUNCTION" },
    { 2, "ZEND_USER_FUNCTION" },
    { 3, "ZEND_OVERLOADED_FUNCTION" },
    { 4, "ZEND_EVAL_CODE" },
    { 5, "ZEND_OVERLOADED_FUNCTION_TEMPORARY"},
};

static void pvt_execute(zend_op_array *op_array TSRMLS_DC);
static void pvt_execute_internal(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC);
static void (*old_zend_execute_internal)(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC);
static void (*old_execute)(zend_op_array *op_array TSRMLS_DC);

static zend_op_array *(*orig_compile_string)(zval *source_string, char *filename TSRMLS_DC);
static void statement_handler(zend_op_array *op_array);

static void init_dot(void);
static void free_dot(void);

static zend_bool evalhook_hooked = 0;

/* {{{ pvt_module_entry
*/
zend_module_entry pvt_module_entry = {
    STANDARD_MODULE_HEADER,
    PVT_EXTNAME,
    NULL,               /* functions */
    PHP_MINIT(pvt),
    PHP_MSHUTDOWN(pvt),
    PHP_RINIT(pvt),
    PHP_RSHUTDOWN(pvt),
    PHP_MINFO(pvt),
    PVT_VERSION,
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 2) || PHP_MAJOR_VERSION >= 6
    NO_MODULE_GLOBALS,
#endif
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
};
/* }}} */

ZEND_DLEXPORT zend_extension zend_extension_entry;
ZEND_DECLARE_MODULE_GLOBALS(pvt);

/* Initialize module */
#if COMPILE_DL_PVT
ZEND_GET_MODULE(pvt)
#endif

PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("pvt.log_file",               "",  PHP_INI_SYSTEM, OnUpdateString, pvt_log_file, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_BOOLEAN("pvt.log_one_folder",       "0", PHP_INI_SYSTEM, OnUpdateBool, pvt_log_one_folder, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_ENTRY("pvt.log_write_mode",         "",  PHP_INI_SYSTEM, OnUpdateString, pvt_log_write_mode, zend_pvt_globals, pvt_globals)

    STD_PHP_INI_BOOLEAN("pvt.graph_fold",           "0", PHP_INI_ALL, OnUpdateBool, pvt_graph_fold, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_BOOLEAN("pvt.count_stat",           "0", PHP_INI_ALL, OnUpdateBool, pvt_count_stat, zend_pvt_globals, pvt_globals)

    STD_PHP_INI_BOOLEAN("pvt.dump_ops",             "0", PHP_INI_ALL, OnUpdateBool, pvt_dump_ops, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_BOOLEAN("pvt.trace_func",           "0", PHP_INI_ALL, OnUpdateBool, pvt_trace_func, zend_pvt_globals, pvt_globals)

    STD_PHP_INI_BOOLEAN("pvt.dump_vars",            "0", PHP_INI_ALL, OnUpdateBool, pvt_dump_vars, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_ENTRY("pvt.dump_vars_list",         "",  PHP_INI_ALL, OnUpdateString, pvt_dump_vars_list, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_BOOLEAN("pvt.dump_vars_all",        "0", PHP_INI_ALL, OnUpdateBool, pvt_dump_vars_all, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_BOOLEAN("pvt.dump_vars_separate",   "0", PHP_INI_ALL, OnUpdateBool, pvt_dump_vars_separate, zend_pvt_globals, pvt_globals)

    STD_PHP_INI_BOOLEAN("pvt.eval_hook",        "0", PHP_INI_ALL, OnUpdateBool, pvt_eval_hook, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_ENTRY("pvt.eval_marker",        "",  PHP_INI_ALL, OnUpdateString, pvt_eval_marker, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_BOOLEAN("pvt.eval_hook_all",    "0", PHP_INI_ALL, OnUpdateBool, pvt_eval_hook_all, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_ENTRY("pvt.eval_hook_len",      "0", PHP_INI_ALL, OnUpdateLong, pvt_eval_hook_len, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_BOOLEAN("pvt.eval_unique",      "0", PHP_INI_ALL, OnUpdateBool, pvt_eval_unique, zend_pvt_globals, pvt_globals)

    STD_PHP_INI_BOOLEAN("pvt.catch_marker",     "0", PHP_INI_ALL, OnUpdateBool, pvt_catch_marker, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_ENTRY("pvt.catch_marker_val",   "",  PHP_INI_ALL, OnUpdateString, pvt_catch_marker_val, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_ENTRY("pvt.catch_funcs",        "",  PHP_INI_ALL, OnUpdateString, pvt_catch_funcs, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_BOOLEAN("pvt.catch_all",        "0", PHP_INI_ALL, OnUpdateBool, pvt_catch_all, zend_pvt_globals, pvt_globals)
    STD_PHP_INI_ENTRY("pvt.catch_len",          "0", PHP_INI_ALL, OnUpdateLong, pvt_catch_len, zend_pvt_globals, pvt_globals)

PHP_INI_END()

static char *zfunc_typename(int type)
{
    return zfunc_type[type].name;
}

/* {{{ php_pvt_init_globals
 */
static void php_pvt_init_globals(zend_pvt_globals *pvt_globals TSRMLS_DC)
{
    memset(pvt_globals, 0, sizeof(zend_pvt_globals));

    pvt_globals->pvt_log_file           = "/tmp";
    pvt_globals->pvt_log_one_folder     = 0;
    pvt_globals->pvt_log_write_mode     = "c";

    pvt_globals->pvt_graph_fold         = 0;
    pvt_globals->pvt_count_stat         = 0;

    pvt_globals->pvt_dump_ops           = 0;
    pvt_globals->pvt_trace_func         = 0;

    pvt_globals->pvt_dump_vars          = 0;
    pvt_globals->pvt_dump_vars_list     = NULL;
    pvt_globals->pvt_dump_vars_all      = 0;
    pvt_globals->pvt_dump_vars_separate = 0;

    pvt_globals->pvt_eval_hook          = 0;
    pvt_globals->pvt_eval_marker        = NULL;
    pvt_globals->pvt_eval_hook_all      = 0;
    pvt_globals->pvt_eval_hook_len      = 0;
    pvt_globals->pvt_eval_unique        = 0;

    pvt_globals->pvt_catch_marker       = 0;
    pvt_globals->pvt_catch_marker_val   = NULL;
    pvt_globals->pvt_catch_funcs        = NULL;
    pvt_globals->pvt_catch_all          = 0;
    pvt_globals->pvt_catch_len          = 0;

    pvt_globals->function_summary = (HashTable *) malloc(sizeof(HashTable));
    pvt_globals->file_summary     = (HashTable *) malloc(sizeof(HashTable));
    pvt_globals->block_summary    = (HashTable *) malloc(sizeof(HashTable));

    zend_hash_init(pvt_globals->function_summary,   0, NULL, NULL, 1);
    zend_hash_init(pvt_globals->file_summary,       0, NULL, NULL, 1);
    zend_hash_init(pvt_globals->block_summary,      0, NULL, NULL, 1);
}
/* }}} */

/* {{{ php_pvt_free_globals
 */
static void php_pvt_free_globals(zend_pvt_globals *pvt_globals TSRMLS_DC)
{
    free(pvt_globals->function_summary);
    free(pvt_globals->file_summary);
    free(pvt_globals->block_summary);
}
/* }}} */


static void pvt_config(char *config)
{
    int i;
    pvt_arg *parts;

    /* _PVT format: _PVT=var=val|var=val */

    if (!config) {
        return;
    }

    parts = (pvt_arg*) malloc(sizeof(pvt_arg));
    pvt_arg_init(parts);
    pvt_explode("|", config, parts, -1);

    for (i = 0; i < parts->c; ++i) {

        char *name   = NULL;
        char *envvar = parts->args[i];
        char *envval = NULL;
        char *eq     = strchr(envvar, '=');

        if (!eq || !*eq) {
            continue;
        }
        *eq = 0;
        envval = eq + 1;
        if (!*envval) {
            continue;
        }

        /* Graph settings */
        if (strcasecmp(envvar, "graph_fold") == 0) {
            name = "pvt.graph_fold";
        } else
        if (strcasecmp(envvar, "count_stat") == 0) {
            name = "pvt.count_stat";
        } else

        /* Switch module 1 */
        if (strcasecmp(envvar, "trace_func") == 0) {
            name = "pvt.trace_func";
        } else

        /* Switch module 2 */
        if (strcasecmp(envvar, "dump_ops") == 0) {
            name = "pvt.dump_ops";
        } else

        /* Switch module 3 */
        if (strcasecmp(envvar, "dump_vars") == 0) {
            name = "pvt.dump_vars";
        } else
        if (strcasecmp(envvar, "dump_vars_list") == 0) {
            name = "pvt.dump_vars_list";
        } else
        if (strcasecmp(envvar, "dump_vars_all") == 0) {
            name = "pvt.dump_vars_all";
        } else
        if (strcasecmp(envvar, "dump_vars_separate") == 0) {
            name = "pvt.dump_vars_separate";
        } else

        /* Switch module 4  */
        if (strcasecmp(envvar, "eval_hook") == 0) {
            name = "pvt.eval_hook";
        } else
        if (strcasecmp(envvar, "eval_marker") == 0) {
            name = "pvt.eval_marker";
        } else
        if (strcasecmp(envvar, "eval_hook_all") == 0) {
            name = "pvt.eval_hook_all";
        } else
        if (strcasecmp(envvar, "eval_hook_len") == 0) {
            name = "pvt.eval_hook_len";
        } else

        /* Switch module 5 */
        if (strcasecmp(envvar, "catch_marker") == 0) {
            name = "pvt.catch_marker";
        } else
        if (strcasecmp(envvar, "catch_marker_val") == 0) {
            name = "pvt.catch_marker_val";
        } else
        if (strcasecmp(envvar, "catch_funcs") == 0) {
            name = "pvt.catch_funcs";
        } else
        if (strcasecmp(envvar, "catch_all") == 0) {
            name = "pvt.catch_all";
        } else
        if (strcasecmp(envvar, "catch_len") == 0) {
            name = "pvt.catch_len";
        }

        if (name) {
            zend_alter_ini_entry(name, strlen(name) + 1, envval, strlen(envval), PHP_INI_SYSTEM, PHP_INI_STAGE_ACTIVATE);
        }
    }

    pvt_arg_dtor(parts);
}

static zend_op_array *evalhook_compile_string(zval *source_string, char *filename TSRMLS_DC)
{
    int c, len;
    int flag_printed = 0;
    char *copy = NULL, *found = NULL;
    zend_bool flag_skip = 0;

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Prologue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    /* Ignore non string eval() */
    if (Z_TYPE_P(source_string) != IS_STRING) {
        return orig_compile_string(source_string, filename TSRMLS_CC);
    }

    len = Z_STRLEN_P(source_string);
    copy = estrndup(Z_STRVAL_P(source_string), len);
    if (len > strlen(copy)) {
        for (c=0; c<len; c++) if (copy[c] == 0) copy[c] = '?';
    }

    unsigned int marker_len  = strlen(PVT_G(pvt_eval_marker));
    unsigned int buff_len    = strlen(copy);
    unsigned int found_pos   = 0;

    /* Search for marker value */
    if ((strlen(PVT_G(pvt_eval_marker)) > 0) && (! PVT_G(pvt_eval_hook_all))) {

        char *endp;
        endp = copy + buff_len;
        found = pvt_memnstr(copy, PVT_G(pvt_eval_marker), marker_len, endp);

        if ((found != NULL)) {
            found_pos = buff_len - strlen(found);
            flag_printed = 1;
        }
    } else if (PVT_G(pvt_eval_hook_all)) {
        flag_printed = 1;
    }

    /* Search for entry in database
     * At the moment it relies on string length, found position and filename.
     */
    int x;
    if (PVT_G(pvt_eval_unique)) {
        for (x = 0; x < PVT_G(evalued)->len; x++) {
            if (PVT_G(evalued)->strlen[x] == buff_len
                && PVT_G(evalued)->lineno[x] == found_pos
                && (strcasecmp(PVT_G(evalued)->filename[x], filename) == 0))
            {
                flag_skip = 1;
            }
        }
    }

    /* If marker was found and unique string evaluated */
    if (flag_printed && !flag_skip) {

        /* If we have to cut string, do that */
        if ((buff_len > PVT_G(pvt_eval_hook_len) + marker_len) && PVT_G(pvt_eval_hook_len) > 0) {

            char *buff_cut = NULL;
            int cut_start = found_pos - PVT_G(pvt_eval_hook_len);
            if (cut_start < 0) {
                cut_start = 0;
            }

            buff_cut = pvt_substr(cut_start, PVT_G(pvt_eval_hook_len) + marker_len + found_pos, copy);
            fprintf(PVT_G(trace_file_e), "\n/**\n * %s (%d bytes)\n * Showing only %lu bytes\n */\n%s\n", filename, buff_len, strlen(buff_cut), buff_cut);

            if (buff_cut) {
                efree(buff_cut);
            }

        } else {
            fprintf(PVT_G(trace_file_e), "\n/**\n * %s (%d bytes)\n */\n%s\n", filename, buff_len, copy);
        }

        if (PVT_G(pvt_eval_unique)) {
            /* Add to database */
            PVT_G(evalued)->strlen = realloc(PVT_G(evalued)->strlen, (PVT_G(evalued)->len+1) * sizeof(int));
            PVT_G(evalued)->strlen[PVT_G(evalued)->len] = buff_len;

            PVT_G(evalued)->lineno = realloc(PVT_G(evalued)->lineno, (PVT_G(evalued)->len+1) * sizeof(int));
            PVT_G(evalued)->lineno[PVT_G(evalued)->len] = found_pos;

            PVT_G(evalued)->filename = realloc(PVT_G(evalued)->filename, sizeof(unsigned char*) * (PVT_G(evalued)->len+1));
            PVT_G(evalued)->filename[PVT_G(evalued)->len] = emalloc(strlen(filename) + 1);
            memcpy(PVT_G(evalued)->filename[PVT_G(evalued)->len], filename, strlen(filename) + 1);
            PVT_G(evalued)->filename[PVT_G(evalued)->len][strlen(filename)] = '\0';

            PVT_G(evalued)->len += 1;
        }
    }

    if (copy) {
        efree(copy);
    }

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Epilogue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    return orig_compile_string(source_string, filename TSRMLS_CC);
}

void get_and_dump_args(char *function_name, int lineno, char *filename, zend_function_state *finfo, zval *arg_array TSRMLS_DC)
{

    int key_type;
    int flag_cought, flag_printed, z;
    unsigned long index;
    unsigned int key_len;
    char *key = NULL;
    char *buffer;
    char *delimiter = NULL;

    zval tmp;
    zval **data = NULL;
    HashPosition iterator;
    HashTable *at = NULL;

    int function_type = finfo->function->common.type;
    int func_num_args = finfo->function->common.num_args;
    delimiter = str_repeat("-", 80);

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Prologue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    flag_cought  = 0;
    flag_printed = 0;

    /* Parse functions list if we need to watch after some of them  */
    if (strlen(PVT_G(pvt_catch_funcs)) > 0 && (!PVT_G(pvt_catch_all))) {

        pvt_arg *parts = (pvt_arg*) malloc(sizeof(pvt_arg));
        pvt_arg_init(parts);
        pvt_explode(",", PVT_G(pvt_catch_funcs), parts, -1);

        for (z = 0; z < parts->c; ++z) {
            /* If no match, go to next variable */
            if (strcasecmp(parts->args[z], function_name) == 0) {
                flag_cought = 1;
                break;
            }
        }
        pvt_arg_dtor(parts);
    }

    /* If functions list was set and nothing found, exit */
    if (strlen(PVT_G(pvt_catch_funcs)) > 0 && (flag_cought == 0) && (!PVT_G(pvt_catch_all))) {
        return;
    }

    zend_hash_internal_pointer_reset_ex(arg_array->value.ht, &iterator);

    /* Iterate through the arguments of function */
    while (zend_hash_get_current_data_ex(arg_array->value.ht, (void **) &tmp, &iterator) == SUCCESS) {

        flag_printed = 0;
        key_type = zend_hash_get_current_key_ex(arg_array->value.ht, &key, &key_len, &index, 0, &iterator);

        zend_hash_get_current_data_ex(arg_array->value.ht, (void**) &data, &iterator);

        tmp = **data;
        zval_copy_ctor(&tmp);
        INIT_PZVAL(&tmp);

        /* Currently only strings support */
        if (Z_TYPE(tmp) != IS_STRING) {
            zend_hash_move_forward_ex(arg_array->value.ht, &iterator);
            zval_dtor(&tmp);
            continue;
        }

        convert_to_string(&tmp);
        buffer = estrndup(Z_STRVAL(tmp), Z_STRLEN(tmp));
        zval_dtor(&tmp);

        unsigned int found_pos   = 0;
        unsigned int buff_len    = strlen(buffer);
        unsigned int marker_len  = strlen(PVT_G(pvt_catch_marker_val));
        char *found = NULL;

        /* Search for marker value */
        if (strlen(PVT_G(pvt_catch_marker_val)) > 0) {

            char *endp;
            endp = buffer + buff_len;
            found = pvt_memnstr(buffer, PVT_G(pvt_catch_marker_val), marker_len, endp);

            if ((found != NULL)) {
                found_pos = buff_len - strlen(found);
                flag_printed = 1;
            }

        } else {
            flag_printed = 1;
        }

        /* If marker was found */
        if (flag_printed) {

            fprintf(PVT_G(trace_file_c),
                "%f # %s() %s:%d %s max args:%d, %d bytes, starting at %d\n",
                pvt_get_utime(), function_name, filename, lineno, zfunc_typename(function_type), func_num_args, buff_len, found_pos
            );

            if (key_type == HASH_KEY_IS_STRING) {
                fprintf(PVT_G(trace_file_c), " $%s = ", key);
            } else if (key_type == HASH_KEY_IS_LONG) {
                /* For language constructions, not functions */
                if (index < finfo->function->common.num_args) {
                    fprintf(PVT_G(trace_file_c), " %lu $%s = ", index + 1, finfo->function->common.arg_info[index].name);
                }  else {
                    fprintf(PVT_G(trace_file_c), " %lu = ", index + 1);
                }
            }

            /* If we have to cut string, do that */
            if ((buff_len > PVT_G(pvt_catch_len) + marker_len) && PVT_G(pvt_catch_len) > 0) {
                char *buff_cut = NULL;

                if (found_pos > PVT_G(pvt_catch_len)) {
                    int cut_start = found_pos - PVT_G(pvt_catch_len);
                    if (cut_start < 0) {
                        cut_start = 0;
                    }
                    buff_cut = pvt_substr(cut_start, PVT_G(pvt_catch_len) + marker_len + found_pos, buffer);
                } else {
                    buff_cut = pvt_substr(0, PVT_G(pvt_catch_len) + marker_len, buffer);
                }
                fprintf(PVT_G(trace_file_c), "(PVT-CUT) %s\n", buff_cut);
                if (buff_cut) {
                    efree(buff_cut);
                }
            } else {
                fprintf(PVT_G(trace_file_c), "%s\n", buffer);
            }
        }

        if (buffer) {
            efree(buffer);
        }

        zend_hash_move_forward_ex(arg_array->value.ht, &iterator);
    }

    if (flag_printed) {
        fprintf(PVT_G(trace_file_c), "%s\n", delimiter);
    }

    efree(delimiter);

    if (key) {
        efree(key);
    }

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Epilogue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

}

char *pvt_get_active_function_name(zend_op_array *op_array TSRMLS_DC)
{
    int   class_name_len;
    int   tmp_fname_len;
    char *tmp_fname;
    char *class_name;
    char *func_name = NULL;

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Prologue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    zend_execute_data *executed = EG(current_execute_data);

    if (!executed) {
        func_name = estrdup("main");
        return func_name;
    }

    tmp_fname = executed->function_state.function->common.function_name;

    if (tmp_fname) {

        tmp_fname_len = strlen(tmp_fname);

        if (executed->object) {

            class_name = Z_OBJCE(*executed->object)->name;
            class_name_len = strlen(class_name);

            func_name = (char *) emalloc(class_name_len + tmp_fname_len + 3);
            snprintf(func_name, class_name_len + tmp_fname_len + 3, "%s->%s", class_name, tmp_fname);

        } else if (executed->function_state.function->common.scope) {

            class_name = executed->function_state.function->common.scope->name;
            class_name_len = strlen(class_name);

            func_name = (char *) emalloc(class_name_len + tmp_fname_len + 3);
            snprintf(func_name, class_name_len + tmp_fname_len + 3, "%s::%s", class_name, tmp_fname);

        } else {
            func_name = estrdup(tmp_fname);
        }

    } else {

#if ZEND_MODULE_API_NO >= 20100409 /* ZE2.4 */
        switch (executed->opline->op2.constant) {
#else
        switch (Z_LVAL(executed->opline->op2.u.constant)) {
#endif
            case ZEND_EVAL:
                func_name = estrdup("eval");
                break;
            case ZEND_INCLUDE:
                func_name = estrdup("include");
                break;
            case ZEND_REQUIRE:
                func_name = estrdup("require");
                break;
            case ZEND_INCLUDE_ONCE:
                func_name = estrdup("include_once");
                break;
            case ZEND_REQUIRE_ONCE:
                func_name = estrdup("require_once");
                break;
            default:
                func_name = estrdup("UNKNOWN");
                break;
        }
    }

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Epilogue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    return func_name;
}

/*
 * TODO: Avoid a memory leak when script gets interrupted during the runtime.
 */

static void pvt_execute(zend_op_array *op_array TSRMLS_DC)
{
    char *file_name = zend_get_executed_filename(TSRMLS_C);
    char *func_name = pvt_get_active_function_name(op_array TSRMLS_CC);

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Prologue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    if (PVT_G(pvt_trace_func)) {
        trace_function_entry(EG(function_table), func_name, ZEND_USER_FUNCTION, file_name, zend_get_executed_lineno(TSRMLS_C));
    }

    if (PVT_G(pvt_catch_marker)) {
        pvt_trace_variables();
    }

    if (PVT_G(pvt_dump_ops)) {
        dump_opcode(func_name, file_name, op_array);
    }

    old_execute(op_array TSRMLS_CC);

    if (PVT_G(pvt_trace_func)) {
        trace_function_exit(func_name, file_name, ZEND_USER_FUNCTION, zend_get_executed_lineno(TSRMLS_C));
    }

    if (func_name) {
        efree(func_name);
    }

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Epilogue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

}

static void pvt_execute_internal(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC)
{
    zend_execute_data *executed = EG(current_execute_data);
    char *func_name = pvt_get_active_function_name(executed->op_array TSRMLS_CC);
    char *file_name = zend_get_executed_filename(TSRMLS_C);

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Prologue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    if (PVT_G(pvt_trace_func)) {
        trace_function_entry(EG(function_table), func_name, ZEND_INTERNAL_FUNCTION, file_name, zend_get_executed_lineno(TSRMLS_C));
    }

    if (PVT_G(pvt_catch_marker)) {
        pvt_trace_variables();
    }

    if (PVT_G(pvt_dump_ops)) {
        dump_opcode(func_name, file_name, executed->op_array);
    }

    execute_internal(execute_data_ptr, return_value_used TSRMLS_CC);

    if (PVT_G(pvt_trace_func)) {
        trace_function_exit(func_name, zend_get_executed_filename(TSRMLS_C), ZEND_INTERNAL_FUNCTION, zend_get_executed_lineno(TSRMLS_C));
    }

    if (func_name) {
        efree(func_name);
    }


#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Epilogue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

}

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(pvt)
{
    php_info_print_box_start(0);

    PUTS("<a href=\"http://www.onsec.ru/\"><img style=\"float:right;border:none;\" src=\"data:image/jpeg;base64,");
    PUTS(logo_b64);
    PUTS("\" alt=\"ONsec\" /></a>");
    PUTS("Scripts running with this PHP interpeter are under the watch of PVT.<br/>");
    PUTS("PVT - PHP Vulnerability Tracer v.");
    PUTS(PVT_VERSION);
    PUTS("<br/>Copyright (c) 2011-2012 ONsec.");

    php_info_print_box_end();

    DISPLAY_INI_ENTRIES();
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(pvt)
{
    ZEND_INIT_MODULE_GLOBALS(pvt, php_pvt_init_globals, php_pvt_free_globals);
    REGISTER_INI_ENTRIES();

    PVT_G(pvt_start_time) = pvt_get_utime();

#if PVT_DBG_TIME >= 1
    char *filename_dbg = NULL;
    spprintf(&filename_dbg, 0, "%s/dump/timing-DBG.txt", PVT_G(pvt_log_file));

    PVT_G(timing_dbg) = fopen(filename_dbg, "a");
    efree(filename_dbg);

    fprintf(PVT_G(timing_dbg), "\n--- NEW ---\n");
    fprintf(PVT_G(timing_dbg), "%s:\t%f\n", __func__, pvt_get_utime());
#endif

    if (PVT_G(pvt_eval_hook) && evalhook_hooked == 0) {
        evalhook_hooked = 1;
        orig_compile_string = zend_compile_string;
        zend_compile_string = evalhook_compile_string;
    }

    old_execute = zend_execute;
    zend_execute = pvt_execute;

    old_zend_execute_internal = zend_execute_internal;
    zend_execute_internal = pvt_execute_internal;

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(pvt)
{
#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s:\t%f\n", __func__, pvt_get_utime());
    fprintf(PVT_G(timing_dbg), "Total run:\t%f\n", pvt_get_utime() - PVT_G(pvt_start_time));
    fprintf(PVT_G(timing_dbg),
        "Modules:\n\ttrace = %d\n"
        "\tdump_ops = %d\n"
        "\tdump_vars = %d\n"
        "\teval_hook = %d\n"
        "\tcatch = %d\n",
        PVT_G(pvt_trace_func),
        PVT_G(pvt_dump_ops),
        PVT_G(pvt_dump_vars),
        PVT_G(pvt_eval_hook),
        PVT_G(pvt_catch_marker)
    );

    fclose(PVT_G(timing_dbg));
#endif

    if (PVT_G(pvt_eval_hook) && evalhook_hooked == 1) {
        evalhook_hooked = 0;
        zend_compile_string = orig_compile_string;
    }

    zend_execute = old_execute;
    zend_execute_internal = old_zend_execute_internal;

    zend_hash_destroy(PVT_G(function_summary));
    zend_hash_destroy(PVT_G(file_summary));
    zend_hash_destroy(PVT_G(block_summary));

#ifdef ZTS
    ts_free_id(pvt_globals_id);
#else
    php_pvt_free_globals(&pvt_globals TSRMLS_CC);
#endif

    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(pvt)
{
    int ret_stat, wm;
    char *fn_tracer;
    char *fn_dump_vars;
    char *fn_eval;
    char *fn_catch;
    char *time;
    char *space;
    char *write_mode;
    struct stat buf;
    zval **dummy;

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "\n--- REQUEST START ---\n");
    fprintf(PVT_G(timing_dbg), "%s Prologue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    time = pvt_get_time();
    space = str_repeat("-", 80);

    PVT_G(file_index)       = 1;
    PVT_G(block_index)      = 1;
    PVT_G(function_index)   = 1;
    PVT_G(log_folder)       = NULL;

    if ((strcasecmp(PVT_G(pvt_log_write_mode), "w")) == 0) {
        spprintf(&write_mode, 2, "w");
        wm = 'w';
    } else if ((strcasecmp(PVT_G(pvt_log_write_mode), "a")) == 0) {
        spprintf(&write_mode, 2, "a");
        wm = 'a';
    } else {
        zend_error(E_ERROR, "PVT: wrong write mode for logs!");
    }


    /* Redefine php.ini settings */
    zend_is_auto_global("_GET", sizeof("_GET")-1 TSRMLS_CC);

    if (PG(http_globals)[TRACK_VARS_GET] && zend_hash_find(PG(http_globals)[TRACK_VARS_GET]->value.ht, "_PVT", sizeof("_PVT"), (void **) &dummy) == SUCCESS) {
        pvt_config(Z_STRVAL_PP(dummy));
        zend_hash_del(PG(http_globals)[TRACK_VARS_GET]->value.ht, "_PVT", sizeof("_PVT"));
    }

    zend_is_auto_global("_POST", sizeof("_POST")-1 TSRMLS_CC);

    if (PG(http_globals)[TRACK_VARS_POST] && zend_hash_find(PG(http_globals)[TRACK_VARS_POST]->value.ht, "_PVT", sizeof("_PVT"), (void **) &dummy) == SUCCESS) {
        pvt_config(Z_STRVAL_PP(dummy));
        zend_hash_del(PG(http_globals)[TRACK_VARS_POST]->value.ht, "_PVT", sizeof("_PVT"));
    }


    if (PVT_G(pvt_log_one_folder)) {
        spprintf(&PVT_G(log_folder), 0, "%s/dump/pvt-common-%s", PVT_G(pvt_log_file), write_mode);
    } else {
        spprintf(&PVT_G(log_folder), 0, "%s/dump/pvt-%s", PVT_G(pvt_log_file), time);
    }


    ret_stat = stat(PVT_G(log_folder), &buf);

    if ((php_mkdir(PVT_G(log_folder), 0777) == -1) && (ret_stat == -1)) {
        zend_error(E_ERROR, "PVT: unable to create folder '%s'.", PVT_G(log_folder));
    }

    /* Module 1 - function tracer */
    if (PVT_G(pvt_trace_func)) {

        spprintf(&fn_tracer, 0, "%s/trace-functions.txt", PVT_G(log_folder));

        if (!(PVT_G(trace_file_f) = fopen(fn_tracer, write_mode))) {
            zend_error(E_ERROR, "PVT: unable to open provided path for dump (trace-f)");
        }

        fprintf(PVT_G(trace_file_f), "Function trace [%s]\n%s\n", time, space);
        fprintf(PVT_G(trace_file_f), "Line | Index | File, function, type\n");
        chmod(fn_tracer, 0777);
        efree(fn_tracer);

        PVT_G(dot_funcs_i)  = malloc(sizeof(dot_funcs_index));
        PVT_G(funcs)        = malloc(sizeof(dot_funcs));
        PVT_G(funcs_stack)  = malloc(sizeof(dot_funcs_stack));

        memset(PVT_G(dot_funcs_i),    0, sizeof(dot_funcs_index));
        memset(PVT_G(funcs),          0, sizeof(dot_funcs));
        memset(PVT_G(funcs_stack),    0, sizeof(dot_funcs_stack));
    }

    /* Module 2 - opcode dumper */
    if (PVT_G(pvt_dump_ops)) {

        char *folder_o = NULL;
        spprintf(&folder_o, 0, "%s/opcodes", PVT_G(log_folder));
        ret_stat = stat(folder_o, &buf);

        if ((php_mkdir(folder_o, 0777) == -1) && (ret_stat == -1)) {
            zend_error(E_ERROR, "PVT: unable to create folder '%s'", folder_o);
        }
        efree(folder_o);
    }

    /* Module 3 - variables dumper */
    if (PVT_G(pvt_dump_vars)) {
        spprintf(&fn_dump_vars, 0, "%s/dump-variables.txt", PVT_G(log_folder));

        if (!(PVT_G(trace_file_v) = fopen(fn_dump_vars, write_mode))) {
            zend_error(E_ERROR, "PVT: unable to open provided path for dump (trace-v)");
        }
        if (wm != 'a') {
            fprintf(PVT_G(trace_file_v), "Variable dump [%s]\n%s\n", time, space);
        }
        chmod(fn_dump_vars, 0777);
        efree(fn_dump_vars);
    }

    /* Module 4 - eval hooker */
    if (PVT_G(pvt_eval_hook)) {
        spprintf(&fn_eval, 0, "%s/dump-evaluated.phps", PVT_G(log_folder));

        if (!(PVT_G(trace_file_e) = fopen(fn_eval, write_mode))) {
            zend_error(E_ERROR, "PVT: unable to open provided path for dump (evalhook)");
        }
        if (wm != 'a') {
            fprintf(PVT_G(trace_file_e), "<?php\n/* evalhook+ logfile [%s] */\n", time);
        }
        chmod(fn_eval, 0777);
        efree(fn_eval);

        if (PVT_G(pvt_eval_unique)) {
            PVT_G(evalued) = emalloc(sizeof(eval_db));
            memset(PVT_G(evalued), 0, sizeof(eval_db));
        }
    }

    /* Module 5 - marker catch */
    if (PVT_G(pvt_catch_marker)) {
        spprintf(&fn_catch, 0, "%s/catched-marker.txt", PVT_G(log_folder));

        if (!(PVT_G(trace_file_c) = fopen(fn_catch, write_mode))) {
            zend_error(E_ERROR, "PVT: unable to open provided path for dump (%s)", fn_catch);
        }
        if (wm != 'a') {
            fprintf(PVT_G(trace_file_c), " Catched marker \"%s\" [%s]\n%s\n", PVT_G(pvt_catch_marker_val), time, space);
        }
        chmod(fn_catch, 0777);
        efree(fn_catch);
    }

    /* Runtime statistics */
    if (PVT_G(pvt_count_stat)) {
        PVT_G(stats) = emalloc(sizeof(stats_db));
        memset(PVT_G(stats), 0, sizeof(stats_db));
    }

    efree(write_mode);
    efree(time);
    efree(space);

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Epilogue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    return SUCCESS;
}
/* }}} */

PHP_RSHUTDOWN_FUNCTION(pvt)
{
#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Prologue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
    fprintf(PVT_G(timing_dbg), "\n--- REQUEST END ---\n");
#endif

    /* Evalhook database */

    if (PVT_G(pvt_eval_hook) && PVT_G(pvt_eval_unique)) {
        int i;
        for (i = 0; i < PVT_G(evalued)->len; ++i) {
            efree(PVT_G(evalued)->filename[i]);
        }
        if (PVT_G(evalued)->filename) {
            efree(PVT_G(evalued)->filename);
        }
        if (PVT_G(evalued)->strlen) {
            efree(PVT_G(evalued)->strlen);
        }
        if (PVT_G(evalued)->lineno) {
            efree(PVT_G(evalued)->lineno);
        }
        efree(PVT_G(evalued));
    }

    /* PVT Statistics  */

    if (PVT_G(pvt_count_stat)) {

        char *file_stats = NULL;
        char *write_mode = NULL;
        char *delimiter  = NULL;
        FILE *fs_handle;

        delimiter = str_repeat("-", 80);

        if ((strcasecmp(PVT_G(pvt_log_write_mode), "w")) == 0) {
            spprintf(&write_mode, 2, "w");
        } else if ((strcasecmp(PVT_G(pvt_log_write_mode), "a")) == 0) {
            spprintf(&write_mode, 2, "a");
        } else {
            zend_error(E_ERROR, "PVT: wrong write mode for logs!");
        }

        spprintf(&file_stats, 0, "%s/stats.txt", PVT_G(log_folder));

        if (!(fs_handle = fopen(file_stats, write_mode))) {
            zend_error(E_ERROR, "PVT: unable to open provided path for stats");
        }

        if (PVT_G(stats)) {
            fprintf(fs_handle,
                "Maximal deepness:  %d\n"
                "Max filed id:      %d\n"
                "Functions amount:  %d\n"
                "Function calls:    %d\n"
                "Files included:    %d\n"
                "Total run time:    %f\n%s\n",
                PVT_G(stats)->max_stack, PVT_G(stats)->max_fileid, PVT_G(stats)->func_amount,
                PVT_G(stats)->func_calls, PVT_G(stats)->file_amount, pvt_get_utime() - PVT_G(pvt_start_time),
                delimiter
            );
        }

        fclose(fs_handle);
        chmod(file_stats, 0777);

        efree(file_stats);
        efree(write_mode);
        efree(delimiter);

        if (PVT_G(stats)) {
            efree(PVT_G(stats));
        }
    }

    /* Catch marker */

    if (PVT_G(trace_file_c)) {
        fclose(PVT_G(trace_file_c));
    }

    if (PVT_G(trace_file_e)) {
        fclose(PVT_G(trace_file_e));
    }

    /* Dump variables */

    if (PVT_G(trace_file_v)) {
        fclose(PVT_G(trace_file_v));
    }

    /* Functions trace */

    if (PVT_G(trace_file_f)) {
        fclose(PVT_G(trace_file_f));
        init_dot();
        dump_dot();
        free_dot();
    }

    efree(PVT_G(log_folder));

    zend_hash_clean(PVT_G(function_summary));
    zend_hash_clean(PVT_G(file_summary));
    zend_hash_clean(PVT_G(block_summary));

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Epilogue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

    return SUCCESS;
}

static void init_dot(void)
{
    TSRMLS_FETCH();

    char *filename_f = NULL;
    char *write_mode = NULL;

    if (0 == (strcasecmp(PVT_G(pvt_log_write_mode), "w"))) {
        spprintf(&write_mode, 2, "w");
    } else if (0 == (strcasecmp(PVT_G(pvt_log_write_mode), "a"))) {
        spprintf(&write_mode, 2, "a");
    } else {
        zend_error(E_ERROR, "PVT: wrong write mode for logs!");
    }

    spprintf(&filename_f, 0, "%s/trace-functions.dot", PVT_G(log_folder));

    if (!(PVT_G(trace_file_f_dot) = fopen(filename_f, write_mode))) {
        zend_error(E_ERROR, "PVT: unable to open provided path for dump (trace-f-dot)");
    }

    chmod(filename_f, 0777);
    efree(filename_f);
    efree(write_mode);
}

static void free_dot(void)
{
    TSRMLS_FETCH();

    /* First structure */

    if (PVT_G(dot_funcs_i)->file_id) {
        free(PVT_G(dot_funcs_i)->file_id);
    }
    if (PVT_G(dot_funcs_i)->empty) {
        free(PVT_G(dot_funcs_i)->empty);
    }
    if (PVT_G(dot_funcs_i)) {
        free(PVT_G(dot_funcs_i));
    }

    /* Second structure */

    int i;
    for (i = 0; i < PVT_G(funcs)->len; ++i) {
        free(PVT_G(funcs)->func_name[i]);
        free(PVT_G(funcs)->file_name[i]);
    }
    if (PVT_G(funcs)->func_name) {
        free(PVT_G(funcs)->func_name);
    }
    if (PVT_G(funcs)->file_name) {
        free(PVT_G(funcs)->file_name);
    }
    if (PVT_G(funcs)->is_evil) {
        free(PVT_G(funcs)->is_evil);
    }
    if (PVT_G(funcs)->is_dyn) {
        free(PVT_G(funcs)->is_dyn);
    }
    if (PVT_G(funcs)->hide) {
        free(PVT_G(funcs)->hide);
    }
    if (PVT_G(funcs)->stack) {
        free(PVT_G(funcs)->stack);
    }
    if (PVT_G(funcs)->type) {
        free(PVT_G(funcs)->type);
    }
    if (PVT_G(funcs)->line) {
        free(PVT_G(funcs)->line);
    }
    if (PVT_G(funcs)->file_id) {
        free(PVT_G(funcs)->file_id);
    }
    if (PVT_G(funcs)->func_id) {
        free(PVT_G(funcs)->func_id);
    }
    if (PVT_G(funcs)) {
        free(PVT_G(funcs));
    }

    /* Third structure */

    if (PVT_G(funcs_stack)->func_id) {
        free(PVT_G(funcs_stack)->func_id);
    }
    if (PVT_G(funcs_stack)) {
        free(PVT_G(funcs_stack));
    }

}

static void dump_variables(zend_op_array *op_array)
{
    int i, z;
    char *delimiter;
    zval **var_value, tmpcopy;
#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Prologue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif
    TSRMLS_FETCH();

    unsigned int lineno = EG(current_execute_data)->opline->lineno;
    zend_function *active_function  = EG(current_execute_data)->function_state.function;

    delimiter = str_repeat("-", 80);
    char *file_name = zend_get_executed_filename(TSRMLS_C);
    char *class_name = active_function->common.scope
        ? active_function->common.scope->name
        : "";

    pvt_arg *parts = (pvt_arg*) malloc(sizeof(pvt_arg));
    pvt_arg_init(parts);
    pvt_explode(",", PVT_G(pvt_dump_vars_list), parts, -1);

    for (i = 0; i < op_array->last_var; i++) {

        /* If settings are set to track variables */
        if (strlen(PVT_G(pvt_dump_vars_list)) > 0 || PVT_G(pvt_dump_vars_all)) {

            for (z = 0; z < parts->c; ++z) {

                char *varn = parts->args[z];

                if (0 == (strcasecmp(varn, op_array->vars[i].name)) || PVT_G(pvt_dump_vars_all)) {

                    fprintf(PVT_G(trace_file_v), "%s:%d in %s%s%s()",
                            file_name, lineno, class_name,
                            class_name[0] ? "::" : "",
                            get_active_function_name(TSRMLS_C));

                    fprintf(PVT_G(trace_file_v), "\n!%d: $%s = ", i, op_array->vars[i].name);

                    if ((zend_hash_find(
                            &EG(symbol_table),
                            (char *) op_array->vars[i].name,
                            strlen(op_array->vars[i].name) + 1,
                            (void **) &var_value) == SUCCESS))
                    {
                        tmpcopy = **var_value;
                        zval_copy_ctor(&tmpcopy);

                        switch(Z_TYPE_PP(var_value)) {
                            case IS_NULL:
                                fprintf(PVT_G(trace_file_v), "NULL");
                                break;
                            case IS_LONG:
                                convert_to_long(&tmpcopy);
                                fprintf(PVT_G(trace_file_v), "%ld", Z_LVAL(tmpcopy));
                                break;
                            case IS_BOOL:
                                convert_to_boolean(&tmpcopy);
                                fprintf(PVT_G(trace_file_v), "%i", Z_BVAL(tmpcopy));
                                break;
                            case IS_DOUBLE:
                                convert_to_double(&tmpcopy); /* bit bogus */
                                fprintf(PVT_G(trace_file_v), "%f", Z_DVAL(tmpcopy));
                                break;
                            case IS_STRING:
                                convert_to_string(&tmpcopy);
                                fprintf(PVT_G(trace_file_v), "%s", Z_STRVAL(tmpcopy));
                                break;
                            case IS_ARRAY:
                                fprintf(PVT_G(trace_file_v), "PVT: ARRAY");
                                break;
                            case IS_OBJECT:
                                fprintf(PVT_G(trace_file_v), "PVT: OBJECT");
                                break;
                            case IS_RESOURCE:
                                fprintf(PVT_G(trace_file_v), "PVT: RESOURCE");
                                break;
                            default:
                                fprintf(PVT_G(trace_file_v), "PVT: UNKNOWN");
                                break;
                        }

                        zval_dtor(&tmpcopy);

                    } else {
                        fprintf(PVT_G(trace_file_v), "PVT: UNINITIALIZED");
                    }

                    /* end if ((zend_hash_find(... */
                    if (!op_array->last_var) {
                        fprintf(PVT_G(trace_file_v), "none\n");
                    }
                    fprintf(PVT_G(trace_file_v), "\n%s\n", delimiter);

                } /* end if ((strcasecmp(... */

            } /* end for (z... */
        } /* end if (strlen(... */
    } /* end for (i... */

    pvt_arg_dtor(parts);
    efree(delimiter);

#if PVT_DBG_TIME >= 1
    fprintf(PVT_G(timing_dbg), "%s Epilogue:\t%f\n", __func__, pvt_get_utime() - PVT_G(pvt_start_time));
#endif

}

static void statement_handler(zend_op_array *op_array)
{
    TSRMLS_FETCH();

    if (PVT_G(pvt_dump_vars) && PVT_G(trace_file_v)) {
        dump_variables(op_array);
    }
}

static int pvt_zend_startup(zend_extension *extension)
{
    TSRMLS_FETCH();

#if PHP_API_VERSION < 20090626
    CG(extended_info) = 1;
#else
    CG(compiler_options) |= ZEND_COMPILE_EXTENDED_INFO;
#endif

    return zend_startup_module(&pvt_module_entry);
}

#ifndef ZEND_EXT_API
#define ZEND_EXT_API    ZEND_DLEXPORT
#endif
ZEND_EXTENSION();

/* {{{ zend extension definition structure */
ZEND_DLEXPORT zend_extension zend_extension_entry = {
    "PHP Vulnerability Tracer",
    PVT_VERSION,
    "Arthur Gerkis",
    NULL,
    "Copyright (c) 2011",
    pvt_zend_startup,
    NULL,   // pvt_zend_shutdown,
    NULL,   // activate_func_t
    NULL,   // deactivate_func_t
    NULL,   // message_handler_func_t
    NULL,   // op_array_handler_func_t
    statement_handler,   // statement_handler_func_t
    NULL,   // fcall_begin_handler_func_t
    NULL,   // fcall_end_handler,
    NULL,   // op_array_ctor_func_t
    NULL,   // op_array_dtor_func_t
    STANDARD_ZEND_EXTENSION_PROPERTIES
};
/* }}} */
