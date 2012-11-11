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
#include "pvt_trace.h"

ZEND_EXTERN_MODULE_GLOBALS(pvt)

static zend_bool new_var = 0;
static int allf_index    = 0;
static int local_index   = 0;
static int flag_empty    = 0;

/* 1 - path to script */
static char *tpl_dot[1] = {
"digraph flowgraph {\n\
    node [\n\
        fontname=\"Helvetica\"\n\
        fontsize=\"9\"\n\
        shape=\"plaintext\"\n\
    ];\n\
    graph [\n\
        rankdir=\"HR\"\n\
        bgcolor=\"#f7f7f7\"\n\
        label=<Functions Flow Graph, %s>\n\
        labeljust=\"c\"\n\
        labelloc=\"t\"\n\
        fontname=\"Helvetica\"\n\
        fontsize=\"9\"\n\
    ];\n\
    edge [\n\
        arrowsize=\"0.5\"\n\
        arrowhead=\"open\"\n\
        penwidth=\"0.5\"\n\
    ];\n\
    mindist = 0.5;\n\
    overlap = false;\n"
};

/* 1-point name,
 * 2-var name,
 * 3-var name,
 * 4-value
 **/
static char *tpl_point_func[3] = {
    /* For block/node start */
    "\"node_%d\"[\
label =<<TABLE BORDER=\"0\" CELLBORDER=\"0\" CELLSPACING=\"1\" bgcolor=\"#cccc99\">\n\
<TR><TD>::%d</TD>\
<TD PORT=\"n_%d\" align=\"left\" bgcolor=\"#ebebda\" href=\"%s:%d\"> %s<br/>\
<font face=\"helvetica-bold\">%s() [%d]</font>\
</TD></TR>\n",
    /* For USER functions */
    "\t<TR><TD>::%d</TD><TD PORT=\"l_%d\" align=\"left\" bgcolor=\"#b2cc80\">%s() [%d]</TD></TR>\n",
    /* For ZEND functions */
    "\t<TR><TD>::%d</TD><TD align=\"left\" bgcolor=\"#%s\">%s() [%d]</TD></TR>\n"
};

/* 1-point from, 2-point to */
static char *tpl_relation_func[1] = {
    "\"node_%d\":\"l_%d\"->\"node_%d\":\"n_%d\"[URL=\"javascript:xx(%d)\"];\n"
};

/*
 * TODO:
 *  move to *.ini config,
 *  move to separate groups,
 *  add parameter checks
 */
static char *dangerous[DF_LEN] = {
    /* 0 Dynamic code */
    "eval,assert,ob_start,create_function,preg_replace,"
    "call_user_func,call_user_func_array,call_user_method,"
    "array_filter,array_map,array_reduce,uasort,uksort,array_walk,"
    "array_udiff_uassoc,array_udiff_assoc,array_diff_uassoc,array_diff_ukey,"
    "array_udiff,preg_replace_callback,"
    "stream_filter_register,create_function,"
    "call_user_method_array,stream_socket_server",
    /* 1 Inclusions */
    "include,require,require_once,include_once",
    /* 2 Overriding variables */
    "extract,parse_str,import_request_variables",
    /* 3 OS command execution */
    "shell_exec,system,exec,passthru,popen,proc_open,mail,dl,posix",
    /* 4 File operations */
    "file,fopen,file_get_contents,readfile,move_uploaded_file,file_put_contents",
    /* 5 Others */
    "unserialize"
};

static int is_dangerous(const char *function_name)
{
    int i, z;

    for (i = 0; i < DF_LEN; i++) {

        pvt_arg *parts = (pvt_arg*) malloc(sizeof(pvt_arg));
        pvt_arg_init(parts);
        pvt_explode(",", dangerous[i], parts, -1);

        for (z = 0; z < parts->c; ++z) {
            char *varn = parts->args[z];
            if (0 == strcasecmp(varn, function_name)) {
                pvt_arg_dtor(parts);
                return 1;
            }
        }
        pvt_arg_dtor(parts);
    }
    return 0;
}

static int is_func_dyn(const char *function_name)
{
    char *dyn_funcs = "include,include_once,require,require_once,"
                      "eval,assert,ob_start,create_function";
    int i, z;

    pvt_arg *parts = (pvt_arg*) malloc(sizeof(pvt_arg));
    pvt_arg_init(parts);
    pvt_explode(",", dyn_funcs, parts, -1);

    for (z = 0; z < parts->c; ++z) {
        char *varn = parts->args[z];
        if (0 == strcasecmp(varn, function_name)) {
            pvt_arg_dtor(parts);
            return 1;
        }
    }
    pvt_arg_dtor(parts);

    return 0;
}

/*
 * Hides function repetitions in graph
 */
static void hide_functions(void)
{
    TSRMLS_FETCH();

    int k, i = 0;

    for (k = 0; k < PVT_G(funcs)->len; k++) {

        int index   = PVT_G(funcs)->func_id[k];
        int file_id = PVT_G(funcs)->file_id[k];

        if (0 == k || k == PVT_G(funcs)->len) continue;

        int i = k - 1;
        for (i; i > 0; i--) {

            /* If there is a match with some previous item */
            if (PVT_G(funcs)->func_id[i] == index
                && PVT_G(funcs)->file_id[i] == file_id)
            {

                int dist = k - i;
                int g;
                g = i;
                /* This is a temporary rude hack, rarely but it tends to loop.
                 * Thus, I limit maximal amount of functions in block to 29.
                 */
                if (dist > 30) continue;

                /* Drop to the very first block */
                for (g = i; g < PVT_G(funcs)->len; ) {
                    int e, m = 0;

                    /* Start cycling by blocks */
                    for (e = 0; e < dist; e++) {
                        if ((g + dist + e) >= PVT_G(funcs)->len) {
                            break;
                        }
                        if (PVT_G(funcs)->func_id[g+e] == PVT_G(funcs)->func_id[g+dist+e]) {
                            m++;
                        }
                    }

                    if (m == dist) {
                        g += dist;
                        int q;
                        for (q = 0; q < dist; q++) {
                            PVT_G(funcs)->hide[q + g] = 1;
                        }
                        k = g + dist - 1;
                    } else {
                        break;
                    }
                } /* end for(g... */
            } /* end if (PVT_G(funcs... */
        } /* end for (i... */
    } /* end for (k... */
}

void dump_dot(void)
{

    int x, print_header, key_type;
    int *block_num;
    int c = 0, len = 0, flag_ho;
    unsigned long index, key_len;
    unsigned char *block_name = NULL;
    char *time_buff = pvt_get_time();
    smart_str str_dot_func = {0};

    TSRMLS_FETCH();

    char *tmp_buff = NULL;
    tmp_buff = pvt_sprintf(tpl_dot[0], time_buff);
    fprintf(PVT_G(trace_file_f_dot), "%s", tmp_buff);
    efree(time_buff);
    efree(tmp_buff);

    if (PVT_G(pvt_graph_fold)) {
        hide_functions();
    }

    /* Iterate through all blocks/nodes */
    for (zend_hash_internal_pointer_reset(PVT_G(block_summary));
        zend_hash_has_more_elements(PVT_G(block_summary)) == SUCCESS;
        zend_hash_move_forward(PVT_G(block_summary))) {

        key_type = zend_hash_get_current_key(PVT_G(block_summary), &block_name, &index, 0);
        if (key_type == HASH_KEY_IS_STRING) {
            key_len = strlen(block_name);
        }
        zend_hash_get_current_data(PVT_G(block_summary), (void*) &block_num);

        print_header = 1;

        int flag_started = 0;
        int flag_break   = 0;
        int flag_nop     = 0;
        flag_ho = 1;

        size_t ret_len;

        /* Iterate through all functions */
        for (x = 0; x < PVT_G(funcs)->len; x++) {

            if (PVT_G(funcs)->file_id[x] == *block_num) {

                flag_started = 1;
                if (print_header) {
                    if (PVT_G(funcs)->type[x] == 2 && flag_ho) {

                        char *ret;
                        php_basename(
                            PVT_G(funcs)->file_name[x],
                            strlen(PVT_G(funcs)->file_name[x]),
                            NULL, 0, &ret, &ret_len TSRMLS_CC
                        );
                        char *escaped_str = php_escape_html_entities(
                            block_name,
                            strlen(block_name),
                            &len, 0, ENT_QUOTES, NULL TSRMLS_CC
                        );
                        /* Print the block header */
                        fprintf(PVT_G(trace_file_f_dot),
                            tpl_point_func[0],
                            *block_num,
                            PVT_G(funcs)->line[x],
                            *block_num,
                            PVT_G(funcs)->file_name[x], PVT_G(funcs)->line[x],
                            ret,
                            escaped_str,
                            PVT_G(funcs)->func_id[x]
                        );
                        flag_ho = 0;
                        efree(ret);
                        efree(escaped_str);
                    }
                }
            }

            if (PVT_G(funcs)->stack[x] <= PVT_G(dot_funcs_i)->file_id[c] && flag_started) {
                if (0 == print_header) {
                    flag_break = 1;
                } else {
                    flag_break = 0;
                }
            }

            if (0 == flag_started) {
                continue;
            }

            if ((PVT_G(funcs)->stack[x]-1) != PVT_G(dot_funcs_i)->file_id[c]) {
                if (!flag_break) {
                    continue;
                } else {
                    flag_nop = 1;
                }
            }

            if (flag_nop != 1) {
                flag_nop = 0;
                if (print_header) {
                    print_header = 0;
                }

                if (PVT_G(dot_funcs_i)->empty[c]) {
                    flag_started = 0;
                    break;
                }

                /* Check if function repeats */
                if (0 == PVT_G(funcs)->hide[x] || !PVT_G(pvt_graph_fold)) {
                    if (2 == PVT_G(funcs)->type[x]) {

                        /* This is USER function */
                        char *escaped_str = php_escape_html_entities(
                            (unsigned char*) PVT_G(funcs)->func_name[x],
                            strlen(PVT_G(funcs)->func_name[x]),
                            &len, 0, ENT_QUOTES, NULL TSRMLS_CC
                        );

                        fprintf(PVT_G(trace_file_f_dot),
                            tpl_point_func[1],
                            PVT_G(funcs)->line[x],
                            PVT_G(funcs)->line[x],
                            escaped_str,
                            PVT_G(funcs)->func_id[x]
                        );
                        efree(escaped_str);

                        char *tmp_buff = pvt_sprintf(
                            tpl_relation_func[0],
                            *block_num,
                            PVT_G(funcs)->line[x],
                            PVT_G(funcs)->file_id[x],
                            PVT_G(funcs)->file_id[x],
                            PVT_G(funcs)->func_id[x]
                        );
                        smart_str_appends(&str_dot_func, tmp_buff);
                        efree(tmp_buff);

                    } else {
                        /* This is ZEND function */
                        char *escaped_str = php_escape_html_entities(
                            (unsigned char*) PVT_G(funcs)->func_name[x],
                            strlen(PVT_G(funcs)->func_name[x]),
                            &len, 0, ENT_QUOTES, NULL TSRMLS_CC
                        );

                        fprintf(PVT_G(trace_file_f_dot),
                            tpl_point_func[2],
                            PVT_G(funcs)->line[x],
                            (1 == PVT_G(funcs)->is_evil[x] ? "d63333" : "e0ebcc"),
                            escaped_str,
                            PVT_G(funcs)->func_id[x]
                        );
                        efree(escaped_str);
                    }

                } /* end if (0 ==... */
            } /* end if (flag_nop... */

            if (flag_break) {
                if (!flag_nop) {
                    flag_break   = 0;
                    flag_started = 0;
                    break;
                }
            }
        } /* end for (x... */
        c++;
        fprintf(PVT_G(trace_file_f_dot), "</TABLE>>\n]\n");
    }

    smart_str_0(&str_dot_func);
    if (str_dot_func.c != NULL) {
        fprintf(PVT_G(trace_file_f_dot), "%s", str_dot_func.c);
    }
    smart_str_free(&str_dot_func);
    fprintf(PVT_G(trace_file_f_dot), "\n}\n");
    fclose(PVT_G(trace_file_f_dot));
}

void trace_function_entry(HashTable *func_table, const char *func_name, int type, const char *filename, int linenum)
{
    int *function_index;
    int tmp_function_index;
    int *filenum;
    int tmp_filenum;
    int tmp_block_num;
    int *block_num;
    int esp         = 0;
    int flag_x      = 0;
    int is_dynamic  = 0;
    int is_evil     = 0;
    char *fname = NULL;

    TSRMLS_FETCH();

    if (PVT_G(pvt_count_stat)) {
        PVT_G(stats)->func_calls += 1;
    }
    allf_index += 1;

    is_evil = is_dangerous(func_name);

    /* Functions tracing */

    if (zend_hash_find(PVT_G(file_summary), (char *) filename, strlen(filename) + 1, (void *) &filenum) == FAILURE) {

        tmp_filenum = ++PVT_G(file_index);

        fprintf(PVT_G(trace_file_f), " \t| #%d\t| \t%s %s()\n", tmp_filenum, filename, func_name);

        zend_hash_add(PVT_G(file_summary), (char *) filename, strlen(filename) + 1, &(tmp_filenum), sizeof(int), NULL);

        if (PVT_G(pvt_count_stat)) {
            PVT_G(stats)->file_amount += 1;
        }
    } else {
        tmp_filenum = *filenum;
    }


    if (is_func_dyn(func_name)) {
        fname = (char *) pvt_sprintf("%s_%d", func_name, tmp_filenum);
        local_index = 0;
        is_dynamic  = 1;
    } else {
        fname = (char *) pvt_sprintf("%s", func_name);
    }

    /* Files tracing */

    if (zend_hash_find(PVT_G(function_summary), (char *) fname, strlen(fname) + 1, (void *) &function_index) == SUCCESS) {

        tmp_function_index = *function_index;

        fprintf(PVT_G(trace_file_f), " %d\t| -->\t| %s() %s #%d {\n", linenum,  fname, filename, tmp_function_index);
        new_var = 0;

    } else {

        /* We enter in new function */
        tmp_function_index = ++PVT_G(function_index);

        zend_hash_add(PVT_G(function_summary), (char *) fname, strlen(fname) + 1, &(tmp_function_index), sizeof(int), NULL);

        fprintf(PVT_G(trace_file_f), " \t| #%d\t| %s() %d\n", tmp_function_index, fname, type);
        fprintf(PVT_G(trace_file_f), " %d\t| -->\t| %s() %s #%d .{\n", linenum,  fname, filename, tmp_function_index);

        if (!is_dynamic && PVT_G(pvt_count_stat)) {
            PVT_G(stats)->func_amount += 1;
        }
    }

    /* For *.dot graphs */

    if (zend_hash_find(PVT_G(block_summary), (char *) fname, strlen(fname) + 1, (void *) &block_num) == FAILURE) {

        /* Files and user functions */
        if (2 == type) {

            tmp_block_num = ++PVT_G(block_index);
            zend_hash_add(PVT_G(block_summary), (char *) fname, strlen(fname) + 1, &(tmp_block_num), sizeof(int), NULL);
            flag_x = 1;
            new_var = 1;
        }
    } else {
        tmp_block_num = *block_num;
    }

    local_index += 1;

    if (2 == type) {

        PVT_G(funcs_stack)->func_id = realloc(PVT_G(funcs_stack)->func_id, (PVT_G(funcs_stack)->len+1) * sizeof(int));
        PVT_G(funcs_stack)->func_id[PVT_G(funcs_stack)->len] = tmp_block_num;

        PVT_G(funcs_stack)->len += 1;
        esp = PVT_G(funcs_stack)->func_id[PVT_G(funcs_stack)->len-1];
    } else {
        /* In file or in function
         * Note: here was a problem with finding esp with dynamic content, had
         * to add second check 'is_dynamic'. Find better fix?
         */
        if (allf_index - tmp_filenum == 0 && !is_dynamic) {
            esp = PVT_G(funcs)->file_id[PVT_G(funcs)->len - local_index + 1];
        } else {
            /* In function */
            esp = PVT_G(funcs_stack)->func_id[PVT_G(funcs_stack)->len-1];
        }
    }

    if (flag_x) {

        PVT_G(dot_funcs_i)->file_id = realloc(PVT_G(dot_funcs_i)->file_id, (PVT_G(dot_funcs_i)->len+1) * sizeof(int));
        PVT_G(dot_funcs_i)->file_id[PVT_G(dot_funcs_i)->len] = PVT_G(funcs_stack)->i;

        PVT_G(dot_funcs_i)->empty = realloc(PVT_G(dot_funcs_i)->empty, (PVT_G(dot_funcs_i)->len+1) * sizeof(int));
        PVT_G(dot_funcs_i)->empty[PVT_G(dot_funcs_i)->len] = 0;

        PVT_G(dot_funcs_i)->len += 1;
    }

    if (PVT_G(pvt_count_stat)) {
        if (esp > PVT_G(stats)->max_fileid) {
            PVT_G(stats)->max_fileid = esp;
        }
    }


    /* Save variable and related block node number */
    PVT_G(funcs)->func_id = realloc(PVT_G(funcs)->func_id, (PVT_G(funcs)->len+1) * sizeof(int));
    PVT_G(funcs)->func_id[PVT_G(funcs)->len] = tmp_function_index;

    PVT_G(funcs)->file_id = realloc(PVT_G(funcs)->file_id, (PVT_G(funcs)->len+1) * sizeof(int));
    PVT_G(funcs)->file_id[PVT_G(funcs)->len] = esp;

    PVT_G(funcs)->line = realloc(PVT_G(funcs)->line, (PVT_G(funcs)->len+1) * sizeof(int));
    PVT_G(funcs)->line[PVT_G(funcs)->len] = linenum;

    PVT_G(funcs)->type = realloc(PVT_G(funcs)->type, (PVT_G(funcs)->len+1) * sizeof(int));
    PVT_G(funcs)->type[PVT_G(funcs)->len] = type;

    PVT_G(funcs)->stack = realloc(PVT_G(funcs)->stack, (PVT_G(funcs)->len+1) * sizeof(int));
    PVT_G(funcs)->stack[PVT_G(funcs)->len] = PVT_G(funcs_stack)->i;

    PVT_G(funcs)->hide = realloc(PVT_G(funcs)->hide, (PVT_G(funcs)->len+1) * sizeof(int));
    PVT_G(funcs)->hide[PVT_G(funcs)->len] = 0;

    PVT_G(funcs)->is_dyn = realloc(PVT_G(funcs)->is_dyn, (PVT_G(funcs)->len+1) * sizeof(int));
    PVT_G(funcs)->is_dyn[PVT_G(funcs)->len] = is_dynamic;

    PVT_G(funcs)->is_evil = realloc(PVT_G(funcs)->is_evil, (PVT_G(funcs)->len+1) * sizeof(int));
    PVT_G(funcs)->is_evil[PVT_G(funcs)->len] = is_evil;

    PVT_G(funcs)->file_name = realloc(PVT_G(funcs)->file_name, sizeof(char*) * (PVT_G(funcs)->len+1));
    PVT_G(funcs)->file_name[PVT_G(funcs)->len] = malloc(strlen(filename) + 1);
    memcpy(PVT_G(funcs)->file_name[PVT_G(funcs)->len], filename, strlen(filename) + 1);
    PVT_G(funcs)->file_name[PVT_G(funcs)->len][strlen(filename)] = '\0';

    PVT_G(funcs)->func_name = realloc(PVT_G(funcs)->func_name, sizeof(char*) * (PVT_G(funcs)->len+1));
    PVT_G(funcs)->func_name[PVT_G(funcs)->len] = malloc(strlen(fname) + 1);
    memcpy(PVT_G(funcs)->func_name[PVT_G(funcs)->len], fname, strlen(fname) + 1);
    PVT_G(funcs)->func_name[PVT_G(funcs)->len][strlen(fname)] = '\0';

    flag_empty = tmp_function_index;

    PVT_G(funcs)->len += 1;
    if (2 == type) {
        PVT_G(funcs_stack)->i += 1;
    }

    if (PVT_G(pvt_count_stat)) {
        if (PVT_G(funcs_stack)->i > PVT_G(stats)->max_stack) {
            PVT_G(stats)->max_stack = PVT_G(funcs_stack)->i;
        }
    }

    if (fname) {
        efree(fname);
    }
}

void trace_function_exit(char *func_name, char *filename, int type, int line)
{
    int *function_index;
    int *filenum;
    int tmp_func_index;
    char *fname;

    TSRMLS_FETCH();

    if (zend_hash_find(PVT_G(file_summary), (char *) filename, strlen(filename) + 1, (void *) &filenum) == FAILURE) {
        /* Do nothing */
    }

    if (is_func_dyn(func_name)) {
        fname = (char *) pvt_sprintf("%s_%d", func_name, *filenum);
        local_index = PVT_G(funcs)->len;
    } else {
        fname = (char *) pvt_sprintf("%s", func_name);
    }

    if (zend_hash_find(PVT_G(function_summary), fname, strlen(fname) + 1, (void *) &function_index) == SUCCESS) {

        tmp_func_index = *function_index;
        fprintf(PVT_G(trace_file_f), " %d\t| <--\t| %s() %s #%d }\n\n", line, fname, filename, tmp_func_index);

    } else {

        tmp_func_index =  ++PVT_G(function_index);
        zend_hash_add(PVT_G(function_summary), fname, strlen(fname) + 1, &(tmp_func_index), sizeof(int), NULL);

        fprintf(PVT_G(trace_file_f), " %d\t| <--\t| %s() %s #%d .}\n\n", line, fname, filename, tmp_func_index);
    }

    allf_index -= 1;

    if (2 == type) {
        PVT_G(funcs_stack)->i -= 1;
        if (flag_empty == tmp_func_index && new_var) {
            PVT_G(dot_funcs_i)->empty[PVT_G(dot_funcs_i)->len-1] = 1;
        }
    }

    if (fname) {
        efree(fname);
    }
}

zval *debug_backtrace_get_args(void ***curpos TSRMLS_DC)
{
#if PHP_API_VERSION >= 20090626
    void **p = *curpos;
#else
    void **p = *curpos - 2;
#endif
    zval *arg_array, **arg;
    int arg_count = (int)(zend_uintptr_t) *p;

#if PHP_API_VERSION < 20090626
    *curpos -= (arg_count+2);
#endif

    MAKE_STD_ZVAL(arg_array);
#if PHP_API_VERSION >= 20090626
    array_init_size(arg_array, arg_count);
#else
    array_init(arg_array);
#endif
    p -= arg_count;

    while (--arg_count >= 0) {
        arg = (zval **) p++;
        if (*arg) {
            if (Z_TYPE_PP(arg) != IS_OBJECT) {
                SEPARATE_ZVAL_TO_MAKE_IS_REF(arg);
            }
#if PHP_API_VERSION >= 20090626
            Z_ADDREF_PP(arg);
#else
            (*arg)->refcount++;
#endif
            add_next_index_zval(arg_array, *arg);
        } else {
            add_next_index_null(arg_array);
        }
    }

#if PHP_API_VERSION < 20090626
    /* skip args from incomplete frames */
    while ( (((*curpos)-1) > EG(argument_stack).elements) && *((*curpos)-1) ) {
        (*curpos)--;
    }

#endif
    return arg_array;
}

void pvt_trace_variables(void)
{
    TSRMLS_FETCH();

    int lineno;
    char *function_name;
    char *filename;
    char *class_name = NULL;
    char *call_type;
    char *include_filename = NULL;
    zval *arg_array = NULL;
    zend_execute_data *ptr, *skip;
    zend_uchar zfunction_type;
    zend_uint func_num_args;
#if PHP_API_VERSION < 20090626
    void **cur_arg_pos = EG(argument_stack).top_element;
    void **args = cur_arg_pos;
    int arg_stack_consistent = 0;
    int frames_on_stack = 0;
#endif
    int indent = 0;

#if PHP_API_VERSION < 20090626
    while (--args > EG(argument_stack).elements) {
        if (*args--) {
            break;
        }
        args -= *(ulong*)args;
        frames_on_stack++;

        /* skip args from incomplete frames */
        while (((args-1) > EG(argument_stack).elements) && *(args-1)) {
            args--;
        }

        if ((args-1) == EG(argument_stack).elements) {
            arg_stack_consistent = 1;
            break;
        }
    }
#endif
    ptr = EG(current_execute_data);

    while (ptr) {
        char *free_class_name = NULL;

        class_name = call_type = NULL;
        arg_array = NULL;

        skip = ptr;
        /* skip internal handler */
        if (!skip->op_array &&
            skip->prev_execute_data &&
            skip->prev_execute_data->opline &&
            skip->prev_execute_data->opline->opcode != ZEND_DO_FCALL &&
            skip->prev_execute_data->opline->opcode != ZEND_DO_FCALL_BY_NAME &&
            skip->prev_execute_data->opline->opcode != ZEND_INCLUDE_OR_EVAL) {
            skip = skip->prev_execute_data;

        }

        if (skip->op_array) {
            filename = skip->op_array->filename;
            lineno = skip->opline->lineno;
        } else {
            filename = NULL;
            lineno = 0;
        }

        function_name = ptr->function_state.function->common.function_name;
        zend_function_state finfo = ptr->function_state;

        if (function_name) {
            if (ptr->object) {
                if (ptr->function_state.function->common.scope) {
                    class_name = ptr->function_state.function->common.scope->name;
                } else {
                    zend_uint class_name_len;
                    int dup;

                    dup = zend_get_object_classname(ptr->object, &class_name, &class_name_len TSRMLS_CC);
                    if(!dup) {
                        free_class_name = class_name;
                    }
                }

                call_type = "->";
            } else if (ptr->function_state.function->common.scope) {
                class_name = ptr->function_state.function->common.scope->name;
                call_type = "::";
            } else {
                class_name = NULL;
                call_type = NULL;
            }

            if ((! ptr->opline) || ((ptr->opline->opcode == ZEND_DO_FCALL_BY_NAME) || (ptr->opline->opcode == ZEND_DO_FCALL))) {
#if PHP_API_VERSION >= 20090626

                if (ptr->function_state.arguments) {
                    arg_array = debug_backtrace_get_args(&ptr->function_state.arguments TSRMLS_CC);
                }
#else
                if (arg_stack_consistent && (frames_on_stack > 0)) {
                    arg_array = debug_backtrace_get_args(&cur_arg_pos TSRMLS_CC);
                    frames_on_stack--;
                }
#endif
            }

        } else {

            zend_bool build_filename_arg = 1;

            if (!ptr->opline || ptr->opline->opcode != ZEND_INCLUDE_OR_EVAL) {
                /* can happen when calling eval from a custom sapi */
                function_name = "unknown";
                build_filename_arg = 0;
            } else
#if ZEND_MODULE_API_NO >= 20100409 /* ZE2.4 */
            switch (ptr->opline->op2.constant) {
#else
            switch (Z_LVAL(ptr->opline->op2.u.constant)) {
#endif
                case ZEND_EVAL:
                    function_name = "eval";
                    build_filename_arg = 0;
                    break;
                case ZEND_INCLUDE:
                    function_name = "include";
                    break;
                case ZEND_REQUIRE:
                    function_name = "require";
                    break;
                case ZEND_INCLUDE_ONCE:
                    function_name = "include_once";
                    break;
                case ZEND_REQUIRE_ONCE:
                    function_name = "require_once";
                    break;
                default:
                    /* this can actually happen if you use debug_backtrace() in your error_handler and
                     * you're in the top-scope */
                    function_name = "unknown";
                    build_filename_arg = 0;
                    break;
            }

            if (build_filename_arg && include_filename) {
                MAKE_STD_ZVAL(arg_array);
                array_init(arg_array);
                add_next_index_string(arg_array, include_filename, 1);
            }
            call_type = NULL;
        }

        if (arg_array) {
            get_and_dump_args(function_name, lineno, filename, &finfo, arg_array TSRMLS_CC);
            zval_ptr_dtor(&arg_array);
        }

        if (!filename) {
            zend_execute_data *prev = skip->prev_execute_data;

            while (prev) {
                if (prev->function_state.function &&
                    prev->function_state.function->common.type != ZEND_USER_FUNCTION) {
                    prev = NULL;
                    break;
                }
                if (prev->op_array) {
                    break;
                }
                prev = prev->prev_execute_data;
            }
        }
        include_filename = filename;
        ptr = skip->prev_execute_data;
        ++indent;
        if (free_class_name) {
            efree(free_class_name);
        }
    }
}
