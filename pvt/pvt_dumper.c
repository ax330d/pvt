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

ZEND_EXTERN_MODULE_GLOBALS(pvt)

typedef struct _op_usage {
    char *name;
    zend_uint flags;
} op_usage;

static const op_usage opcodes[] = {
    /*  0 */    { "NOP", NONE_USED },
    /*  1 */    { "ADD", ALL_USED },
    /*  2 */    { "SUB", ALL_USED },
    /*  3 */    { "MUL", ALL_USED },
    /*  4 */    { "DIV", ALL_USED },
    /*  5 */    { "MOD", ALL_USED },
    /*  6 */    { "SL", ALL_USED },
    /*  7 */    { "SR", ALL_USED },
    /*  8 */    { "CONCAT", ALL_USED },
    /*  9 */    { "BW_OR", ALL_USED },
    /*  10 */   { "BW_AND", ALL_USED },
    /*  11 */   { "BW_XOR", ALL_USED },
    /*  12 */   { "BW_NOT", RES_USED | OP1_USED },
    /*  13 */   { "BOOL_NOT", RES_USED | OP1_USED },
    /*  14 */   { "BOOL_XOR", ALL_USED },
    /*  15 */   { "IS_IDENTICAL", ALL_USED },
    /*  16 */   { "IS_NOT_IDENTICAL", ALL_USED },
    /*  17 */   { "IS_EQUAL", ALL_USED },
    /*  18 */   { "IS_NOT_EQUAL", ALL_USED },
    /*  19 */   { "IS_SMALLER", ALL_USED },
    /*  20 */   { "IS_SMALLER_OR_EQUAL", ALL_USED },
    /*  21 */   { "CAST", ALL_USED },
    /*  22 */   { "QM_ASSIGN", RES_USED | OP1_USED },
    /*  23 */   { "ASSIGN_ADD", ALL_USED | EXT_VAL },
    /*  24 */   { "ASSIGN_SUB", ALL_USED | EXT_VAL },
    /*  25 */   { "ASSIGN_MUL", ALL_USED | EXT_VAL },
    /*  26 */   { "ASSIGN_DIV", ALL_USED | EXT_VAL },
    /*  27 */   { "ASSIGN_MOD", ALL_USED | EXT_VAL },
    /*  28 */   { "ASSIGN_SL", ALL_USED | EXT_VAL },
    /*  29 */   { "ASSIGN_SR", ALL_USED | EXT_VAL },
    /*  30 */   { "ASSIGN_CONCAT", ALL_USED | EXT_VAL },
    /*  31 */   { "ASSIGN_BW_OR", ALL_USED | EXT_VAL },
    /*  32 */   { "ASSIGN_BW_AND", ALL_USED | EXT_VAL },
    /*  33 */   { "ASSIGN_BW_XOR", ALL_USED | EXT_VAL },
    /*  34 */   { "PRE_INC", OP1_USED | RES_USED },
    /*  35 */   { "PRE_DEC", OP1_USED | RES_USED },
    /*  36 */   { "POST_INC", OP1_USED | RES_USED },
    /*  37 */   { "POST_DEC", OP1_USED | RES_USED },
    /*  38 */   { "ASSIGN", ALL_USED },
    /*  39 */   { "ASSIGN_REF", SPECIAL },
    /*  40 */   { "ECHO", OP1_USED },
    /*  41 */   { "PRINT", RES_USED | OP1_USED },
    /*  42 */   { "JMP", OP1_USED | OP1_OPLINE },
    /*  43 */   { "JMPZ", OP1_USED | OP2_USED | OP2_OPLINE },
    /*  44 */   { "JMPNZ", OP1_USED | OP2_USED | OP2_OPLINE },
    /*  45 */   { "JMPZNZ", SPECIAL },
    /*  46 */   { "JMPZ_EX", ALL_USED | OP2_OPLINE },
    /*  47 */   { "JMPNZ_EX", ALL_USED | OP2_OPLINE },
    /*  48 */   { "CASE", ALL_USED },
    /*  49 */   { "SWITCH_FREE", RES_USED | OP1_USED },
    /*  50 */   { "BRK", SPECIAL },
    /*  51 */   { "CONT", ALL_USED },
    /*  52 */   { "BOOL", RES_USED | OP1_USED },
    /*  53 */   { "INIT_STRING", RES_USED },
    /*  54 */   { "ADD_CHAR", ALL_USED },
    /*  55 */   { "ADD_STRING", ALL_USED },
    /*  56 */   { "ADD_VAR", ALL_USED },
    /*  57 */   { "BEGIN_SILENCE", ALL_USED },
    /*  58 */   { "END_SILENCE", ALL_USED },
    /*  59 */   { "INIT_FCALL_BY_NAME", SPECIAL },
    /*  60 */   { "DO_FCALL", SPECIAL },
    /*  61 */   { "DO_FCALL_BY_NAME", SPECIAL },
    /*  62 */   { "RETURN", OP1_USED },
    /*  63 */   { "RECV", RES_USED | OP1_USED },
    /*  64 */   { "RECV_INIT", ALL_USED },
    /*  65 */   { "SEND_VAL", OP1_USED },
    /*  66 */   { "SEND_VAR", OP1_USED },
    /*  67 */   { "SEND_REF", ALL_USED },
    /*  68 */   { "NEW", SPECIAL },
#if (PHP_MAJOR_VERSION < 5) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 1)
    /*  69 */   { "JMP_NO_CTOR", SPECIAL },
#else
# if (PHP_MAJOR_VERSION > 5) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION >= 3)
    /*  69 */   { "INIT_NS_FCALL_BY_NAME", SPECIAL },
# else
    /*  69 */   { "UNKNOWN", ALL_USED },
# endif
#endif
    /*  70 */   { "FREE", OP1_USED },
    /*  71 */   { "INIT_ARRAY", ALL_USED },
    /*  72 */   { "ADD_ARRAY_ELEMENT", ALL_USED },
    /*  73 */   { "INCLUDE_OR_EVAL", ALL_USED | OP2_INCLUDE },
    /*  74 */   { "UNSET_VAR", ALL_USED },
#ifdef ZEND_ENGINE_2
    /*  75 */   { "UNSET_DIM", ALL_USED },
    /*  76 */   { "UNSET_OBJ", ALL_USED },
#else
    /*  75 */   { "UNSET_DIM_OBJ", ALL_USED },
    /*  76 */   { "ISSET_ISEMPTY", ALL_USED },
#endif
    /*  77 */   { "FE_RESET", SPECIAL },
    /*  78 */   { "FE_FETCH", ALL_USED | OP2_OPNUM },
    /*  79 */   { "EXIT", ALL_USED },
    /*  80 */   { "FETCH_R", RES_USED | OP1_USED | OP_FETCH },
    /*  81 */   { "FETCH_DIM_R", ALL_USED },
    /*  82 */   { "FETCH_OBJ_R", ALL_USED },
    /*  83 */   { "FETCH_W", RES_USED | OP1_USED | OP_FETCH },
    /*  84 */   { "FETCH_DIM_W", ALL_USED },
    /*  85 */   { "FETCH_OBJ_W", ALL_USED },
    /*  86 */   { "FETCH_RW", RES_USED | OP1_USED | OP_FETCH },
    /*  87 */   { "FETCH_DIM_RW", ALL_USED },
    /*  88 */   { "FETCH_OBJ_RW", ALL_USED },
    /*  89 */   { "FETCH_IS", ALL_USED },
    /*  90 */   { "FETCH_DIM_IS", ALL_USED },
    /*  91 */   { "FETCH_OBJ_IS", ALL_USED },
    /*  92 */   { "FETCH_FUNC_ARG", RES_USED | OP1_USED | OP_FETCH },
    /*  93 */   { "FETCH_DIM_FUNC_ARG", ALL_USED },
    /*  94 */   { "FETCH_OBJ_FUNC_ARG", ALL_USED },
    /*  95 */   { "FETCH_UNSET", ALL_USED },
    /*  96 */   { "FETCH_DIM_UNSET", ALL_USED },
    /*  97 */   { "FETCH_OBJ_UNSET", ALL_USED },
    /*  98 */   { "FETCH_DIM_TMP_VAR", ALL_USED },
    /*  99 */   { "FETCH_CONSTANT", ALL_USED },
#if (PHP_MAJOR_VERSION < 5) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 3)
    /*  100 */  { "DECLARE_FUNCTION_OR_CLASS", ALL_USED },
#else
    /*  100 */  { "GOTO", ALL_USED | OP1_OPLINE },
#endif
    /*  101 */  { "EXT_STMT", ALL_USED },
    /*  102 */  { "EXT_FCALL_BEGIN", ALL_USED },
    /*  103 */  { "EXT_FCALL_END", ALL_USED },
    /*  104 */  { "EXT_NOP", ALL_USED },
    /*  105 */  { "TICKS", ALL_USED },
    /*  106 */  { "SEND_VAR_NO_REF", ALL_USED | EXT_VAL },
#ifdef ZEND_ENGINE_2
    /*  107 */  { "ZEND_CATCH", ALL_USED | EXT_VAL },
    /*  108 */  { "ZEND_THROW", ALL_USED | EXT_VAL },

    /*  109 */  { "ZEND_FETCH_CLASS", SPECIAL },

    /*  110 */  { "ZEND_CLONE", ALL_USED },

#if (PHP_MAJOR_VERSION < 5) || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION <= 2)
    /*  111 */  { "ZEND_INIT_CTOR_CALL", ALL_USED },
#else
    /*  111 */  { "UNKNOWN", ALL_USED },
#endif
    /*  112 */  { "ZEND_INIT_METHOD_CALL", ALL_USED },
    /*  113 */  { "ZEND_INIT_STATIC_METHOD_CALL", ALL_USED },

    /*  114 */  { "ZEND_ISSET_ISEMPTY_VAR", ALL_USED | EXT_VAL },
    /*  115 */  { "ZEND_ISSET_ISEMPTY_DIM_OBJ", ALL_USED | EXT_VAL },

    /*  116 */  { "ZEND_IMPORT_FUNCTION", ALL_USED },
    /*  117 */  { "ZEND_IMPORT_CLASS", ALL_USED },
    /*  118 */  { "ZEND_IMPORT_CONST", ALL_USED },

    /*  119 */  { "119", ALL_USED },
    /*  120 */  { "120", ALL_USED },

    /*  121 */  { "ZEND_ASSIGN_ADD_OBJ", ALL_USED },
    /*  122 */  { "ZEND_ASSIGN_SUB_OBJ", ALL_USED },
    /*  123 */  { "ZEND_ASSIGN_MUL_OBJ", ALL_USED },
    /*  124 */  { "ZEND_ASSIGN_DIV_OBJ", ALL_USED },
    /*  125 */  { "ZEND_ASSIGN_MOD_OBJ", ALL_USED },
    /*  126 */  { "ZEND_ASSIGN_SL_OBJ", ALL_USED },
    /*  127 */  { "ZEND_ASSIGN_SR_OBJ", ALL_USED },
    /*  128 */  { "ZEND_ASSIGN_CONCAT_OBJ", ALL_USED },
    /*  129 */  { "ZEND_ASSIGN_BW_OR_OBJ", ALL_USED },
    /*  130 */  { "ZEND_ASSIGN_BW_AND_OBJ", ALL_USED },
    /*  131 */  { "ZEND_ASSIGN_BW_XOR_OBJ", ALL_USED },

    /*  132 */  { "ZEND_PRE_INC_OBJ", ALL_USED },
    /*  133 */  { "ZEND_PRE_DEC_OBJ", ALL_USED },
    /*  134 */  { "ZEND_POST_INC_OBJ", ALL_USED },
    /*  135 */  { "ZEND_POST_DEC_OBJ", ALL_USED },

    /*  136 */  { "ZEND_ASSIGN_OBJ", ALL_USED },
    /*  137 */  { "ZEND_OP_DATA", ALL_USED },

    /*  138 */  { "ZEND_INSTANCEOF", ALL_USED },

    /*  139 */  { "ZEND_DECLARE_CLASS", ALL_USED },
    /*  140 */  { "ZEND_DECLARE_INHERITED_CLASS", ALL_USED },
    /*  141 */  { "ZEND_DECLARE_FUNCTION", ALL_USED },

    /*  142 */  { "ZEND_RAISE_ABSTRACT_ERROR", ALL_USED },

    /*  143 */  { "ZEND_START_NAMESPACE", ALL_USED },

    /*  144 */  { "ZEND_ADD_INTERFACE", ALL_USED },
    /*  145 */  { "ZEND_VERIFY_INSTANCEOF", ALL_USED },
    /*  146 */  { "ZEND_VERIFY_ABSTRACT_CLASS", ALL_USED },
    /*  147 */  { "ZEND_ASSIGN_DIM", ALL_USED },
    /*  148 */  { "ZEND_ISSET_ISEMPTY_PROP_OBJ", ALL_USED },
    /*  149 */  { "ZEND_HANDLE_EXCEPTION", NONE_USED },
    /*  150 */  { "ZEND_USER_OPCODE", ALL_USED },
    /*  151 */  { "ZEND_U_NORMALIZE", RES_USED | OP1_USED },
    /*  152 */  { "ZEND_JMP_SET", ALL_USED | OP2_OPLINE },
    /*  153 */  { "ZEND_DECLARE_LAMBDA_FUNCTION", OP1_USED },
#endif
};

/* {{{ format_zval
 */
void *format_zval(zval *z, zend_bool raw)
{
    switch (z->type)
    {
        case IS_NULL:
            return pvt_sprintf("%s", "NULL");
        case IS_LONG:
        case IS_BOOL:
            return pvt_sprintf("%li", z->value.lval);
        case IS_DOUBLE:
            return pvt_sprintf("%f", z->value.lval);
        case IS_STRING:
            if (raw) {
                return pvt_sprintf("%s", z->value.str.val);
            } else {
                return pvt_sprintf("\"%s\"", z->value.str.val);
            }
        case IS_ARRAY:
            return pvt_sprintf("%s", "(Array)");
        case IS_OBJECT:
            return pvt_sprintf("%s", "(Object)");
        case IS_RESOURCE:
            return pvt_sprintf("%s", "(Resource)");
        case IS_CONSTANT:
            return pvt_sprintf("%s", "(Constant)");
        case IS_CONSTANT_ARRAY:
            return pvt_sprintf("%s", "(Constant array)");
        default:
            return pvt_sprintf("%s", "Unknown");
    }
}
/* {{{ */

/* {{{ format_znode
 */
void *format_znode(znode *n, zend_uint base_address)
{
    char *tmp;
    char *buff = NULL;

    switch (n->op_type) {
        case IS_UNUSED:
            return pvt_sprintf("%s", " ");
            break;
        /* 1, Constant */
        case IS_CONST:
#if PHP_VERSION_ID >= 50399
            tmp = format_zval(n->zv, 0);
#else
            tmp = format_zval(&n->u.constant, 0);
#endif
            buff = pvt_sprintf("%s", tmp);
            efree(tmp);
            return buff;
            break;
        /* 16, Compiled variable */
        case IS_CV:
            return pvt_sprintf("!%d", n->u.var);
            break;
        /* 4, Variable */
        case IS_VAR:
            return pvt_sprintf("$%ld", n->u.var/sizeof(temp_variable));
            break;
        /* 2, TMP variable */
        case IS_TMP_VAR:
            return pvt_sprintf( "~%ld", n->u.var/sizeof(temp_variable));
            break;
        case PVT_IS_OPNUM:
            return pvt_sprintf("->%d", n->u.opline_num);
            break;
        case PVT_IS_OPLINE:
            return pvt_sprintf("->%ld", (n->u.opline_num - base_address) / sizeof(zend_op));
            break;
        case PVT_IS_CLASS:
            return pvt_sprintf(":%ld", n->u.var / sizeof(temp_variable));
            break;
        default:
            return pvt_sprintf("%s", " ");
            break;
    }
}
/* }}} */


/* {{{ opname
 */
char *opname(zend_uchar opcode)
{
    return opcodes[opcode].name;
}
/* }}} */

#define NUM_KNOWN_OPCODES (sizeof(opcodes)/sizeof(opcodes[0]))

/* {{{ dump_op
 */
static void dump_op(zend_op_array *op_array, zend_op *opi, int num, zend_uint base_address)
{
    unsigned int flags, op1_type, op2_type, res_type;
    char *op_result = NULL;
    char *op_op1 = NULL;
    char *op_op2 = NULL;

    TSRMLS_FETCH();

    /* EXT_STMT */
    if (opi->opcode == 101) {
        fprintf(PVT_G(log_file_path), "\t<tr class=\"s\">");
    } else {
        fprintf(PVT_G(log_file_path), "\t<tr>");
    }

    fprintf(PVT_G(log_file_path),
        "<td>%d</td><td>%d</td><td title=\"%d\" class=\"wz\">%s</td>",
        num, opi->lineno, opi->opcode, opname(opi->opcode)
    );

    if (!(opi->PVT_EXTENDED_VALUE(result) & EXT_TYPE_UNUSED)) {
        op_result = format_znode(&opi->result, base_address);
        fprintf(PVT_G(log_file_path),
            "<td>%s</td>", op_result
        );
        if (op_result) {
            efree(op_result);
        }
    } else {
        fprintf(PVT_G(log_file_path), "<td></td>");
    }

    op_op1 = format_znode(&opi->op1, base_address);
    fprintf(PVT_G(log_file_path),
        "<td>%s</td>", op_op1
    );

    if (op_op1) {
        efree(op_op1);
    }

    op_op2 = format_znode(&opi->op2, base_address);
    fprintf(PVT_G(log_file_path),
        "<td>%s</td></tr>\n", op_op2
    );
    if (op_op2) {
        efree(op_op2);
    }
}
/* }}} */


void dump_opcode(char *func_name, char *file_name, zend_op_array *op_array TSRMLS_DC)
{
    int i;
    size_t ret_len;
    char *log_filename = NULL;
    char *ret = NULL;
    char *tmp_time = pvt_get_time();

    if (op_array == 0) {
        return;
    }

    zend_uint base_address = (zend_uintptr_t) &(op_array->opcodes[0]);

    if (file_name == NULL) {
        spprintf(&file_name, 0, "%s", "none");
    }

#ifdef ZEND_ENGINE_2
    php_basename(file_name, strlen(file_name), NULL, 0, &ret, &ret_len TSRMLS_CC);
#else
    ret = php_basename(file_name, strlen(file_name), "", 0);
    ret_len = strlen(ret);
#endif

    pvt_normalize_str(ret);
    spprintf(&log_filename, 0, "%s/opcodes/t-%s-%s.html", PVT_G(log_folder), ret, func_name);
    PVT_G(log_file_path) = fopen(log_filename, "w");

    efree(ret);

    if (!PVT_G(log_file_path)) {
        zend_error(E_ERROR, "PVT: unable to open log file '%s'.", log_filename);
    }

    fprintf(PVT_G(log_file_path), "\
<html>\
<link rel=\"stylesheet\" type=\"text/css\" href=\"%s/design/main.css\"/>\
<body>\
<div class=\"logo\">PVT - PHP Vulnerability Tracer</div>\
", PVT_G(pvt_log_file));

    fprintf(PVT_G(log_file_path), "<h3>File: '%s'</h3>\
<h3>Function: %s()</h3>\
<h3>Time: %s</h3>", file_name, func_name, tmp_time);

    fprintf(PVT_G(log_file_path), "\
<table>\
<tr id=\"m\">\
<td class=\"w20\">Op num</td><td>Line</td><td>Opcode</td><td>Result</td><td>OP 1</td><td>OP 2</td></tr>\
");

    for (i = 0; i < op_array->last; i++) {
        dump_op(op_array, &op_array->opcodes[i], i, base_address);
    }

    fprintf(PVT_G(log_file_path), "</table></body></html>\n");
    fclose(PVT_G(log_file_path));

    efree(tmp_time);
    efree(log_filename);
}

