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

ZEND_EXTERN_MODULE_GLOBALS(pvt)

char *pvt_get_time(void)
{
    time_t cur_time;
    char *str_time;

    str_time = emalloc(24);
    cur_time = time(NULL);

    strftime(str_time, 24, "%Y-%m-%d_%H:%M:%S", gmtime (&cur_time));

    return str_time;
}

char *pvt_sprintf_real(const char* fmt, va_list args)
{
    char* new_str;
    int size = 1;
#ifdef va_copy
    va_list copy;
#endif
    new_str = (char*) emalloc(size);

    for (;;) {
        int n;
#ifdef va_copy
        va_copy(copy, args);
        n = vsnprintf(new_str, size, fmt, copy);
        va_end(copy);
#else
        n = vsnprintf(new_str, size, fmt, args);
#endif
        if (n > -1 && n < size) {
            break;
        }
        if (n < 0) {
            size *= 2;
        } else {
            size = n+1;
        }
        new_str = (char*) erealloc(new_str, size);
    }

    va_end(args);

    return new_str;
}

double pvt_get_utime(void)
{
#ifdef HAVE_GETTIMEOFDAY
    struct timeval tp;
    long sec = 0L;
    double msec = 0.0;

    if (gettimeofday((struct timeval *) &tp, NULL) == 0) {
        sec = tp.tv_sec;
        msec = (double) (tp.tv_usec / MICRO_IN_SEC);

        if (msec >= 1.0) {
            msec -= (long) msec;
        }
        return msec + sec;
    }
#endif
    return 0;
}

void pvt_fprintf(const char* fmt, ...)
{
    va_list args;
    char* new_str;

    TSRMLS_FETCH();

    va_start(args, fmt);
    new_str = pvt_sprintf_real(fmt, args);
    va_end(args);

    if (PVT_G(trace_file_f)) {
        fprintf(PVT_G(trace_file_f), "%s", new_str);
    }

    efree(new_str);
}

char *pvt_sprintf(char* fmt, ...)
{
    char   *new_str;
    int     size = 1;
    va_list args;

    new_str = (char *) emalloc(size);

    for (;;) {
        int n;

        va_start(args, fmt);
        n = vsnprintf(new_str, size, fmt, args);
        va_end(args);

        if (n > -1 && n < size) {
            break;
        }
        if (n < 0) {
            size *= 2;
        } else {
            size = n + 1;
        }
        new_str = (char *) erealloc(new_str, size);
    }

    return new_str;
}

/* {{{ pvt_substr
 */
char *pvt_substr(int start, int end, char *source)
{
    char *dest = NULL;
    int i, x = 0;

    /* Yeah, not safe */

    if (end - start <= 0) {
        end = start + 1;
    }

    dest = estrdup(source);

    if (start > -1) {
        for (i = start; i < end && source[i] != '\0'; i++, x++) {
            dest[x] = source[i];

        }
        dest[x] = '\0';
        return dest;
    }

    return NULL;
}
/* }}} */

char *pvt_memnstr(char *haystack, char *needle, int needle_len, char *end)
{
    char *p = haystack;
    char first = *needle;

    /* let end point to the last character where needle may start */
    end -= needle_len;

    while (p <= end) {
        while (*p != first) {
            if (++p > end) {
                return NULL;
            }
        }

        if (memcmp(p, needle, needle_len) == 0) {
            return p;
        }
        p++;
    }
    return NULL;
}

void pvt_explode(char *delim, char *str, pvt_arg *args, int limit)
{
    char *p1, *p2, *endp;

    endp = str + strlen(str);

    p1 = str;
    p2 = pvt_memnstr(str, delim, strlen(delim), endp);

    if (p2 == NULL) {
        args->c++;
        args->args = (char**) realloc(args->args, sizeof(char*) * args->c);
        args->args[args->c - 1] = (char*) malloc(strlen(str) + 1);
        memcpy(args->args[args->c - 1], p1, strlen(str));
        args->args[args->c - 1][strlen(str)] = '\0';
    } else {
        do {
            args->c++;
            args->args = (char**) realloc(args->args, sizeof(char*) * args->c);
            args->args[args->c - 1] = (char*) malloc(p2 - p1 + 1);
            memcpy(args->args[args->c - 1], p1, p2 - p1);
            args->args[args->c - 1][p2 - p1] = '\0';
            p1 = p2 + strlen(delim);
        } while ((p2 = pvt_memnstr(p1, delim, strlen(delim), endp)) != NULL && (limit == -1 || --limit > 1));

        if (p1 <= endp) {
            args->c++;
            args->args = (char**) realloc(args->args, sizeof(char*) * args->c);
            args->args[args->c - 1] = (char*) malloc(endp - p1 + 1);
            memcpy(args->args[args->c - 1], p1, endp - p1);
            args->args[args->c - 1][endp - p1] = '\0';
        }
    }
}

char *str_repeat(const char *input_str, int len)
{
    char *result;
    size_t result_len;

    if (input_str == NULL)
        return NULL;
    if (len <= 0)
        return "";

    result_len = strlen(input_str) * len;
    result = (char *)safe_emalloc(strlen(input_str), len, 1);

    /* Heavy optimization for situations where input string is 1 byte long */
    if (strlen(input_str) == 1) {
        memset(result, *(input_str), len);
    } else {
        char *s, *e, *ee;
        int l=0;
        memcpy(result, input_str, strlen(input_str));
        s = result;
        e = result + strlen(input_str);
        ee = result + result_len;

        while (e<ee) {
            l = (e-s) < (ee-e) ? (e-s) : (ee-e);
            memmove(e, s, l);
            e += l;
        }
    }

    result[result_len] = '\0';
    return result;
}

void *pvt_normalize_str(char *input_str)
{
    static char from[] = " \n\r";
    php_strtr(input_str, strlen(input_str), from, "_", strlen(input_str));
}

