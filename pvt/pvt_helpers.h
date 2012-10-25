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

#ifndef PVT_HELPERS
#define PVT_HELPERS

char *pvt_get_time(void);
char *pvt_memnstr(char *haystack, char *needle, int needle_len, char *end);
char *pvt_sprintf_real(const char* fmt, va_list args);
double pvt_get_utime(void);
void pvt_fprintf(const char* fmt, ...);
char *pvt_sprintf(char* fmt, ...);
char *pvt_substr(int start, int end, char *source);
char *pvt_memnstr(char *haystack, char *needle, int needle_len, char *end);
void pvt_explode(char *delim, char *str, pvt_arg *args, int limit);
char *str_repeat(const char *input_str, int len);

#endif
