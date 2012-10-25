PHP_ARG_ENABLE(pvt, whether to enable PHP Vulnerability Tracer support,
[  --enable-pvt  Enable PHP Vulnerability Tracer support])

if test "$PHP_PVT" = "yes"; then
  AC_DEFINE(HAVE_PVT, 1, [Whether you have PHP Vulnerability Tracer])
  PHP_NEW_EXTENSION(pvt, pvt.c pvt_helpers.c pvt_trace.c pvt_dumper.c, $ext_shared)
fi 
