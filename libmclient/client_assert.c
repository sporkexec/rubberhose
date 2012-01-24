#include <stdarg.h>
#include <stdio.h>
#include <err.h>

#include "client_assert.h"

EXPORT void maruFatal(char *fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start (ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    errx(1, buf);
}
