/* $Id: pi.c,v 1.1 2000/05/06 15:51:09 proff Exp $
 * $Copyright:$
 *
 * generate the first 8192 digits of pi. you are not meant to
 * understand this
 */

#include <stdio.h>
int
main()
{
    int a=10000, c=28672, b=c+1, e, f[b], g;
    while (b--)
	f[b]=a/5;
    for (e=0; (g=c*2); c-=14)
	{
	    int d=0, h=c;
	    for (; d+=f[h]*a, f[h]=d%--g, d/=g--, --h; d*=h) ;
	    printf("%.4d", e+d/a);
	    fflush(stdout);
	    e=d%a;
	}
    exit(0);
}
