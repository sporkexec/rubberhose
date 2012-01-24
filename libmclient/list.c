#include "maru_types.h"

#include "list.h"

EXPORT struct list *listFind(void *vl, void *ve)
{
    struct list *l = vl, 
                *e = ve,
                *p;
    LIST_FOREACH(l, p)
        if (p == e)
	    return p;
    return NULL;
}

struct sl
{
    struct sl *next, *prev;
    char *data;
};
