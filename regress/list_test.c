#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#define LIST_ALLOC malloc

#include "list.h"

struct strl
{
    struct strl *next, *prev;
    char *data;
};

#define a(x) if(!(x)) {warnx("failed assertion(%s)", #x); fails++;}

static struct strl *
strl_new(char *data)
{
    struct strl *sl = LIST_NEW(struct strl);
    sl->data = strdup(data);
    return sl;
}

static void
strl_free(struct strl *sl)
{
    free(sl->data);
    free(sl);
}

static char *
strl_mkstr(struct strl *sl)
{
    struct strl *e;
    char *s;
    int n = 0;
    LIST_FOREACH(sl, e)
	n+=strlen(e->data);
    s = calloc(1, n+1);
    LIST_FOREACH(sl, e)
	strcat(s, e->data);
    return s;
}

static char *Koestler_fatigue_of_the_synapses = "\
I cannot authorise any altered version of my speech.\n\
It has to be transmitted according to the original text.\n\
I shall make you responsible for any deviation from it.\n\
\t-- Arthur Koestler";

int
main()
{
    struct strl *sl = LIST_NEW(struct strl),
                *sl2,
	        *e;
    int fails = 0;
    char *k;
    LIST_INIT(sl);
    a(LIST_EMPTY(sl));
    LIST_INSERT_HEAD(sl, strl_new("It has to be transmitted according"));
    LIST_INSERT_TAIL(sl, (sl2=strl_new(" the original text.\n")));
    LIST_INSERT_HEAD(sl, strl_new("altered version of my speech.\n"));
    LIST_INSERT_TAIL(sl, strl_new("I shall make you responsible for any"));
    LIST_INSERT_BEFORE(sl2, strl_new(" to"));
    LIST_INSERT_BEFORE(LIST_FIRST(sl), strl_new("I cannot authorise"));
    LIST_INSERT_AFTER(LIST_FIRST(sl), strl_new(" any "));
    LIST_INSERT_AFTER(LIST_LAST(sl), strl_new(" deviation from it.\n"));
    a(strcmp(LIST_FIND(sl, sl2)->data, " the original text.\n") == 0);
    LIST_INSERT_AFTER(sl2, strl_new(" Leontiev"));
    LIST_DEL(LIST_NEXT(sl2));
    LIST_INSERT_TAIL(sl, strl_new("\t-- Arthur Koestler"));
    printf("Original:\n%s\n\n", Koestler_fatigue_of_the_synapses);
    printf("List:\n%s\n", (k=strl_mkstr(sl)));
    a(strcmp(k, Koestler_fatigue_of_the_synapses) == 0);
    LIST_FOREACH_DEL(sl, e)
	strl_free(e);
    a(LIST_EMPTY(sl));
    exit(fails>0);
}
