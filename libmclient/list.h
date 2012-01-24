/* $Id: list.h,v 1.2 2000/04/23 14:52:27 proff Exp $
 * $Copyright: $
 */
#ifndef LIST_H
#define LIST_H

#ifndef LIST_ALLOC
#  define LIST_ALLOC(size) (maruMalloc(size))
#endif

/* l = list, e = element, t = type */

struct list
{
    struct list *next;
    struct list *prev;
};

#define LIST_NEW(t) ((typeof(t)*)LIST_ALLOC(sizeof (t)))
#define LIST_INIT(l) ((l)->next = (l)->prev = (l))
#define LIST_FIRST(l) ((l)->next)
#define LIST_PREV(e) ((e)->prev)
#define LIST_NEXT(e) ((e)->next)
#define LIST_LAST(l) ((l)->prev)
#define LIST_EMPTY(l) ((l)->prev == (l)->next)
#define LIST_INSERT_AFTER_UNSAFE(l, e) (e->prev = l, e->next=l->next, l->next->prev=e, l->next=e)
#define LIST_INSERT_AFTER(ll, ee) do {\
	typeof(ee) e = (ee);\
        typeof(ll) l = (ll);\
	LIST_INSERT_AFTER_UNSAFE(l, e);\
	} while (0)
#define LIST_INSERT_BEFORE_UNSAFE(l, e) (e->next = l, e->prev=l->prev, l->prev->next=e, l->prev=e)
#define LIST_INSERT_BEFORE(ll, ee) do {\
	typeof(ee) e = (ee);\
        typeof(ll) l = (ll);\
	LIST_INSERT_BEFORE_UNSAFE(l, e);\
	} while (0)
#define LIST_INSERT_TAIL(l, e) LIST_INSERT_BEFORE((l), (e))
#define LIST_INSERT_HEAD(l, e) LIST_INSERT_AFTER((l), (e))
#define LIST_DEL_UNSAFE(e) (e->prev->next = e->next, e->next->prev = e->prev)
#define LIST_DEL(ee) do {\
	typeof(ee) e = (ee);\
	LIST_DEL_UNSAFE(e);\
	} while (0)
#define LIST_FOREACH(l, e) for ((e)=(l)->next; (e)!=(l); (e) = (e)->next)
#define LIST_FOREACH_REV(l, e) for ((e)=(l)->prev; (e)!=(l); (e) = (e)->prev)
#define LIST_FOREACH_DEL(l, e) for (; (l)->prev != (l) && ((e) = (l)->prev) && LIST_DEL_UNSAFE(e);)
#define LIST_FIND(l, e) ((typeof(e))listFind((l), (e)))

#include "list.ext"

#endif /* LIST_H */
