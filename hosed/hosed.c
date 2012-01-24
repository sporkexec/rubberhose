#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

/* unistd.h must be included first */
#ifdef _POSIX_PRIORITY_SCHEDULING
#include <sched.h>
#endif

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#define HOSED_C

#include <libproff.h>

#include "maru.h"
#include "encoding.h"
#include "kue-api.h"
#include "mkern-api.h"
#include "maru_bsd_ioctl.h"
#include "libmclient.h"
#include "hosed.h"
#include "assert.h"
#include "remappers.h"
#include "ipc_commands.h"
#include "libmclient/block.h"
#include "block.h"			/* XXX rename me  */

#define MAX_STRINGBUF_SIZE		4096
#define MAX_ASPECTS			16
#define KUE_MAX_DEVICES			16

static hosed_context  hosed_contexts[HOSED_CONTEXTS_MAX];
static maruInstance  *hosed_instance = NULL;
static maruKeymap    *hosed_keymap = NULL;
static char          *hosed_socket_path = "/tmp/maru-test-sock";
static int            hosed_sock;

/* detach extents after 30 minutes of idle time. adjust if needed. */
static unsigned long  hosed_idle_detach_timer = 1800;
/* default time to live for attached extents is 48 hours. adjust value if needed */
static unsigned long  hosed_ttl_detach_timer  = 172800;

static int            debug_level = 0;
static int            kue_fd = -1;

static char           errbuf[MAX_STRINGBUF_SIZE];
static char           msgbuf[MAX_STRINGBUF_SIZE];

#define SUCCESS(args...)	do \
                        { \
			    snprintf(msgbuf, sizeof msgbuf, ##args); \
			    return TRUE; \
                        } while(0)

#define FAILURE(args...)	do \
                        { \
			    snprintf(errbuf, sizeof errbuf, ##args); \
			    return FALSE; \
                        } while(0)

#define FAILUREX(args...)	do \
		        { \
			    char s[MAX_STRINGBUF_SIZE]; \
			    snprintf(s, sizeof s, ##args); \
			    snprintf(errbuf, sizeof errbuf, "%s: %s", s, strerror(errno)); \
                            return FALSE; \
                        } while(0)

static bool
destroy_unix_socket(char *sname)
{
    int sock;
    struct sockaddr_un uns;
    bool ret;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	perror("socket");
	return FALSE;
    }

    memset(&uns, 0, sizeof(struct sockaddr_un));
    uns.sun_family = AF_UNIX;
    strncpy(uns.sun_path, sname, sizeof(uns.sun_path));

    /* test whether there is someone listening on this socket */
    if (connect(sock, (struct sockaddr *)&uns, sizeof(struct sockaddr_un)) == 0)
	ret = FALSE;
    else
	{
	    /* ok. it's dead. remove it */
	    struct stat st;
	    if (stat(sname, &st) == 0)
		{
		    if (unlink(sname) == 0)
			ret = TRUE;
		    else
			ret = FALSE;
		}
	    else
		ret = TRUE;
	}		

    close(sock);

    return ret;
}

/* create a listening AF_UNIX socket */
static int
create_unix_socket(char *sname)
{
    int sock;
    struct sockaddr_un uns;

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
	    perror("socket");
	    return -1;
	}
    
    memset(&uns, 0, sizeof(struct sockaddr_un));
    uns.sun_family = AF_UNIX;
    strncpy(uns.sun_path, sname, sizeof(uns.sun_path));

    if (bind(sock, (struct sockaddr *)&uns, sizeof(struct sockaddr_un)) < 0)
	{
	    /* save error number */
	    int saved_errno = errno;

	    if (destroy_unix_socket(sname))
		{
		    /* errno is never set to zero by any library function */
		    if (bind(sock, (struct sockaddr *)&uns, sizeof(struct sockaddr_un)) >= 0)
			errno = 0;
		}
	    else
		errno = saved_errno;

	    if (errno)
		{
		    perror("bind");
		    return -1;
		}
	}
    Iam1970(sname);
    if (chmod(sname, 0700) < 0)
	{
	    perror("chmod");
	    close(sock);
	}
    else if (listen(sock, 5) < 0)
	{
	    perror("listen");
	    close(sock);
	}
    else
	{
	    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0)
		warn("fcntl(%d, O_NONBLOCK)", sock);
	    if (fcntl(sock, F_SETFL, O_NDELAY) < 0)
		warn("fcntl(%d, O_NDELAY)", sock);
	    
	    /* everything went fine */
	    return sock;
	}

    return -1;
}

/* search for unused context */
inline static hosed_context *get_free_context()
{
    int i;

    for(i = 0; i < HOSED_CONTEXTS_MAX; i++)
	{
	    if (!hosed_contexts[i].in_use)
		return &hosed_contexts[i];
	}

    return NULL;
}

static bool hosed_power_detach()
{
    int arg = 0;

    if (ioctl(kue_fd, MARUIOCUNBIND, &arg) < 0)
	FAILUREX("power detach failed: ioctl(MARUIOCUNBIND, %p)", &arg);
    else
	SUCCESS("Power was detach successful.");
}

static bool hosed_test_maru_device(int fd)
{
    return ioctl(fd, MARUIOCISBOUND) ? FALSE : TRUE;
}

static bool hosed_test_kue_device(int fd)
{
    return TRUE;
}

/* XXX fixme */
static char *hosed_hunt_device(char *prefix, int mode, int num_devices, int *fd,
			       bool (*test_device)(int))
{
    char *dev_string;
    int fd2, i;
    m_u32 offset;

    dev_string = maruCalloc(strlen(prefix) + 11);

    for(i = 0; i < 4 * num_devices; i++)
	{
	    if (i > 3 * num_devices)
		offset = 0;
	    else {
		/* use high-order bits. not very elegant */
		offset = (m_u32) (((m_u64) maruRandom32() * (m_u64) num_devices) / (((m_u64) 1) << 32));
	    }

	    sprintf(dev_string, "%s%u", prefix, (i + offset) % num_devices);
	    if ((fd2 = open(dev_string, mode)) >= 0) {
		Iam1970(dev_string);
		if (!test_device(fd2))
		    {
			close(fd2);
			continue;
		    }
		*fd = fd2;
		return dev_string;
	    }
	}
    maruFree(dev_string);
    return NULL;
}

static bool
hosed_dekey_aspect(int aspect_num)
{
    if (hosed_instance->aspect[aspect_num] != NULL) {
	freeAspect(hosed_instance->aspect[aspect_num]);
	hosed_instance->aspect[aspect_num] = NULL;
	SUCCESS("Keying data for aspect %d has been wiped from memory at your request.", aspect_num);
    }

    FAILURE("Aspect %d is not keyed.", aspect_num);
}

static bool
hosed_key_aspect(int aspect_num, maruPass *pass)
{
    maruAspect *a = NULL;

    if (!(a = buildAspect(hosed_instance, getKeymapAspect(hosed_instance, hosed_keymap, aspect_num), aspect_num,
			  pass, strlen(pass->data))))
	FAILURE("Passphrase for aspect %d is invalid.", aspect_num);
    hosed_instance->aspect[aspect_num] = a;

    SUCCESS("Aspect %d keyed.", aspect_num);
}

static bool
hosed_bind_aspect(int aspect_num)
{
    struct maru_ioc_attach attach;

    hosed_context *ctx;
    char *aspect_device = NULL;
    int i, result;

    for(i = 0; i < HOSED_CONTEXTS_MAX; i++)
	if (hosed_contexts[i].in_use && hosed_contexts[i].aspect_num == aspect_num)
	    FAILURE("Aspect is already visible on device %s.", hosed_contexts[i].maru_device_path);

    if (hosed_instance->aspect[aspect_num] == NULL)
	FAILURE("Aspect has not been keyed yet.");
    
    if ((ctx = get_free_context()) == NULL)
	FAILURE("Cannot get free context.");

    /* we only need read access for ioctls */
    if ((aspect_device = hosed_hunt_device("/dev/maru", O_RDONLY, MAX_ASPECTS, &ctx->aspect_fd,
					   hosed_test_maru_device)) == NULL)
	FAILURE("Unable to find unused aspect device.");

    memset(&attach, 0, sizeof attach);
    attach.ma_size   = hosed_instance->extent_size;
    attach.ma_kue_fd = kue_fd;
    attach.ma_aspect = aspect_num;

    if (ioctl(ctx->aspect_fd, MARUIOCBIND, &attach) < 0)
	{
	    sprintf(errbuf, "Binding aspect %d to device %s failed.", aspect_num, aspect_device);
	    goto err_out;
	}

    ctx->aspect_num = aspect_num;
    ctx->maru_device_path = aspect_device;
    ctx->in_use = TRUE;
    
    sprintf(msgbuf, "Aspect %d is now visible on device %s.", aspect_num, aspect_device);

    result = maru_set_blocksize(ctx->aspect_fd, hosed_instance->blockSize);
    if (result >= 0)
	return TRUE;
    else
	{
	    strcat(msgbuf, "\nUnable to set block size however.");
	    return FALSE;
	}

 err_out:
    if (aspect_device)
	maruFree(aspect_device);
    return FALSE;
}

static bool
hosed_unbind_aspect(int aspect_num, int force)
{
    int i;

    for(i = 0; i < HOSED_CONTEXTS_MAX; i++)
	{
	    if (!hosed_contexts[i].in_use || hosed_contexts[i].aspect_num != aspect_num)
		continue;

	    if (ioctl(hosed_contexts[i].aspect_fd, MARUIOCUNBIND, force) < 0)
		FAILUREX("ioctl(MARUIOCUNBIND)");

	    close(hosed_contexts[i].aspect_fd);
	    if (hosed_contexts[i].maru_device_path)
		maruFree(hosed_contexts[i].maru_device_path);
	    memset(&hosed_contexts[i], 0, sizeof(hosed_context));
	    hosed_contexts[i].in_use = FALSE;
	    syncInstance(hosed_instance);
	    SUCCESS("Aspect %d has been unbound.", aspect_num);
	}
    FAILURE("Aspect %d is not visible.", aspect_num);
}

static bool
hosed_attach_extent(char *maru_device, char *fname_extent,
		    char *keymap_file, int aspect_bsize, maruRemapFlags remap_flags)
{
    struct stat st;
    int klen;

    hosed_keymap = loadKeymap(keymap_file, &klen);
    if (hosed_keymap == NULL) 
	{
	err_keymap:
	    FAILUREX("Could not open maru keymap file");
	}

    hosed_instance = instanceNew(hosed_keymap, klen, remap_flags);

    if (hosed_instance == NULL) 
	FAILURE("Internal error: creation of instance failed.");

    if ((hosed_instance->keymap_fd = open(keymap_file, O_WRONLY)) < 0)
	goto err_keymap;

    if ((hosed_instance->extent_fd = open(fname_extent, O_RDWR)) < 0) 
	FAILUREX("Could not open extent file %.1024s", fname_extent);

    if (fstat(hosed_instance->extent_fd, &st) != 0)
	FAILUREX("Could not stat extent file %.1024s", fname_extent);
    
    hosed_instance->extent_size = st.st_size;
    hosed_instance->extent_pos = (m_u64) 0;
    hosed_instance->blockSize = aspect_bsize;

    sprintf(msgbuf, "Attach of %.1024s was successful.\n" \
	    "Block size is %d bytes, extent is a total of %qu bytes in size.", fname_extent,
	    aspect_bsize, (m_u64) st.st_size);
    if(((m_u64) st.st_size) % ((m_u64) aspect_bsize)) 
	{
	    strcat(msgbuf, "\nWarning: extent size is not an integer multiple of the block size !");
	}

    return TRUE;
}

static bool
hosed_detach_extent(bool force)
{
    int i;

    for (i = 0; i < HOSED_CONTEXTS_MAX; i++)
	{
	    if (hosed_contexts[i].in_use)
		{
		    if (force)
			hosed_unbind_aspect(hosed_contexts[i].aspect_num, force);
		    else
			FAILURE("Detach failed, reason: aspect %d is still visible.", hosed_contexts[i].aspect_num);
		}
	}

    if (hosed_instance)
	{
	    freeInstance(hosed_instance);
	    fsync(hosed_instance->extent_fd);
	    close(hosed_instance->extent_fd);
	    hosed_instance = NULL;
	}
    SUCCESS("Detach was successful.");
}

static bool
hosed_sync()
{
    if (hosed_instance)
	{
	    syncInstance(hosed_instance);
	    fsync(hosed_instance->extent_fd);
	    SUCCESS("Sync was successful.");
	}
    SUCCESS("Nothing to sync.");
}

/* not re-entrant */
static bool
process_control_message(void *msg, int msg_len, char **msgreplyptr, int *replylen)
{
    int msg_cmd;
    char *data = msg;
    int len = msg_len, maxlen = MAX_STRINGBUF_SIZE;
    bool result = FALSE;
    static char msgreply[MAX_STRINGBUF_SIZE + 16];

    DECODE(int, &msg_cmd);
    
    /* clear error and message buffers */
    *msgbuf = 0;
    *errbuf = 0;

    switch(msg_cmd) {
    case MARUCMD_ATTACH_EXTENT:
	{
	    char *extent_fname, *keymap_file, *maru_device;
	    int aspect_bsize;
	    maruRemapFlags remap_flags;

	    if (hosed_instance != NULL)
		{
		    sprintf(errbuf, "Extent already attached.");
		    break;
		}
	    DECODE(string, &maru_device);
	    DECODE(string, &extent_fname);
	    DECODE(string, &keymap_file);
	    DECODE(int, &aspect_bsize);
	    DECODE(int, &remap_flags);
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARUCMD_ATTACH_EXTENT)", msg_cmd);
	    MDEBUG(2, "DEBUG: maru_device = %s, extent_fname = %s, "
		   "keymap_file = %s, aspect_bsize = %d", maru_device, extent_fname, 
		   keymap_file, aspect_bsize);
	    result = hosed_attach_extent(maru_device, extent_fname,
					 keymap_file, aspect_bsize, remap_flags);
	    break;
	}

    case MARUCMD_BIND_ASPECT:
	{
	    int aspect_num;

	    DECODE(int, &aspect_num);
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARUCMD_BIND_ASPECT)", msg_cmd);
	    if (hosed_instance == NULL)
		{
		    sprintf(errbuf, "No extent attached yet.");
		    break;
		}
	    result = hosed_bind_aspect(aspect_num);
	    break;
	}

    case MARUCMD_DEKEY_ASPECT:
	{
	    int aspect_num;
	    
	    DECODE(int, &aspect_num);
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARUCMD_DEKEY_ASPECT)", msg_cmd);
	    MDEBUG(3, "DEBUG: aspect_num = %d", aspect_num);
	    result = hosed_dekey_aspect(aspect_num);
	    break;
	}

    case MARUCMD_DETACH_EXTENT:
	{
	    int force;

	    DECODE(int, &force);
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARUCMD_DETACH_EXTENT)", msg_cmd);
	    MDEBUG(2, "DEBUG: force = %d", force);
	    result = hosed_detach_extent(force != 0);
	    break;
	}

    case MARUCMD_GET_PARAMETER:
	{
	    int option;
	    int aspect_num;

	    DECODE(int, &option);
	    DECODE(int, &aspect_num);
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARU_GET_PARAMETER)", msg_cmd);
	    MDEBUG(3, "DEBUG: aspect_num = %d", aspect_num);
	    switch(option)
		{
		case PARAM_IDLE_DETACH:
		    break;
		case PARAM_TTL_DETACH:
		    break;
		case PARAM_EMERGENCY_KEY:
		    break;
		}
	    break;
	}

    case MARUCMD_KEY_ASPECT:
	{
	    int aspect_num;
	    maruPass *pass;

	    DECODE(int, &aspect_num);
	    DECODE_RAW((void **) &pass);
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARUCMD_KEY_ASPECT)", msg_cmd);
	    MDEBUG(3, "DEBUG: aspect_num = %d, passphrase = %s", aspect_num, pass->data);
	    if (hosed_instance == NULL)
		{
		    sprintf(errbuf, "No extent attached yet.");
		    break;
		}
	    result = hosed_key_aspect(aspect_num, pass);
	    break;
	}

    case MARUCMD_SET_PARAMETER:
	{
	    int option;
	    int aspect;

	    DECODE(int, &option);
	    DECODE(int, &aspect);

	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARU_SET_PARAMETER)", msg_cmd);
	    switch(option)
		{
#if 0
		case PARAM_IDLE_DETACH:

		    hosed_set_timer();

		    break;
		case PARAM_TTL_DETACH:

		    hosed_set_timer();

		    break;
		case PARAM_EMERGENCY_KEY:
		    break;
#endif
		default:
		    break;
		}
	    break;
	}

    case MARUCMD_TERMINATE_DAEMON:
	{
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARUCMD_TERMINATE_DAEMON)", msg_cmd);
	    result = hosed_detach_extent(TRUE);
	    if (!result)
		hosed_power_detach();
	    exit(0);
	}

    case MARUCMD_SYNC:
	{
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARUCMD_SYNC)", msg_cmd);
	    result = hosed_sync();
	    break;
	}

    case MARUCMD_UNBIND_ASPECT:
	{
	    int aspect_num;
	    
	    DECODE(int, &aspect_num);
	    MDEBUG(2, "DEBUG: msg_cmd = %d (MARUCMD_UNBIND_ASPECT)", msg_cmd);
	    MDEBUG(3, "DEBUG: aspect_num = %d", aspect_num);
	    result = hosed_unbind_aspect(aspect_num, 0);
	    break;
	}
    }

    len = 0;
    data = msgreply;

    ENCODE(int, result);
    if (result) {
	MDEBUG(2, "DEBUG: result = %d, msgbuf = %s", result, msgbuf);
	ENCODE(string, msgbuf);
    } else {
	MDEBUG(2, "DEBUG: result = %d, errbuf = %s", result, errbuf);
	ENCODE(string, errbuf);
    }

    *msgreplyptr = msgreply;
    *replylen = data - msgreply;
    return result;
}

static int process_maru_message(struct maru_message *maru_msg)
{
    struct kue_message  *kue_msg_reply;
    struct maru_message *maru_msg_reply;
    char tokenbuf[HOSED_BUFFER_SIZE];
    m_u32 len = 0;
    int aspect;

    kue_msg_reply  = (struct kue_message *)   tokenbuf;
    maru_msg_reply = (struct maru_message *) (tokenbuf + KUE_HLEN);

    MDEBUG(1, "process_maru_message(): maru_msg = %p, mm_offset = %qd, mm_len = %u, "
	      "mm_flags = %u, mm_aspect = %u", maru_msg, maru_msg->mm_offset,
	   maru_msg->mm_len, maru_msg->mm_flags, maru_msg->mm_aspect);

    kue_msg_reply->km_len = MARU_HLEN;
    memcpy(maru_msg_reply, maru_msg, MARU_HLEN);

    aspect = maru_msg->mm_aspect;

    if (aspect < 0 || aspect > hosed_instance->aspects ||
	hosed_instance->aspect[aspect] == NULL)
	{
	    sprintf(errbuf, "Aspect %d is invalid", aspect);
	    warnx(errbuf);
	    maru_msg_reply->mm_flags = MARU_ERROR;
	    len = KUE_HLEN + MARU_HLEN;
	}

    if (maru_msg->mm_flags & MARU_WRITE)
	{
	    len = maru_handle_chunk((char *) maru_msg + MARU_HLEN,
				    maru_msg->mm_offset, maru_msg->mm_len,
				    MR_WRITE, hosed_instance->aspect[aspect]);
	    if (len < 0) 
		maru_msg_reply->mm_flags = MARU_ERROR;
	    else
		maru_msg_reply->mm_flags = 0;
	    
	    len = KUE_HLEN + MARU_HLEN;
	}

    if (maru_msg->mm_flags & MARU_READ_REQ)
	{
	    len = maru_handle_chunk((char *) maru_msg_reply + MARU_HLEN,
				    maru_msg->mm_offset, maru_msg->mm_len,
				    MR_READ, hosed_instance->aspect[aspect]);
	    if (len < 0) {
		maru_msg_reply->mm_flags = MARU_ERROR;
		len = KUE_HLEN + MARU_HLEN;
	    }
	    else 
		{
		    maru_msg_reply->mm_flags &= MARU_READ_REQ;
		    maru_msg_reply->mm_flags |= MARU_READ;
		    len += KUE_HLEN + MARU_HLEN;
		}
	}

    kue_msg_reply->km_len = len - KUE_HLEN;

    /* we should actually call maruFatal here */
    if (write(kue_fd, tokenbuf, len) != len)
	err(1, "write to kue device failed");

    /* XXX */
    return 0;
}

#define KUE_MESSAGE_SIZE_MAX		16384

static int process_kue_request()
{
    static char buf[KUE_MESSAGE_SIZE_MAX];
    char *ptr;
    int len;

    if ((len = read(kue_fd, buf, sizeof(buf))) <= 0)
	{
	    warn("error occured while reading from fd %d", kue_fd);
	    return -1;
	}

    MDEBUG(1, "process_kue_request(), len = %d", len);

    if (len < KUE_HLEN)
	{
	    warnx("message too short (%d)", len);
	    return -1;
	}

    ptr = buf;

    while(ptr < buf + len)
	{
	    if (process_maru_message((struct maru_message *) (ptr + KUE_HLEN)) < 0)
		return -1;
	    
	    ptr += KUE_HLEN + ((struct kue_message *) ptr)->km_len;
	}
    return 0;
}

static void hosed_main_loop()
{
    char ctlbuf[HOSED_MESSAGE_SIZE_MAX];
    int max_fd = (hosed_sock > kue_fd) ? hosed_sock : kue_fd;
    int result, len, i;
    int connections[HOSED_CONNECTIONS_MAX];
    fd_set read_fds;

    for(i = 0; i < HOSED_CONNECTIONS_MAX; connections[i++] = -1);

    FD_ZERO(&read_fds);
    FD_SET(kue_fd, &read_fds);
    FD_SET(hosed_sock, &read_fds);
    for(i = 0; i < HOSED_CONNECTIONS_MAX; i++)
	{
	    if (connections[i] >= 0)
		FD_SET(connections[i], &read_fds);
	}

    /* todo:
     * use a seperate fd_set for write request and split the whole loop up
     * so that it operates on two queues, one for read one for write requests.
     */
    while((result = select(max_fd + 1, &read_fds, NULL, NULL, NULL)) > 0 ||
	  errno == EINTR)
	{
	    if (result && FD_ISSET(kue_fd, &read_fds))
		{
		    process_kue_request();
		    result--;
		}

	    if (result && FD_ISSET(hosed_sock, &read_fds))
		{
		    int connected_sock;
		    int sunlen = sizeof(struct sockaddr_un);
		    struct sockaddr_un sun;

		    if ((connected_sock = accept(hosed_sock, (struct sockaddr *) &sun, &sunlen)) < 0)
			warn("accept");
		    else {
			if (connected_sock > max_fd)
			    max_fd = connected_sock;

			for(i = 0; i < HOSED_CONNECTIONS_MAX; i++)
			    {
				connections[i] = connected_sock;
				break;
			    }

			if (i == HOSED_CONNECTIONS_MAX)
			    {
				shutdown(connected_sock, 2);
				close(connected_sock);
			    }
		    }
		}

	    if (result) {
		for(i = 0; i < HOSED_CONNECTIONS_MAX; i++) {
		    if (connections[i] > 0 && FD_ISSET(connections[i], &read_fds)) {
			len = read(connections[i], ctlbuf, sizeof(ctlbuf));

			if (len <= 0)
			    {
				shutdown(connections[i], 2);
				close(connections[i]);
				connections[i] = -1;
				continue;
			    }

			if (len < HOSED_MESSAGE_SIZE_MIN)
			    warn("message too short, discarding (length = %d)", len);
			else
			    {
				char *msgreply = NULL;
				int replylen = 0 ;

				/* XXX this isn't implemented very cleanly... */
				process_control_message(ctlbuf, len, &msgreply, &replylen);

				if (replylen && msgreply)
				    write(connections[i], msgreply, replylen);
			    }
		    }
		    result--;
		}
	    }

	    FD_ZERO(&read_fds);
	    FD_SET(kue_fd, &read_fds);
	    FD_SET(hosed_sock, &read_fds);
	    for(i = 0; i < HOSED_CONNECTIONS_MAX; i++)
		{
		    if (connections[i] >= 0)
			FD_SET(connections[i], &read_fds);
		}
	}
    err(1, "main loop exited unexpectedly.");
}

static void usage() {
    fprintf(stderr, "Usage: hosed [OPTION]...\n");
    fprintf(stderr, "Start the marutukku hose daemon.\n\n");
    fprintf(stderr, "-d <level>    set debug level\n");
    fprintf(stderr, "-f            don't go into background mode\n");
    fprintf(stderr, "-s <path>     path for AF_UNIX socket (used for communication with hose)\n");
#ifdef _POSIX_PRIORITY_SCHEDULING 
    fprintf(stderr, "-R            turn on real-time scheduling\n");
#else
    fprintf(stderr, "-R            turn on real-time scheduling (ignored)\n");
#endif
}

NORETURN static void
hosed_exit_handler()
{
    unlink(hosed_socket_path);
    if (stackP)
        {
            freeWipeList(FALSE);
            wipeStackExit();
        }
    _exit(1);
}

void hosed_signal_handler(int sig)
{
    switch(sig)
	{
	case SIGTERM:
	    if (!hosed_detach_extent(TRUE) && !hosed_power_detach())
		exit(1);
	    exit(0);
	case SIGALRM:
	    break;
	}
}

#ifdef _POSIX_PRIORITY_SCHEDULING

#define SCHED_DEFAULT_SCHEDULER		SCHED_FIFO
#define SCHED_PRIORITY_DEFAULT		50

static bool
toggle_rt_scheduling(bool enabled)
{
    static bool state_saved = FALSE;
    static struct sched_param saved_param;
    static int saved_scheduler;
    struct sched_param param;
    int mypid = getpid();

    if (enabled) 
	{
	    if (!state_saved)
		{
		    sched_getparam(mypid, &saved_param);
		    saved_scheduler = sched_getscheduler(mypid);
		    state_saved = TRUE;
		}
	    param.sched_priority = SCHED_PRIORITY_DEFAULT;
	    if (sched_setscheduler(mypid, SCHED_FIFO, &saved_param) < 0)
		FAILUREX("Could not set real time scheduling policy");
	}
    else
	{
	    if (!state_saved) 
		FAILUREX("Could not restore previous state");
	    if (sched_setscheduler(mypid, saved_scheduler, &saved_param) < 0) 
		FAILUREX("Could restore orignal scheduling policy:");
	}

    SUCCESS("Real time scheduling policy turned %s", enabled ? "on" : "off");
}

#endif

int
main(int argc, char **argv)
{
    volatile char marker = 0;
    int ch;
    int foreground      = 0;
    int real_time_sched   = 0;
    char *kue_name;

    while((ch = getopt(argc, argv, "d:fRs:")) != -1)
	{
	    switch(ch) {
	    case 'd':
		debug_level = atoi(optarg);
		break;
	    case 'f':
		foreground = 1;
		break;
	    case 'R':
		real_time_sched = 1;
		break;
	    case 's':
		hosed_socket_path = optarg;
		break;
	    default:
		usage();
		exit(0);
	    }
	}

    lockAllMem(); /* XXX check return code */

#ifdef _POSIX_PRIORITY_SCHEDULING
    if (real_time_sched && !toggle_rt_scheduling(TRUE))
	warnx(errbuf);
#endif /* _POSIX_PRIORITY_SCHEDULING */

    kue_name = hosed_hunt_device("/dev/kue", O_RDWR | O_EXCL, KUE_MAX_DEVICES, &kue_fd,
			       hosed_test_kue_device);

    setuid(getuid());

    if (!debug_level)
	{
	    nocore();
	    nosignals();
	    atexit(hosed_exit_handler);
	}

    signal(SIGTERM, hosed_signal_handler);

    memset(hosed_contexts, 0, sizeof(hosed_context) * HOSED_CONTEXTS_MAX);

    /* create a unix socket for communication with hose */
    if((hosed_sock = create_unix_socket(hosed_socket_path)) < 0)
	{
	    errx(1, "could not create socket for communicating with hose.\n");
	}

    if (kue_name == NULL)
	{
	    errx(1, "could not find any kue devices that can be accessed.");
	}
    else
	{
	    char *ptr;

	    /* 
	     * we are avoiding strdup() on purpose. memory allocated by maruCalloc() gets
	     * wiped and free'd upon program termination without any extra effort.
	     */
	    ptr = maruCalloc(strlen(kue_name) + 1);
	    strcpy(ptr, kue_name);
	    kue_name = ptr;
	}

    /* don't chdir here */
    if (!foreground)
	daemon(1, 0);

#if 0
    {
	struct itimerval intervall = { 10, 0 };
	
	setitimer(ITIMER_REAL, intervall, NULL);
	signal(SIGALRM, hosed_signal_handler);
    }
#endif

    /* stack protection */
    stackP = &marker;
    hosed_main_loop(hosed_sock);
    NOTREACHED;
}
