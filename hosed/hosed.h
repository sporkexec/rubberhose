#ifndef HOSED_H
#define HOSED_H

#include "kue-api.h"
#include "mkern-api.h"

#define HOSED_CONNECTIONS_MAX		30

/* minimum size of a hosed message. we expect select() to notify us if
 * that >= HOSED_MESSAGE_SIZE_MIN bytes are ready to be read.
 * this may be too small a value actually. if it is we need to pad the commands
 * in some cases however (recommended size is 16 I think) */
#define HOSED_MESSAGE_SIZE_MIN		(sizeof(int))

/* maximum message size for a hosed message. if message is longer than
 * this, the end will be discarded */
#define HOSED_MESSAGE_SIZE_MAX		512

/* maximum number of contexts */
#define HOSED_CONTEXTS_MAX		64

/* maximum number of kue devices */
#define KUE_DEVICES_MAX			32

/* path/format for the kue devices */
#define KUE_DEVICE_FMT			"/dev/kue%d"

/* size of the buffer hosed uses for read/write requests to/from the kernel */
#define HOSED_BUFFER_SIZE		(MAX_MARU_BLOCK + KUE_HLEN + MARU_HLEN)

typedef struct {
    bool         in_use;
    int		 aspect_fd;
    int          aspect_num;
    char	*maru_device_path;
} hosed_context;

#define MDEBUG(level, fmt...) \
  do { if (debug_level >= level) warnx(## fmt); } while(0)

#endif /* HOSED_H */
