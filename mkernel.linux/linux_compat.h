#include <linux/version.h>

/* XXX --rpw I know the following is absolute crap. we don't support 2.1.x
 *           development kernels for now. if you are running development
 *           kernels you are on the cutting edge anyway and using 2.3.something
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,0,0)
#error "Jeeez! And I thought my granny looked ancient... upgrade your kernel. now!"
#elsif LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0)
#define LINUX20
#endif

#ifndef LINUX20
#define FINODE(f)	((f)->f_dentry->d_inode)
#else
#define FINODE(f)	((f)->f_inode)
#endif

#ifdef LINUX20
inline int copy_from_user(void *dst, const void *src, unsigned long len)
{
  int err;

  if(err = verify_area(VERIFY_READ, src, len))
    return err;

  memcpy_fromfs(dst, src, len);
  return 0;
}

inline int copy_to_user(void *dst, const void *src, int len)
{
  int err;

  if(err = verify_area(VERIFY_WRITE, dst, len))
    return err;

  memcpy_tofs(dst, src, len);
  return 0;
}
#endif
