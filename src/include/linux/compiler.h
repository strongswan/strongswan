#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H

#ifndef __ASSEMBLY__

#ifdef __CHECKER__
# define __user		__attribute__((noderef, address_space(1)))
# define __kernel	/* default address space */
# define __safe		__attribute__((safe))
# define __force	__attribute__((force))
# define __nocast	__attribute__((nocast))
# define __iomem	__attribute__((noderef, address_space(2)))
# define __acquires(x)	__attribute__((context(0,1)))
# define __releases(x)	__attribute__((context(1,0)))
# define __acquire(x)	__context__(1)
# define __release(x)	__context__(-1)
# define __cond_lock(x)	((x) ? ({ __context__(1); 1; }) : 0)
extern void __chk_user_ptr(void __user *);
extern void __chk_io_ptr(void __iomem *);
#else
# define __user
# define __kernel
# define __safe
# define __force
# define __nocast
# define __iomem
# define __chk_user_ptr(x) (void)0
# define __chk_io_ptr(x) (void)0
# define __acquires(x)
# define __releases(x)
# define __acquire(x) (void)0
# define __release(x) (void)0
# define __cond_lock(x) (x)
#endif

#endif /* __ASSEMBLY__ */

#endif /* __LINUX_COMPILER_H */
