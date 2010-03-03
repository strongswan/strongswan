/* stuff defined in AndroidConfig.h, which is included using the -include
 * command-line option, thus cannot be undefined using -U CFLAGS options.
 * the reason we have to undefine these flags in the first place, is that
 * AndroidConfig.h defines them as 0, which in turn means that they are
 * actually defined. */

#undef HAVE_BACKTRACE
#undef HAVE_DLADDR

