#!/bin/sh
cat << EOF
#include <linux/kernel.h>
#include <linux/list.h>
#include "freeswan/ipsec_alg.h"
$(for i in $*; do
	test -z "$i" && continue
	echo "extern int $i(void);"
done)
void ipsec_alg_static_init(void){ 
	int __attribute__ ((unused)) err=0;
$(for i in $*; do
	test -z "$i" && continue
	echo "	if ((err=$i()) < 0)"
	echo "		printk(KERN_WARNING \"$i() returned %d\", err);"
done)
}
EOF
