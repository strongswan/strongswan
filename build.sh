#source /opt/xilinx_linux_gnu/environment-setup-zynq-arch-linux-gnu

export LD_LIBRARY_PATH=/ipsec/lib
export PKG_CONFIG_PATH=/ipsec/lib/pkgconfig/
export PKG_CONFIG_LIBDIR=/ipsec/lib/pkgconfig/


USAGE="Usage: $0 Platform (linux/hisiv510/openwrt/himix)"

usage()
{
    echo $USAGE
    exit
}


system=$1

# --host=arm-hisiv510-linux

PREFIX=/ipsec
case $system in
    linux )
        ./configure   --prefix=$PREFIX \
                    CFLAGS="-I$PREFIX/include -I/root/openssl-$system/include" \
                    LDFLAGS="-L$PREFIX/lib -L/root/openssl-$system/lib" \
                    --enable-kernel-libipsec  \
                    --disable-gmp  --disable-openssl \
                    --enable-gmalg --with-gmalg_interior=yes
        ;;

    hisiv510 )
        ./configure --host=arm-hisiv510-linux  --prefix=$PREFIX                \
                      CFLAGS="-I$PREFIX/include -I/root/openssl-$system/include" \
                      LDFLAGS="-L$PREFIX/lib -L/root/openssl-$system/lib" \
                      --enable-kernel-libipsec  \
                      --disable-gmp  --disable-openssl \
                      --enable-rng
                      --enable-gmalg --with-gmalg_interior=yes
        ;;

    * )
        usage
        ;;
esac


make clean && make

rm -rf $PREFIX
make install