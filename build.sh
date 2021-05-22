#source /opt/xilinx_linux_gnu/environment-setup-zynq-arch-linux-gnu

export LD_LIBRARY_PATH=/ipsec/lib
export PKG_CONFIG_PATH=/ipsec/lib/pkgconfig/
export PKG_CONFIG_LIBDIR=/ipsec/lib/pkgconfig/


USAGE="Usage: $0 Platform (linux/arm) InstallRoot(/tmp/ipsec)"

usage()
{
    echo $USAGE
    exit
}


system=$1

# --host=arm-hisiv510-linux

if [ -z "$2" ];then
	echo $USAGE
	exit
fi

if [ ! -d "$2" ]; then
  echo "Creating directory $2"
  mkdir $2 
fi

PREFIX=$2

case $system in
    linux )
        ./configure   --prefix=$PREFIX \
                    --enable-kernel-libipsec  \
                    --enable-gmalg --with-gmalg_interior=yes
        ;;

    arm )
        ./configure --host=arm-linux  --prefix=$PREFIX                \
                      --enable-kernel-libipsec  \
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
