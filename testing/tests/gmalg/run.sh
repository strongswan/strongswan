export LD_LIBRARY_PATH=/ipsec/lib
export PATH=/ipsec/bin:/ipsec/sbin:$PATH

swanctl --load-all --clear
swanctl --initiate --chil host-host
