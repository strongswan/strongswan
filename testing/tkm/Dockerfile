# Container for TKM testing
#
# Build and usage (called from repository root):
#
#   docker build -t strongswan-tkm -f testing/tkm/Dockerfile testing
#
#   docker run -it --rm --cap-add net_admin -v $PWD:/strongswan strongswan-tkm
#
# In the container, this may be used to configure strongSwan with TKM support:
#
#   /strongswan/configure --disable-defaults --enable-silent-rules --enable-ikev2 --enable-kernel-netlink --enable-openssl --enable-pem --enable-socket-default --enable-swanctl --enable-tkm
#
# The following script can be used to generate private key, CA cert and example
# config for TKM:
#
#   /usr/local/share/tkm/generate-config.sh
#
# Run TKM in the background with:
#
#   tkm_keymanager -c tkm.conf -k key.der -r ca.der:1 >/tmp/tkm.log &
#
# Then tests for charon-tkm can be run against TKM:
#
#   make -j check TESTS_RUNNERS=tkm TESTS_TKM=1

FROM debian:bullseye

ARG packages="autoconf automake bison build-essential ca-certificates ccache \
flex gettext git gperf libssl-dev libtool pkg-config \
gnat gprbuild libahven9-dev libxmlada-schema10-dev libgmpada10-dev \
libalog6-dev"

RUN apt-get update && \
  DEBIAN_FRONTEND=noninteractive apt-get install -qq -y \
  --no-install-recommends \
  $packages \
  && rm -rf /var/lib/apt/lists/*

COPY scripts/recipes/*.mk /tmp/recipes/

RUN cd /tmp/recipes \
  && make -f 004_spark-crypto.mk \
  && make -f 005_anet.mk \
  && make -f 006_tkm-rpc.mk \
  && make -f 007_x509-ada.mk \
  && make -f 008_xfrm-ada.mk \
  && make -f 009_xfrm-proxy.mk \
  && make -f 010_tkm.mk \
  && rm -rf /tmp/recipes

ENV ADA_PROJECT_PATH /usr/local/ada/lib/gnat
ENV PATH /usr/lib/ccache:$PATH

COPY tkm/generate-config.sh /usr/local/share/tkm/
COPY tests/tkm/host2host-initiator/hosts/moon/etc/tkm/tkm.conf /usr/local/share/tkm/

WORKDIR /build

CMD [ "bash" ]
