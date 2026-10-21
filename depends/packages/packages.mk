packages:=boost openssl libevent
ifeq ($(host_os),mingw32)
packages:=boost openssl_windows libevent
endif

qt_packages = zlib

qrencode_packages = qrencode

qt_linux_packages:=qt expat libxcb xcb_proto libXau xproto freetype fontconfig
qt_android_packages=qt

qt_darwin_packages=qt
qt_mingw32_packages=qt_windows

wallet_packages=bdb

zmq_packages=zeromq

upnp_packages=miniupnpc
ifeq ($(host_os),mingw32)
upnp_packages=miniupnpc_windows
endif

darwin_native_packages = native_biplist native_ds_store native_mac_alias

ifneq ($(build_os),darwin)
darwin_native_packages += native_cctools native_cdrkit native_libdmg-hfsplus
endif
