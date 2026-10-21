package=openssl_windows
$(package)_version=3.5.9
$(package)_download_path=https://github.com/openssl/openssl/releases/download/openssl-$($(package)_version)
$(package)_file_name=openssl-$($(package)_version).tar.gz
$(package)_sha256_hash=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

# Keep the legacy recipes for other platforms unchanged. The wallet links only
# libcrypto; OpenSSL build_libs/install_dev also stages unused libssl artifacts.
# Wallet/P2P traffic does not use TLS or the Windows certificate store.
# The no-ssl option below disables legacy SSLv3; it does not omit libssl.
define $(package)_set_vars
$(package)_config_env=CC="$($(package)_cc)" AR="$($(package)_ar)" RANLIB="$($(package)_ranlib)" RC="$(host)-windres"
$(package)_config_opts=--prefix=$(host_prefix) --libdir=lib --openssldir=$(host_prefix)/etc/openssl
$(package)_config_opts+=no-shared no-apps no-tests no-docs no-dso no-module no-engine no-winstore no-autoload-config no-legacy no-ssl
$(package)_config_opts+=$($(package)_cflags) $($(package)_cppflags)
$(package)_config_target_x86_64=mingw64
$(package)_config_target_i686=mingw
endef

define $(package)_config_cmds
  ./Configure $($(package)_config_target_$(host_arch)) $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE) build_libs
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install_dev
endef
