package=miniupnpc_windows
$(package)_version=2.3.3
$(package)_download_path=https://miniupnp.tuxfamily.org/files
$(package)_file_name=miniupnpc-$($(package)_version).tar.gz
$(package)_sha256_hash=d52a0afa614ad6c088cc9ddff1ae7d29c8c595ac5fdd321170a05f41e634bd1a

define $(package)_set_vars
$(package)_build_env=OS=
$(package)_build_opts=-f Makefile.mingw CC="$($(package)_cc)" AR="$($(package)_ar)"
$(package)_build_opts+=CFLAGS="$($(package)_cflags) $($(package)_cppflags)" GITHUB_SHA=release-$($(package)_version)
endef

define $(package)_build_cmds
  $(MAKE) $($(package)_build_opts) libminiupnpc.a
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include/miniupnpc $($(package)_staging_prefix_dir)/lib && \
  install include/*.h $($(package)_staging_prefix_dir)/include/miniupnpc && \
  install libminiupnpc.a $($(package)_staging_prefix_dir)/lib
endef
