package=qt_windows
$(package)_version=5.15.19
$(package)_download_path=https://download.qt.io/archive/qt/5.15/$($(package)_version)/submodules
$(package)_suffix=everywhere-opensource-src-$($(package)_version).tar.xz
$(package)_file_name=qtbase-$($(package)_suffix)
$(package)_sha256_hash=51e91c73abacab81e64efd01bf95794e79c0e605ad80947a024769f0dd620a32
$(package)_qttools_file_name=qttools-$($(package)_suffix)
$(package)_qttools_sha256_hash=2694af886130d63b8a42bcd138f4035fd8108273ebd16781f87300da352f1aa6
$(package)_qttranslations_file_name=qttranslations-$($(package)_suffix)
$(package)_qttranslations_sha256_hash=967e0d259af13f47e853f183cffc9671cc054380188fee28402f6425132a2c7b
$(package)_extra_sources=$($(package)_qttools_file_name) $($(package)_qttranslations_file_name)
$(package)_dependencies=zlib
$(package)_build_subdir=qtbase
$(package)_patches=translation_tool_path.patch

# This is a Windows-only recipe. Do not apply the legacy Qt 5.9 Mac/Android/X11
# patches to these sources or change other platforms' Qt versions implicitly.
define $(package)_set_vars
$(package)_config_opts=-release -static -opensource -confirm-license -c++std c++17
$(package)_config_opts+=-prefix $(host_prefix) -hostprefix $(build_prefix)
$(package)_config_opts+=-platform linux-g++ -xplatform win32-g++ -device-option CROSS_COMPILE=$(host)-
$(package)_config_opts+=-nomake examples -nomake tests -no-compile-examples
$(package)_config_opts+=-no-opengl -no-openssl -no-dbus -no-icu -no-cups -no-glib -no-iconv
$(package)_config_opts+=-no-feature-vulkan -no-feature-direct2d -no-feature-sql
$(package)_config_opts+=-no-feature-bearermanagement -no-feature-networkproxy -no-feature-http -no-feature-ftp
$(package)_config_opts+=-no-gif -no-ico -no-libjpeg -qt-libpng -qt-pcre -qt-harfbuzz -system-zlib
endef

define $(package)_fetch_cmds
  $(call fetch_file,$(package),$($(package)_download_path),$($(package)_file_name),$($(package)_file_name),$($(package)_sha256_hash)) && \
  $(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttools_file_name),$($(package)_qttools_file_name),$($(package)_qttools_sha256_hash)) && \
  $(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttranslations_file_name),$($(package)_qttranslations_file_name),$($(package)_qttranslations_sha256_hash))
endef

define $(package)_extract_cmds
  mkdir -p qtbase qttools qttranslations && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > .sources.sha256 && \
  echo "$($(package)_qttools_sha256_hash)  $($(package)_source_dir)/$($(package)_qttools_file_name)" >> .sources.sha256 && \
  echo "$($(package)_qttranslations_sha256_hash)  $($(package)_source_dir)/$($(package)_qttranslations_file_name)" >> .sources.sha256 && \
  $(build_SHA256SUM) -c .sources.sha256 && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source) -C qtbase && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttools_file_name) -C qttools && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttranslations_file_name) -C qttranslations
endef

define $(package)_preprocess_cmds
  patch -p1 -i $($(package)_patch_dir)/translation_tool_path.patch && \
  echo "!host_build: QMAKE_CFLAGS += $($(package)_cflags) $($(package)_cppflags)" >> qtbase/mkspecs/common/gcc-base.conf && \
  echo "!host_build: QMAKE_CXXFLAGS += $($(package)_cxxflags) $($(package)_cppflags)" >> qtbase/mkspecs/common/gcc-base.conf && \
  echo "!host_build: QMAKE_LFLAGS += $($(package)_ldflags)" >> qtbase/mkspecs/common/gcc-base.conf
endef

define $(package)_config_cmds
  ./configure $($(package)_config_opts) && \
  echo 'host_build: QT_CONFIG ~= s/system-zlib/zlib' >> mkspecs/qconfig.pri && \
  echo 'CONFIG += force_bootstrap' >> mkspecs/qconfig.pri
endef

# Qt generates bootstrap-private module metadata while building qtbase/src.
# Configure translation host tools only after those modules and libraries exist.
define $(package)_build_cmds
  $(MAKE) sub-src-qmake_all && \
  $(MAKE) -C src && \
  cd ../qttools/src/linguist/lrelease && ../../../../qtbase/bin/qmake lrelease.pro -o Makefile && $(MAKE) && \
  cd ../lupdate && ../../../../qtbase/bin/qmake lupdate.pro -o Makefile && $(MAKE) && \
  cd ../../../../qttranslations && ../qtbase/bin/qmake qttranslations.pro -o Makefile && $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) INSTALL_ROOT=$($(package)_staging_dir) install && \
  $(MAKE) -C ../qttools/src/linguist/lrelease INSTALL_ROOT=$($(package)_staging_dir) install_target && \
  $(MAKE) -C ../qttools/src/linguist/lupdate INSTALL_ROOT=$($(package)_staging_dir) install_target && \
  $(MAKE) -C ../qttranslations INSTALL_ROOT=$($(package)_staging_dir) install_subtargets
endef
