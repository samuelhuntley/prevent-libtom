NAME:=generic-models

# - The stack_use module is disabled to avoid RELAX_PARAM_NAMES.
#   We want this off to skip the often-fake parameter names
#   that are used in hand models and to use model links.
EXTRA_FLAGS:= --concurrency \
--enable ALLOC_FREE_MISMATCH \
--enable DIVIDE_BY_ZERO \
--forbid-missing-models \
--enable-exceptions \
--handle-badalloc \
--disable-module stack_use \
--security \
--enable RELAX_SECURE_CODING_FUNCTION \
--enable RELAX_USER_POINTER \
-en RELAX_DATAFLOW_PRIMITIVES

GENERIC_LIB_DIR:=$(patsubst %/,%,$(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))))

SOURCES:=

LIBC_FILES:=$(GENERIC_LIB_DIR)/libc/common.c $(GENERIC_LIB_DIR)/libc/decls.h $(wildcard $(GENERIC_LIB_DIR)/libc/*.h/*.c)

ALL_LIBC_MODEL_FILE_DIR:=$(OBJ_DIR)/make-library

# Note: "symlinks.mk" at toplevel also knows about this file.
ALL_LIBC_MODEL_FILE:=$(ALL_LIBC_MODEL_FILE_DIR)/all.c

ALL_LIBC_MODEL_FILE: GENERIC_LIB_DIR:=$(GENERIC_LIB_DIR)
ALL_LIBC_MODEL_FILE: ALL_LIBC_MODEL_FILE_DIR:=$(ALL_LIBC_MODEL_FILE_DIR)

$(ALL_LIBC_MODEL_FILE): $(LIBC_FILES)
	mkdir -p $(ALL_LIBC_MODEL_FILE_DIR)
	bash $(GENERIC_LIB_DIR)/libc/all.sh "$(GENERIC_LIB_DIR)/libc" "$@"

# Add a rule to copy all.c to the target "library" directory.
# Used to be done in symlinks.mk, but that required the file to be
# generated (i.e. this makefile included), which is not always the
# case.
# Putting this rule here ties it to the all.c file generation properly.
$(eval $(call setup_file_copy_2_dirs,$(ALL_LIBC_MODEL_FILE_DIR)/,library/generic/libc/all/,all.c))

SOURCES_RELATIVE_TO_ROOT:=\
$(ALL_LIBC_MODEL_FILE)

SOURCES:=

SOURCES+= \
common/gcc-builtin.c \

SOURCES+= \
common/killpath.c \
common/new.cc \

SOURCES+=\
bsd/killpath.c \
bsd/kmalloc.c \
bsd/lock.c \
bsd/taint.c \

SOURCES+=\
linux/fdopendir.c \
linux/killpath.c \
linux/kmalloc.c \
linux/lock.c \
linux/taint.c \

SOURCES+=\
macosx/killpath.c \

SOURCES+=\
uitron/uitron.c

SOURCES+=\
stdcxx/stl.cc \
stdcxx/stl-inlinecxx11.cc \
stdcxx/stl-nostd.cc \

SOURCES+=\
win32/all.c \
win32/posix-wrappers.c \
win32-unicode/all.c \
win32/misc-incoming.c \
win32/misc-incoming.cpp \
win32-sal/sal.c \
win32-sal/sal-addenda.c \
mfc/*.cpp \
mfc/*.c \

SOURCES+=\
concurrency/*.c \
concurrency/*.cpp \

SOURCES+=\
security/posix/arpa_inet.c \
security/posix/netdb.c \
security/posix/stdlib.c \
security/posix/unistd.c \
security/sql-injection/odbc.c \
security/sql-injection/sqlite.c \
security/sql-injection/mysql.c \
security/sql-injection/postgres.c \
security/sql-injection/oracle-oci.c \
security/sql-injection/sql-server.c \
security/win32/all.c \
security/win32-unicode/all.c \

SOURCES+=\
uefi/StrLen.c \

SOURCES+=\
zlib/zlib_models.c \

SOURCES+=\
libtomcrypt/libtomcrypt_crypto_api_models.c \

SOURCES+=\
libsodium/crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c \
libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c \
libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c \
libsodium/crypto_auth/crypto_auth.c \
libsodium/crypto_generichash/crypto_generichash.c \
libsodium/crypto_secretbox/crypto_secretbox_easy.c \
libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c \
libsodium/crypto_shorthash/crypto_shorthash.c \

EXTRA_DEPS:=\
win32/misc-incoming.h \
win32/src/*.c \
win32-sal/win32_header.h \
security/win32/src/*.c \
