cd "$(dirname "$0")"
"${CC}" \
exports.c \
-Iargon2/include \
-o test.out \
-DNO_WASM \
-DARGON2_NO_THREADS \
-DCONFIG_H_FILE="<scrypt_config.h>" \
-Ofast \
-fwhole-program \
-march=native \
-DLPVOID="void*" \
-DCRITICAL_SECTION="void*" \
-D_7ZIP_ST \
-DHANDLE="void*"
