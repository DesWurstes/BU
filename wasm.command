cd "$(dirname "$0")"
cp argon2/include/argon2.h argon2/src/
emcc \
exports.c \
-fno-exceptions \
-fno-rtti \
-o util.js \
-s "EXPORTED_FUNCTIONS=['_checksum', '_lzma_compress', '_lzma_decompress', '_full_encrypt', '_full_decrypt', '_malloc', '_free']" \
-s "EXTRA_EXPORTED_RUNTIME_METHODS=['cwrap', 'ccall']" \
-s ALLOW_MEMORY_GROWTH=1 \
-fvisibility=hidden \
-O3 \
-Iargon2/include/ \
-DLPVOID="void*" \
-DCRITICAL_SECTION="void*" \
-D_7ZIP_ST \
-DHANDLE="void*"
rm argon2/src/argon2.h
