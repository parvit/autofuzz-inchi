FROM debian:jessie

RUN apt-get update
RUN apt-get install -y --force-yes wget gnupg

# Unfortunately, this key isn't available over HTTPS.
RUN wget -O /tmp/llvm-snapshot.gpg.key http://apt.llvm.org/llvm-snapshot.gpg.key
RUN apt-key add /tmp/llvm-snapshot.gpg.key
RUN bash -c 'echo "deb http://apt.llvm.org/jessie/ llvm-toolchain-jessie-3.9 main" >> /etc/apt/sources.list'
RUN bash -c 'echo "deb-src http://apt.llvm.org/jessie/ llvm-toolchain-jessie-3.9 main" >> /etc/apt/sources.list'
RUN apt-get install -y --force-yes apt-transport-https ca-certificates
RUN apt-get update
RUN apt-get install -y --force-yes clang-3.9 clang-3.9-doc libclang-common-3.9-dev libclang-3.9-dev libclang1-3.9 libclang1-3.9-dbg libllvm-3.9-ocaml-dev libllvm3.9 libllvm3.9-dbg lldb-3.9 llvm-3.9 llvm-3.9-dev llvm-3.9-doc llvm-3.9-examples llvm-3.9-runtime clang-format-3.9 python-clang-3.9 libfuzzer-3.9-dev


ENV CFLAGS="-O1 -g -fsanitize=address,bool,float-cast-overflow,integer-divide-by-zero,return,returns-nonnull-attribute,shift-exponent,signed-integer-overflow,unreachable,vla-bound -fno-sanitize-recover=all -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"
ENV CXXFLAGS="-O1 -g -fsanitize=address,bool,float-cast-overflow,integer-divide-by-zero,return,returns-nonnull-attribute,shift-exponent,signed-integer-overflow,unreachable,vla-bound -fno-sanitize-recover=all -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"
ENV LDFLAGS="-g -fsanitize=address,bool,float-cast-overflow,integer-divide-by-zero,return,returns-nonnull-attribute,shift-exponent,signed-integer-overflow,unreachable,vla-bound"
ENV CC="/usr/bin/clang-3.9"
ENV CXX="/usr/bin/clang++-3.9"
ENV ASAN_OPTIONS="exitcode=1,handle_segv=1,detect_leaks=1,leak_check_at_exit=1,allocator_may_return_null=1,detect_odr_violation=0"
ENV ASAN_SYMBOLIZER_PATH="/usr/lib/llvm-3.9/bin/llvm-symbolizer"

RUN bash -c 'echo "export CFLAGS=\"${CFLAGS}\"" >> /root/.bashrc'
RUN bash -c 'echo "export CXXFLAGS=\"${CXXFLAGS}\"" >> /root/.bashrc'
RUN bash -c 'echo "export LDFLAGS=\"${LDFLAGS}\"" >> /root/.bashrc'
RUN bash -c 'echo "export CC=\"${CC}\"" >> /root/.bashrc'
RUN bash -c 'echo "export CXX=\"${CXX}\"" >> /root/.bashrc'
RUN bash -c 'echo "export CXXFLAGS=\"${CXXFLAGS}\"" >> /root/.bashrc'
RUN bash -c 'echo "export ASAN_OPTIONS=\"${ASAN_OPTIONS}\"" >> /root/.bashrc'
RUN bash -c 'echo "export ASAN_SYMBOLIZER_PATH=\"${ASAN_SYMBOLIZER_PATH}\"" >> /root/.bashrc'
RUN bash -c 'echo "echo Use \"docker cp /path/to/input <container>:/path/inside/container\" to stage files for testing" >> /root/.bashrc'

# Only the last ENTRYPOINT or CMD is honored, so this can be overridden.
ENTRYPOINT /bin/bash
RUN apt-get install -y --force-yes wget make unzip
WORKDIR /fuzzing
RUN wget --no-check-certificate https://www.inchi-trust.org/wp/wp-content/uploads/2014/06/INCHI-1-API.zip
RUN unzip INCHI-1-API.zip
WORKDIR /fuzzing/INCHI-1-API/INCHI_API/inchi_dll
# The makefile is a mess as it doesn't use CC/CXX/CFLAGS/etc, plus it doesn't
# seem to build by default, so we just build manually.
RUN $CXX $CXXFLAGS -c *.c
RUN ar rcs libinchi.a *.o
WORKDIR /fuzzing

RUN printf '#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n#include <stdlib.h>\n#include <string>\n#include "inchi_api.h"\n\
\n\
char *szOptions = strdup("");\n\
\n\
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
  char *x = strdup(std::string(reinterpret_cast<const char *>(data), size).c_str());\n\
\n\
  char inchiKey[29], xtra1[65], xtra2[65];\n\
  GetINCHIKeyFromINCHI(x, 0, 0, inchiKey, xtra1, xtra2);\n\
\n\
  inchi_InputINCHI i;\n\
  i.szInChI = x;\n\
  i.szOptions = szOptions;\n\
\n\
  inchi_Output o;\n\
  GetINCHIfromINCHI(&i, &o);\n\
  FreeINCHI(&o);\n\
\n\
  inchi_OutputStruct os;\n\
  GetStructFromINCHI(&i, &os);\n\
  FreeStructFromINCHI(&os);\n\
\n\
  free(x);\n\
  return 0;\n\
}' >> /fuzzing/fuzzer.c

RUN $CXX $CXXFLAGS fuzzer.c -lFuzzer -linchi -L./INCHI-1-API/INCHI_API/inchi_dll/ -I./INCHI-1-API/INCHI_API/inchi_dll/ -I./INCHI-1-API/INCHI/common -o fuzzer

RUN bash -c 'echo "#!/bin/bash" > /fuzzing/repro.sh'
RUN bash -c 'echo "echo REPRO_START: v1.04, September 2011" >> /fuzzing/repro.sh'
RUN bash -c 'echo "/fuzzing/fuzzer \$1" >> /fuzzing/repro.sh'
RUN bash -c 'echo "echo REPRO_END" >> /fuzzing/repro.sh'
RUN bash -c 'chmod 755 /fuzzing/repro.sh'

RUN bash -c 'echo "echo \"Repro: /fuzzing/repro.sh <poc>\"" >> /root/.bashrc'

