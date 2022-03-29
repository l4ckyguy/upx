#define ACC_LIBC_NAKED 1

#include "miniacc.h"

#define UPX_LZMA_COMPAT 1

#if 0
#undef _LZMA_IN_CB
#undef _LZMA_OUT_READ
#undef _LZMA_PROB32
#undef _LZMA_LOC_OPT
#endif
#if (ACC_ARCH_I086)
#define Byte unsigned char
#define _7ZIP_BYTE_DEFINED 1
#endif
#if !defined(_LZMA_UINT32_IS_ULONG)
#if defined(__INT_MAX__) && ((__INT_MAX__) + 0 == 32767)
#define _LZMA_UINT32_IS_ULONG 1
#endif
#endif
#if !defined(_LZMA_NO_SYSTEM_SIZE_T)
#define _LZMA_NO_SYSTEM_SIZE_T 1
#endif

#if 0

#include "c/7zip/compress/lzma_c/lzmadecode.h"
#if (ACC_ABI_LP64)
#else
ACC_COMPILE_TIME_ASSERT_HEADER(sizeof(CLzmaDecoderState) == 16)
#endif
#include "c/7zip/compress/lzma_c/lzmadecode.c"

#else

#define CLzmaDecoderState CLzmaDecoderState_dummy
#define LzmaDecodeProperties LzmaDecodeProperties_dummy
#define LzmaDecode LzmaDecode_dummy
#if (ACC_CC_BORLANDC)
#include "lzmadecode.h"
#else
#if (WITH_LZMA >= 0x449)
#include "c/compress/lzma/lzmadecode.h"
#else
#include "c/7zip/compress/lzma_c/lzmadecode.h"
#endif
#endif
#undef CLzmaDecoderState
#undef LzmaDecodeProperties
#undef LzmaDecode
typedef struct {
     struct {
          unsigned char lc, lp, pb, dummy;
     } Properties;
#ifdef _LZMA_PROB32
     CProb Probs[8191];
#else
     CProb Probs[16382];
#endif
} CLzmaDecoderState;
ACC_COMPILE_TIME_ASSERT_HEADER(sizeof(CLzmaDecoderState) == 32768u)
ACC_COMPILE_TIME_ASSERT_HEADER(sizeof(SizeT) >= 4)

#if (ACC_ARCH_I086)
#define char char __huge
#elif (ACC_CC_WATCOMC)
#else
#define CLzmaDecoderState const CLzmaDecoderState
#endif
int LzmaDecodeProperties(CLzmaProperties *, const unsigned char *, int);
int LzmaDecode(CLzmaDecoderState *, const unsigned char *, SizeT, SizeT *, unsigned char *, SizeT, SizeT *);
#if (ACC_CC_BORLANDC)
#include "lzmadecode.c"
#else
#if (WITH_LZMA >= 0x449)
#include "c/compress/lzma/lzmadecode.c"
#else
#include "c/7zip/compress/lzma_c/lzmadecode.c"
#endif
#endif
#undef char
#undef CLzmaDecoderState

#endif
