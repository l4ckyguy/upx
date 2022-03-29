#if defined(__GNUC__)
#if defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__)
#define ACC_CC_GNUC (__GNUC__ * 0x10000L + (__GNUC_MINOR__ - 0) * 0x100 + (__GNUC_PATCHLEVEL__ - 0))
#elif defined(__GNUC_MINOR__)
#define ACC_CC_GNUC (__GNUC__ * 0x10000L + (__GNUC_MINOR__ - 0) * 0x100)
#else
#define ACC_CC_GNUC (__GNUC__ * 0x10000L)
#endif
#endif

#define ACC_UNUSED(var) ((void)var)

typedef long ptrdiff_t;
typedef long ssize_t;
typedef unsigned long size_t;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned uint32_t;
#if (ACC_CC_GNUC >= 0x020800ul)
#if 64 == __WORDSIZE
typedef long int64_t;
typedef unsigned long uint64_t;
#else
__extension__ typedef long long int64_t;
__extension__ typedef unsigned long long uint64_t;
#endif
#elif defined(_WIN32)
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
typedef long long int64_t;
typedef unsigned long long uint64_t;
#endif
typedef size_t uintptr_t;

typedef unsigned off_t_upx_stub;

#define PAGE_MASK (~0ul << 12)
#define PAGE_SIZE (-PAGE_MASK)

#define O_RDONLY 0

int close(int);
void exit(int) __attribute__((__noreturn__, __nothrow__));
int mprotect(void *, size_t, int);
extern int munmap(char *, size_t);
int open(char const *, int, ...);
extern ssize_t write(int, char const *, size_t);

#define UPX_MAGIC_LE32 0x21585055

#define nrv_byte unsigned char
typedef unsigned int nrv_uint;

#define CONST_CAST(type,var) ((type)((uintptr_t)(var)))

#if !defined(__attribute_cdecl)
#if defined(__i386__)
#if (ACC_CC_GNUC >= 0x030300)
#define __attribute_cdecl __attribute__((__cdecl__, __used__))
#elif (ACC_CC_GNUC >= 0x020700)
#define __attribute_cdecl __attribute__((__cdecl__))
#endif
#endif
#endif
#if !defined(__attribute_cdecl)
#define __attribute_cdecl 
#endif
