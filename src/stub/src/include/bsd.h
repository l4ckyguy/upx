#if defined(__GNUC__)
#if defined(__GNUC_MINOR__) && defined(__GNUC_PATCHLEVEL__)
#define ACC_CC_GNUC (__GNUC__ * 0x10000L + __GNUC_MINOR__ * 0x100 + __GNUC_PATCHLEVEL__)
#elif defined(__GNUC_MINOR__)
#define ACC_CC_GNUC (__GNUC__ * 0x10000L + __GNUC_MINOR__ * 0x100)
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
__extension__ typedef long long int64_t;
__extension__ typedef unsigned long long uint64_t;
#elif defined(_WIN32)
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#else
typedef long long int64_t;
typedef unsigned long long uint64_t;
#endif
typedef size_t uintptr_t;

typedef long off_t;

typedef void * caddr_t;
typedef unsigned pid_t;

struct rusage;
struct timex;
struct timeval {
     unsigned tv_sec;
     unsigned tv_usec;
};
struct timespec {
     unsigned tv_sec;
     long tv_nsec;
};

#if defined(__amd64__) || defined(__powerpc64__)
#define PAGE_MASK (~0ul << 12)
#define PAGE_SIZE (1ul << 12)
#elif defined(__i386__) || defined(__powerpc__) || defined(__arm__)
#define PAGE_MASK (~0ul << 12)
#define PAGE_SIZE (1ul << 12)
#endif

#define SEEK_SET 0
#define SEEK_CUR 1

#define O_RDONLY 00
#define O_WRONLY 01
#define O_RDWR 02
#define O_CREAT 0100
#define O_EXCL 0200

#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0

#define F_GETFD 1
#define F_SETFD 2
#define FD_CLOEXEC 1

#define ENOENT 2
#define EINTR 4

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define PROT_NONE 0x0

#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x1000
#define MAP_DENYWRITE 0x0

int access(char const *, int);
void * brk(void *);
int close(int);
int execve(char const *, char const *const *, char const *const *);
void exit(int) __attribute__((__noreturn__, __nothrow__));
int fcntl(int, int, long);
int ftruncate(int, size_t);
pid_t fork(void);
pid_t getpid(void);
int gettimeofday(struct timeval *, void *);
void * mmap(void *, size_t, int, int, int, off_t);
int munmap(void *, size_t);
int mprotect(void const *, size_t, int);
int nanosleep(struct timespec const *, struct timespec *);
int open(char const *, unsigned, unsigned);
ssize_t read(int, void *, size_t);
pid_t waitpid(pid_t, int *, int);
ssize_t write(int, void const *, size_t);
int unlink(char const *);

typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf32_Word;
typedef int32_t Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;
typedef uint64_t Elf32_Xword;
typedef int64_t Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;
typedef Elf32_Half Elf32_Versym;
typedef Elf64_Half Elf64_Versym;

#define EI_NIDENT 16

typedef struct {
     unsigned char e_ident[EI_NIDENT];
     Elf32_Half e_type;
     Elf32_Half e_machine;
     Elf32_Word e_version;
     Elf32_Addr e_entry;
     Elf32_Off e_phoff;
     Elf32_Off e_shoff;
     Elf32_Word e_flags;
     Elf32_Half e_ehsize;
     Elf32_Half e_phentsize;
     Elf32_Half e_phnum;
     Elf32_Half e_shentsize;
     Elf32_Half e_shnum;
     Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct {
     unsigned char e_ident[EI_NIDENT];
     Elf64_Half e_type;
     Elf64_Half e_machine;
     Elf64_Word e_version;
     Elf64_Addr e_entry;
     Elf64_Off e_phoff;
     Elf64_Off e_shoff;
     Elf64_Word e_flags;
     Elf64_Half e_ehsize;
     Elf64_Half e_phentsize;
     Elf64_Half e_phnum;
     Elf64_Half e_shentsize;
     Elf64_Half e_shnum;
     Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct {
     Elf32_Word p_type;
     Elf32_Off p_offset;
     Elf32_Addr p_vaddr;
     Elf32_Addr p_paddr;
     Elf32_Word p_filesz;
     Elf32_Word p_memsz;
     Elf32_Word p_flags;
     Elf32_Word p_align;
} Elf32_Phdr;

typedef struct {
     Elf64_Word p_type;
     Elf64_Word p_flags;
     Elf64_Off p_offset;
     Elf64_Addr p_vaddr;
     Elf64_Addr p_paddr;
     Elf64_Xword p_filesz;
     Elf64_Xword p_memsz;
     Elf64_Xword p_align;
} Elf64_Phdr;

typedef struct {
     uint32_t a_type;
     union {
          uint32_t a_val;
     } a_un;
} Elf32_auxv_t;

typedef struct {
     uint64_t a_type;
     union {
          uint64_t a_val;
     } a_un;
} Elf64_auxv_t;

#define AT_NULL 0
#define AT_IGNORE 1
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_PAGESZ 6
#define AT_BASE 7
#define AT_ENTRY 9

#define ET_EXEC 2
#define ET_DYN 3

#define PF_X 1
#define PF_W 2
#define PF_R 4

#define PT_LOAD 1
#define PT_INTERP 3
#define PT_PHDR 6

#define OVERHEAD 2048

#define UPX_MAGIC_LE32 0x21585055

#if 1

#define UPX2 0x32585055
#define UPX3 0x33585055
#define UPX4 0x34585055

#else

extern const unsigned UPX2;
extern const unsigned UPX3;
extern const unsigned UPX4;
#define UPX2 ((unsigned)(const void *)&UPX2)
#define UPX3 ((unsigned)(const void *)&UPX3)
#define UPX4 ((unsigned)(const void *)&UPX4)
#endif

typedef int nrv_int;
typedef int nrv_int32;
typedef unsigned int nrv_uint;
typedef unsigned int nrv_uint32;
#define nrv_byte unsigned char
#define nrv_bytep unsigned char *
#define nrv_voidp void *

struct b_info {
     uint32_t sz_unc;
     uint32_t sz_cpr;
     unsigned char b_method;
     unsigned char b_ftid;
     unsigned char b_cto8;
     unsigned char b_unused;
};

struct l_info {
     uint32_t l_checksum;
     uint32_t l_magic;
     uint16_t l_lsize;
     uint8_t l_version;
     uint8_t l_format;
};

struct p_info {
     uint32_t p_progid;
     uint32_t p_filesize;
     uint32_t p_blocksize;
};

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
