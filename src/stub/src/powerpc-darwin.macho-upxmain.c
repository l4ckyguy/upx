#define __WORDSIZE 32
#include <stdio.h>
#include <stdlib.h>
#include "include/darwin.h"

#ifndef DEBUG
#define DEBUG 0
#endif
#if !DEBUG
#define DPRINTF(a) 
#define DEBUG_STRCON(name,value) 
#else
extern int write(int, void const *, size_t);
#if 0
#include "stdarg.h"
#else
#define va_arg __builtin_va_arg
#define va_end __builtin_va_end
#define va_list __builtin_va_list
#define va_start __builtin_va_start
#endif

#if defined(__i386__) || defined(__x86_64__)
#define PIC_STRING(value,var) \
     __asm__ __volatile__("call 0f; .asciz \"" value "\"; \
      0: pop %0;"                                                            \
                          : "=r"(var) \
                          :)
#elif defined(__arm__)
#define PIC_STRING(value,var) \
     __asm__ __volatile__("mov %0,pc; b 0f; \
        .asciz \"" value "\"; .balign 4; \
      0: "                                                                             \
                          : "=r"(var))
#elif defined(__mips__)
#define PIC_STRING(value,var) \
     __asm__ __volatile__(".set noreorder; bal 0f; move %0,$31; .set reorder; \
        .asciz \"" value "\"; .balign 4; \
      0: "                                                                             \
                          : "=r"(var) \
                          : \
                          : "ra")
#endif

#define DEBUG_STRCON(name,strcon) \
     static char const *name(void) \
     { \
          register char const *rv; \
          PIC_STRING(strcon, rv); \
          return rv; \
     }

#ifdef __arm__
extern unsigned div10(unsigned);
#else
static unsigned div10(unsigned x)
{
     return x / 10u;
}
#endif

static int unsimal(unsigned x, char *ptr, int n)
{
     if (10 <= x) {
          unsigned const q = div10(x);
          x -= 10 * q;
          n = unsimal(q, ptr, n);
     }
     ptr[n] = '0' + x;
     return 1 + n;
}

static int decimal(int x, char *ptr, int n)
{
     if (x < 0) {
          x = -x;
          ptr[n++] = '-';
     }
     return unsimal(x, ptr, n);
}

DEBUG_STRCON(STR_hex, "0123456789abcdef");

static int heximal(unsigned long x, char *ptr, int n)
{
     if (16 <= x) {
          n = heximal(x >> 4, ptr, n);
          x &= 0xf;
     }
     ptr[n] = STR_hex()[x];
     return 1 + n;
}

#define DPRINTF(a) my_printf a

static int my_printf(char const *fmt, ...)
{
     char c;
     int n = 0;
     char * ptr;
     char buf[20];
     va_list va;
     va_start(va, fmt);
     ptr = &buf[0];
     while (0 != (c = *fmt++))
          if ('%' != c)
               goto literal;
          else
               switch (c = *fmt++) {
                    default: {
                    literal:
                         n += write(2, fmt - 1, 1);
                    } break;
                    case 0:
                         goto done;
                    case 'u': {
                         n += write(2, buf, unsimal(va_arg(va, unsigned), buf, 0));
                    } break;
                    case 'd': {
                         n += write(2, buf, decimal(va_arg(va, int), buf, 0));
                    } break;
                    case 'p': {
                         buf[0] = '0';
                         buf[1] = 'x';
                         n += write(2, buf, heximal((unsigned long)va_arg(va, void *), buf, 2));
                    } break;
                    case 'x': {
                         buf[0] = '0';
                         buf[1] = 'x';
                         n += write(2, buf, heximal(va_arg(va, int), buf, 2));
                    } break;
               }
done:
     va_end(va);
     return n;
}
#endif

typedef struct {
     size_t size;
     void * buf;
} Extent;

DEBUG_STRCON(STR_xread, "xread %%p(%%x %%p) %%p %%x\\n")
DEBUG_STRCON(STR_xreadfail, "xreadfail %%p(%%x %%p) %%p %%x\\n")

static void xread(Extent *x, void *buf, size_t count)
{
     unsigned char *p = x->buf, *q = buf;
     size_t j;
     DPRINTF((STR_xread(), x, x->size, x->buf, buf, count));
     if (x->size < count) {
          DPRINTF((STR_xreadfail(), x, x->size, x->buf, buf, count));
          exit(127);
     }
     for (j = count; 0 != j--; ++p, ++q) {
          *q = *p;
     }
     x->buf += count;
     x->size -= count;
}

#if 1
#define ERR_LAB \
     error: \
     exit(127);
#define err_exit(a) goto error
#else
#define ERR_LAB 
DEBUG_STRCON(STR_exit, "err_exit %%x\\n");

static void err_exit(int a)
{
     DPRINTF((STR_exit(), a));
     (void)a;
     exit(127);
}
#endif

struct l_info {
     unsigned l_checksum;
     unsigned l_magic;
     unsigned short l_lsize;
     unsigned char l_version;
     unsigned char l_format;
};
struct p_info {
     unsigned p_progid;
     unsigned p_filesize;
     unsigned p_blocksize;
};

struct b_info {
     unsigned sz_unc;
     unsigned sz_cpr;
     unsigned char b_method;
     unsigned char b_ftid;
     unsigned char b_cto8;
     unsigned char b_unused;
};

typedef void f_unfilter(nrv_byte *, nrv_uint, unsigned cto8, unsigned ftid);
typedef int f_expand(const nrv_byte *, nrv_uint, nrv_byte *, nrv_uint *, unsigned);

DEBUG_STRCON(STR_unpackExtent, "unpackExtent in=%%p(%%x %%p)  out=%%p(%%x %%p)  %%p %%p\\n");
DEBUG_STRCON(STR_err5, "sz_cpr=%%x  sz_unc=%%x  xo->size=%%x\\n");

static void unpackExtent(Extent *const xi, Extent *const xo, f_expand *const f_decompress, f_unfilter *f_unf)
{
     DPRINTF((STR_unpackExtent(), xi, xi->size, xi->buf, xo, xo->size, xo->buf, f_decompress, f_unf));
     while (xo->size) {
          struct b_info h;

          xread(xi, (unsigned char *)&h, sizeof(h));
          if (h.sz_unc == 0) {
               if (h.sz_cpr != UPX_MAGIC_LE32)
                    err_exit(2);
               if (xi->size != 0)
                    err_exit(3);
               break;
          }
          if (h.sz_cpr <= 0) {
               err_exit(4);
               ERR_LAB
          }
          if (h.sz_cpr > h.sz_unc || h.sz_unc > xo->size) {
               DPRINTF((STR_err5(), h.sz_cpr, h.sz_unc, xo->size));
               err_exit(5);
          }

          if (h.sz_cpr < h.sz_unc) {
               nrv_uint out_len = h.sz_unc;
               int const j = (*f_decompress)(xi->buf, h.sz_cpr, xo->buf, &out_len, h.b_method);
               if (j != 0 || out_len != (nrv_uint)h.sz_unc)
                    err_exit(7);
               if (h.b_ftid != 0 && f_unf) {
                    (*f_unf)(xo->buf, out_len, h.b_cto8, h.b_ftid);
               }
               xi->buf += h.sz_cpr;
               xi->size -= h.sz_cpr;
          }
          else {
               xread(xi, xo->buf, h.sz_cpr);
          }
          xo->buf += h.sz_unc;
          xo->size -= h.sz_unc;
     }
}

static void upx_bzero(unsigned char *p, size_t len)
{
     if (len)
          do {
               *p++ = 0;
          } while (--len);
}
#define bzero upx_bzero

#define REP8(x) ((x) | ((x) << 4) | ((x) << 8) | ((x) << 12) | ((x) << 16) | ((x) << 20) | ((x) << 24) | ((x) << 28))
#define EXP8(y) ((1 & (y)) ? 0xf0f0f0f0 : (2 & (y)) ? 0xff00ff00 : (4 & (y)) ? 0xffff0000 : 0)
#define PF_TO_PROT(pf) \
     ((PROT_READ | PROT_WRITE | PROT_EXEC) \
      & (((REP8(PROT_EXEC) & EXP8(PF_X)) | (REP8(PROT_READ) & EXP8(PF_R)) | (REP8(PROT_WRITE) & EXP8(PF_W))) \
         >> ((pf & (PF_R | PF_W | PF_X)) << 2)))

typedef struct {
     unsigned magic;
     unsigned nfat_arch;
} Fat_header;
typedef struct {
     unsigned cputype;
     unsigned cpusubtype;
     unsigned offset;
     unsigned size;
     unsigned align;
} Fat_arch;
enum e8 { FAT_MAGIC = 0xcafebabe, FAT_CIGAM = 0xbebafeca };
enum e9 {
     CPU_TYPE_I386 = 7,
     CPU_TYPE_AMD64 = 0x01000007,
     CPU_TYPE_ARM = 12,
     CPU_TYPE_POWERPC = 0x00000012,
     CPU_TYPE_POWERPC64 = 0x01000012
};

typedef struct {
     unsigned magic;
     unsigned cputype;
     unsigned cpysubtype;
     unsigned filetype;
     unsigned ncmds;
     unsigned sizeofcmds;
     unsigned flags;
} Mach_header;
enum e0 { MH_MAGIC = 0xfeedface, MH_MAGIC64 = 1 + 0xfeedface };
enum e2 { MH_EXECUTE = 2 };
enum e3 { MH_NOUNDEFS = 1 };

typedef struct {
     unsigned cmd;
     unsigned cmdsize;
} Mach_load_command;
enum e4 {
     LC_REQ_DYLD = 0x80000000,
     LC_SEGMENT = 0x1,
     LC_SEGMENT_64 = 0x19,
     LC_THREAD = 0x4,
     LC_UNIXTHREAD = 0x5,
     LC_LOAD_DYLINKER = 0xe,
     LC_MAIN = (0x28 | LC_REQ_DYLD)
};

typedef struct {
     unsigned cmd;
     unsigned cmdsize;
     char segname[16];
     uint32_t vmaddr;
     uint32_t vmsize;
     uint32_t fileoff;
     uint32_t filesize;
     unsigned maxprot;
     unsigned initprot;
     unsigned nsects;
     unsigned flags;
} Mach_segment_command;
enum e5 { VM_PROT_READ = 1, VM_PROT_WRITE = 2, VM_PROT_EXECUTE = 4 };

typedef struct {
     char sectname[16];
     char segname[16];
     uint32_t addr;
     uint32_t size;
     unsigned offset;
     unsigned align;
     unsigned reloff;
     unsigned nreloc;
     unsigned flags;
     unsigned reserved1;
     unsigned reserved2;
} Mach_section_command;

typedef struct {
     uint32_t cmd;
     uint32_t cmdsize;
     uint64_t entryoff;
     uint64_t stacksize;
} Mach_main_command;

typedef struct {
     uint32_t srr0;
     uint32_t srr1;
     uint32_t r0, r1, r2, r3, r4, r5, r6, r7;
     uint32_t r8, r9, r10, r11, r12, r13, r14, r15;
     uint32_t r16, r17, r18, r19, r20, r21, r22, r23;
     uint32_t r24, r25, r26, r27, r28, r29, r30, r31;

     uint32_t cr;
     uint32_t xer;
     uint32_t lr;
     uint32_t ctr;
     uint32_t mq;

     uint32_t vrsave;
} Mach_ppc_thread_state;

typedef struct {
     unsigned cmd;
     unsigned cmdsize;
     unsigned flavor;
     unsigned count;
     Mach_ppc_thread_state state;
} Mach_thread_command;
enum e6 { PPC_THREAD_STATE = 1 };
enum e7 { PPC_THREAD_STATE_COUNT = sizeof(Mach_ppc_thread_state) / 4 };

typedef union {
     unsigned offset;
} Mach_lc_str;

#define MAP_FIXED 0x10
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x1000

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_ANON_FD -1
#define MAP_FAILED ((void *)-1)

extern void *mmap(void *, size_t, unsigned, unsigned, int, off_t);
ssize_t pread(int, void *, size_t, off_t);

DEBUG_STRCON(STR_mmap, "mmap  addr=%%p  len=%%p  prot=%%x  flags=%%x  fd=%%d  off=%%p\\n");
DEBUG_STRCON(STR_do_xmap, "do_xmap  fdi=%%x  mhdr=%%p  xi=%%p(%%x %%p) f_unf=%%p\\n")

static uint32_t do_xmap(Mach_header const *const mhdr,
                        off_t const fat_offset,
                        Extent *const xi,
                        int const fdi,
                        Mach_header ** mhdrpp,
                        f_expand *const f_decompress,
                        f_unfilter *const f_unf)
{
     Mach_segment_command const *sc = (Mach_segment_command const *)(1 + mhdr);
     Mach_segment_command const *segTEXT = 0;
     uint32_t entry = 0;
     unsigned long base = 0;
     unsigned j;

     DPRINTF((STR_do_xmap(), fdi, mhdr, xi, (xi ? xi->size : 0), (xi ? xi->buf : 0), f_unf));

     for (j = 0; j < mhdr->ncmds; ++j, (sc = (Mach_segment_command const *)(sc->cmdsize + (void const *)sc)))
          if (LC_SEGMENT == sc->cmd && sc->vmsize != 0) {
               Extent xo;
               size_t mlen = xo.size = sc->filesize;
               unsigned char *addr = xo.buf = base + (unsigned char *)sc->vmaddr;
               unsigned char *haddr = sc->vmsize + addr;
               size_t frag = (int)(uint32_t)addr & ~PAGE_MASK;
               addr -= frag;
               mlen += frag;

               if (0 != mlen) {
                    unsigned const prot = VM_PROT_READ | VM_PROT_WRITE;
                    unsigned const flags
                       = (addr ? MAP_FIXED : 0) | MAP_PRIVATE | ((xi || 0 == sc->filesize) ? MAP_ANON : 0);
                    int const fdm = ((0 == sc->filesize) ? MAP_ANON_FD : fdi);
                    off_t const offset = sc->fileoff + fat_offset;

                    DPRINTF((STR_mmap(), addr, mlen, prot, flags, fdm, offset));
                    unsigned char *mapa = mmap(addr, mlen, prot, flags, fdm, offset);
                    if (MAP_FAILED == mapa) {
                         err_exit(8);
                    }
                    if (0 == addr) {
                         base = (unsigned long)mapa;
                    }
                    addr = mapa;
               }
               if (xi && 0 != sc->filesize) {
                    if (0 == sc->fileoff) {
                         segTEXT = sc;
                         *mhdrpp = (Mach_header *)(void *)addr;
                    }
                    unpackExtent(xi, &xo, f_decompress, f_unf);
               }

               frag = (-mlen) & ~PAGE_MASK;
               bzero(mlen + addr, frag);
               if (0 != mlen && 0 != mprotect(addr, mlen, sc->initprot)) {
                    err_exit(10);
                    ERR_LAB
               }
               addr += mlen + frag;
               if (
#if defined(SIMULATE_ON_DEBIAN_EABI4)
                  0 != addr &&
#endif
                  addr < haddr) {
                    if (0 != addr
                        && addr
                              != mmap(addr,
                                      haddr - addr,
                                      sc->initprot,
                                      MAP_FIXED | MAP_PRIVATE | MAP_ANON,
                                      MAP_ANON_FD,
                                      0)) {
                         err_exit(9);
                    }
               }
          }
          else if (LC_UNIXTHREAD == sc->cmd || LC_THREAD == sc->cmd) {
               Mach_thread_command const *const thrc = (Mach_thread_command const *)sc;
               if (PPC_THREAD_STATE == thrc->flavor && PPC_THREAD_STATE_COUNT == thrc->count) {
                    entry = thrc->state.srr0 + base;
               }
          }
          else if (LC_MAIN == sc->cmd) {
               entry = ((Mach_main_command const *)sc)->entryoff;
               if (segTEXT->fileoff <= entry && entry < segTEXT->filesize) {
                    entry += segTEXT->vmaddr;
               }
          }
     return entry;
}

static off_t fat_find(Fat_header *fh)
{
     Fat_arch *fa = (Fat_arch *)(1 + fh);

     unsigned j;
     for (j = 0; j < fh->nfat_arch; ++j, ++fa) {
          if (CPU_TYPE_POWERPC == fa->cputype) {
               return fa->offset;
          }
     }
     return 0;
}

DEBUG_STRCON(STR_upx_main,
             "upx_main szc=%%x  f_dec=%%p  f_unf=%%p  "
             "  xo=%%p(%%x %%p)  xi=%%p(%%x %%p)  mhdrpp=%%p\\n")

uint32_t upx_main(struct l_info const *const li,
                  size_t volatile sz_compressed,
                  Mach_header *const mhdr,
                  size_t const sz_mhdr,
                  f_expand *const f_decompress,
                  f_unfilter *const f_unf,
                  Mach_header **const mhdrpp)
{
     uint32_t entry;
     off_t fat_offset = 0;
     Extent xi, xo, xi0;
     xi.buf = CONST_CAST(unsigned char *, 1 + (struct p_info const *)(1 + li));
     xi.size = sz_compressed - (sizeof(struct l_info) + sizeof(struct p_info));
     xo.buf = (unsigned char *)mhdr;
     xo.size = ((struct b_info const *)(void const *)xi.buf)->sz_unc;
     xi0 = xi;

     DPRINTF((STR_upx_main(), sz_compressed, f_decompress, f_unf, &xo, xo.size, xo.buf, &xi, xi.size, xi.buf, mhdrpp));

     unpackExtent(&xi, &xo, f_decompress, 0);

     entry = do_xmap(mhdr, fat_offset, &xi0, MAP_ANON_FD, mhdrpp, f_decompress, f_unf);

     {
          Mach_load_command const *lc = (Mach_load_command const *)(1 + mhdr);
          unsigned j;

          for (j = 0; j < mhdr->ncmds; ++j, (lc = (Mach_load_command const *)(lc->cmdsize + (void const *)lc)))
               if (LC_LOAD_DYLINKER == lc->cmd) {
                    char const *const dyld_name = ((Mach_lc_str const *)(1 + lc))->offset + (char const *)lc;
                    int const fdi = open(dyld_name, O_RDONLY, 0);
                    if (0 > fdi) {
                         err_exit(18);
                    }
                    for (;;) {
                         if (sz_mhdr != pread(fdi, (void *)mhdr, sz_mhdr, fat_offset)) {
                              ERR_LAB
                              err_exit(19);
                         }
                         switch (mhdr->magic) {
                              case MH_MAGIC:
                                   break;
                              case MH_MAGIC64:
                                   break;

                              case FAT_CIGAM:
                              case FAT_MAGIC: {

                                   fat_offset = fat_find((Fat_header *)mhdr);
                                   if (fat_offset) {
                                        continue;
                                   }
                                   err_exit(20);
                              } break;
                         }
                         break;
                    }
                    entry = do_xmap(mhdr, fat_offset, 0, fdi, 0, 0, 0);
                    close(fdi);
                    break;
               }
     }

     return entry;
}

typedef struct {
     uint32_t cmd;
     uint32_t cmdsize;
     uint32_t data[2];
} Mach_command;
int main(int argc, char *argv[])
{
     Mach_header const * mhdr0 = (Mach_header const *)((~0ul << 12) & (unsigned long)&main);
     Mach_command const *ptr = (Mach_command const *)(1 + mhdr0);
     f_unfilter * f_unf;
     f_expand * f_exp;
     char * payload;
     size_t paysize;

     unsigned j;
     for (j = 0; j < mhdr0->ncmds; ++j, ptr = (Mach_command const *)(ptr->cmdsize + (char const *)ptr))
          if (LC_SEGMENT == ptr->cmd) {
               Mach_segment_command const *const seg = (Mach_segment_command const *)ptr;

               if (*(uint64_t const *)(&"__LINKEDIT"[2]) == *(uint64_t const *)(&seg->segname[2])) {
                    f_unf = (f_unfilter *)(sizeof(unsigned) + seg->vmaddr);
                    f_exp = (f_expand *)(*(unsigned const *)seg->vmaddr + seg->vmaddr);
                    unsigned const *q = (unsigned const *)seg->vmaddr;
                    while (!(paysize = *--q))
                         ;
                    payload = (char *)(-paysize + (char const *)q);
                    break;
               }
          }
     char mhdr[16384];
     uint32_t entry = upx_main((struct l_info const *)payload,
                               paysize,
                               (Mach_header *)mhdr,
                               sizeof(mhdr),
                               f_exp,
                               f_unf,
                               (Mach_header **)&argv[-2]);

     munmap(payload, paysize);
     return entry;
}
