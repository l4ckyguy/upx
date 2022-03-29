#define __WORDSIZE 32
#include "include/darwin.h"

#ifndef DEBUG
#define DEBUG 0
#endif
#if !DEBUG
#define DPRINTF(a...) 
#else
#define DPRINTF(fmt,args...) \
     ({ \
          char const *r_fmt; \
          asm("call 0f; .asciz \"" fmt "\"; 0: pop %0" : "=r"(r_fmt)); \
          dprintf(r_fmt, args); \
     })

#define va_arg __builtin_va_arg
#define va_end __builtin_va_end
#define va_list __builtin_va_list
#define va_start __builtin_va_start

static int unsimal(unsigned x, char *ptr, int n)
{
     if (10 <= x) {
          unsigned const q = x / 10;
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

static int heximal(unsigned long x, char *ptr, int n)
{
     unsigned j = -1 + 2 * sizeof(unsigned long);
     unsigned long m = 0xful << (4 * j);
     for (; j; --j, m >>= 4) {
          if (m & x)
               break;
     }
     for (; m; --j, m >>= 4) {
          unsigned d = 0xf & (x >> (4 * j));
          ptr[n++] = ((10 <= d) ? ('a' - 10) : '0') + d;
     }
     return n;
}

static int dprintf(char const *fmt, ...)
{
     int n = 0;
     char const *literal = 0;
     char buf[24];
     va_list va;
     va_start(va, fmt);
     for (;;) {
          char c = *fmt++;
          if (!c) {
               if (literal) {
                    goto finish;
               }
               break;
          }
          if ('%' != c) {
               if (!literal) {
                    literal = fmt;
               }
               continue;
          }

          if (literal) {
          finish:
               n += write(2, -1 + literal, fmt - literal);
               literal = 0;
               if (!c) {
                    break;
               }
          }
          switch (c = *fmt++) {
               default: {
                    n += write(2, -1 + fmt, 1);
               } break;
               case 0: {
                    goto done;
               } break;
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
                    n += write(2, buf, heximal(va_arg(va, unsigned int), buf, 2));
               } break;
               case 's': {
                    char *s0 = (char *)va_arg(va, unsigned char *), *s = s0;
                    if (s)
                         while (*s)
                              ++s;
                    n += write(2, s0, s - s0);
               } break;
          }
     }
done:
     va_end(va);
     return n;
}
#endif

extern int spin(int);

typedef struct {
     size_t size;
     void * buf;
} Extent;

static void xread(Extent *x, void *buf, size_t count)
{
     unsigned char *p = x->buf, *q = buf;
     size_t j;
     DPRINTF("xread %%p(%%x %%p) %%p %%x\\n", x, x->size, x->buf, buf, count);
     if (x->size < count) {
          DPRINTF("xreadfail %%p(%%x %%p) %%p %%x\\n", x, x->size, x->buf, buf, count);
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

static void unpackExtent(Extent *const xi, Extent *const xo, f_expand *const f_decompress, f_unfilter *f_unf)
{
     DPRINTF("unpackExtent in=%%p(%%x %%p)  out=%%p(%%x %%p)  %%p %%p\\n",
             xi,
             xi->size,
             xi->buf,
             xo,
             xo->size,
             xo->buf,
             f_decompress,
             f_unf);
     while (xo->size) {
          struct b_info h;

          xread(xi, (unsigned char *)&h, sizeof(h));
          DPRINTF("  sz_unc=%%x  sz_cpr=%%x  param=%%x\\n", h.sz_unc, h.sz_cpr, *(int *)&h.b_method);
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
               DPRINTF("sz_cpr=%%x  sz_unc=%%x  xo->size=%%x\\n", h.sz_cpr, h.sz_unc, xo->size);
               err_exit(5);
          }

          if (h.sz_cpr < h.sz_unc) {
               nrv_uint out_len = h.sz_unc;
               int const j = (*f_decompress)(xi->buf, h.sz_cpr, xo->buf, &out_len, h.b_method);
               if (j != 0 || out_len != (nrv_uint)h.sz_unc)
                    err_exit(7);
               DPRINTF("  b_ftid=%%x  f_unf=%%p\\n", h.b_ftid, f_unf);
               if (h.b_ftid != 0 && f_unf) {
                    DPRINTF(" unfiltering f_unf=%%p  buf=%%p  len=%%x  cto=%%x  ftid=%%x\\n",
                            f_unf,
                            xo->buf,
                            out_len,
                            h.b_cto8,
                            h.b_ftid);
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

typedef size_t Addr;

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
enum e4 { LC_SEGMENT = 0x1, LC_SEGMENT_64 = 0x19, LC_THREAD = 0x4, LC_UNIXTHREAD = 0x5, LC_LOAD_DYLINKER = 0xe };

typedef struct {
     unsigned cmd;
     unsigned cmdsize;
     char segname[16];
     Addr vmaddr;
     Addr vmsize;
     unsigned fileoff;
     unsigned filesize;
     unsigned maxprot;
     unsigned initprot;
     unsigned nsects;
     unsigned flags;
} Mach_segment_command;
enum e5 { VM_PROT_NONE = 0, VM_PROT_READ = 1, VM_PROT_WRITE = 2, VM_PROT_EXECUTE = 4 };

typedef struct {
     char sectname[16];
     char segname[16];
     Addr addr;
     Addr size;
     unsigned offset;
     unsigned align;
     unsigned reloff;
     unsigned nreloc;
     unsigned flags;
     unsigned reserved1;
     unsigned reserved2;
} Mach_section_command;

typedef struct {
     unsigned eax, ebx, ecx, edx;
     unsigned edi, esi, ebp;
     unsigned esp, ss;
     unsigned eflags;
     unsigned eip, cs;
     unsigned ds, es, fs, gs;
} Mach_i386_thread_state;

typedef struct {
     unsigned cmd;
     unsigned cmdsize;
     unsigned flavor;
     unsigned count;
     Mach_i386_thread_state state;
} Mach_thread_command;
enum e6 { i386_THREAD_STATE = 1 };
enum e7 { i386_THREAD_STATE_COUNT = sizeof(Mach_i386_thread_state) / 4 };

typedef union {
     unsigned long offset;
     char * ptr;
} Mach_lc_str;

#define MAP_FIXED 0x10
#define MAP_PRIVATE 0x02
#define MAP_ANON 0x1000
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_ANON_FD -1

extern void * mmap(void *, size_t, unsigned, unsigned, int, off_t_upx_stub, unsigned);
extern ssize_t pread(int, void *, size_t, off_t_upx_stub, unsigned);
extern void bswap(void *, unsigned);

enum {
     MH_DYLINKER = 7,
     MH_PIE = 0x200000

};

static Addr xfind_pages(Mach_header const *const mhdr, Mach_segment_command const *sc, int const ncmds, Addr addr)
{
     Addr lo = ~(Addr)0, hi = 0;
     int j;
     unsigned mflags = ((mhdr->filetype == MH_DYLINKER || mhdr->flags & MH_PIE) ? 0 : MAP_FIXED);
     mflags += MAP_PRIVATE | MAP_ANON;
     DPRINTF("xfind_pages  mhdr=%%p  sc=%%p  ncmds=%%d  addr=%%p  mflags=%%x\\n", mhdr, sc, ncmds, addr, mflags);
     for (j = 0; j < ncmds; ++j, (sc = (Mach_segment_command const *)((sc->cmdsize >> 2) + (unsigned const *)sc)))
          if (LC_SEGMENT == sc->cmd) {
               DPRINTF("  #%%d  cmd=%%x  cmdsize=%%x  vmaddr=%%p  vmsize==%%p  lo=%%p  mflags=%%x\\n",
                       j,
                       sc->cmd,
                       sc->cmdsize,
                       sc->vmaddr,
                       sc->vmsize,
                       lo,
                       mflags);
               if (sc->vmsize && !(sc->vmaddr == 0 && (MAP_FIXED & mflags))) {
                    if (mhdr->filetype == MH_DYLINKER && 0 == (1 + lo) && sc->vmaddr != 0) {

                         mflags |= MAP_FIXED;
                    }
                    if (lo > sc->vmaddr) {
                         lo = sc->vmaddr;
                    }
                    if (hi < (sc->vmsize + sc->vmaddr)) {
                         hi = sc->vmsize + sc->vmaddr;
                    }
               }
          }
     lo -= ~PAGE_MASK & lo;
     hi = PAGE_MASK & (hi - lo - PAGE_MASK - 1);
     DPRINTF("  addr=%%p  lo=%%p  len=%%p  mflags=%%x\\n", addr, lo, hi, mflags);
     if (MAP_FIXED & mflags) {
          addr = lo;
          int rv = munmap((void *)addr, hi);
          if (rv) {
               DPRINTF("munmap addr=%%p len=%%p, rv=%%x\\n", addr, hi, rv);
          }
     }
     addr = (Addr)mmap((void *)addr, hi, VM_PROT_NONE, mflags, MAP_ANON_FD, 0, 0);
     DPRINTF("  addr=%%p\\n", addr);
     if (~PAGE_MASK & addr) {
     }
     return (Addr)(addr - lo);
}
Addr do_xmap(Mach_header *const mhdr,
             off_t_upx_stub const fat_offset,
             Extent *const xi,
             int const fdi,
             Mach_header ** mhdrpp,
             f_expand *const f_exp,
             f_unfilter *const f_unf)
{
     DPRINTF("do_xmap  fdi=%%x  mhdr=%%p  *mhdrpp=%%p  xi=%%p(%%x %%p) f_unf=%%p\\n",
             fdi,
             mhdr,
             (mhdrpp ? *mhdrpp : 0),
             xi,
             (xi ? xi->size : 0),
             (xi ? xi->buf : 0),
             f_unf);

     Addr rv = 0;
     Mach_segment_command *sc = (Mach_segment_command *)(1 + mhdr);
     Addr const reloc = xfind_pages(mhdr, sc, mhdr->ncmds, 0);
     DPRINTF("do_xmap reloc=%%p\\n", reloc);
     unsigned j;
     for (j = 0; j < mhdr->ncmds; ++j, (sc = (Mach_segment_command *)((sc->cmdsize >> 2) + (unsigned *)sc))) {
          DPRINTF("  #%%d  cmd=%%x  cmdsize=%%x  vmsize=%%x\\n", j, sc->cmd, sc->cmdsize, sc->vmsize);
          if (LC_SEGMENT == sc->cmd && !sc->vmsize) {

               struct b_info h;
               xread(xi, (unsigned char *)&h, sizeof(h));
               DPRINTF("    0==.vmsize; skipping %%x\\n", h.sz_cpr);
               xi->buf += h.sz_cpr;
          }
          if (LC_SEGMENT == sc->cmd && sc->vmsize) {
               Extent xo;
               size_t mlen = xo.size = sc->filesize;
               xo.buf = (void *)(reloc + sc->vmaddr);
               Addr addr = (Addr)xo.buf;
               Addr haddr = sc->vmsize + addr;
               size_t frag = addr & ~PAGE_MASK;
               addr -= frag;
               mlen += frag;

               DPRINTF("    mlen=%%p  frag=%%p  addr=%%p\\n", mlen, frag, addr);
               if (0 != mlen) {
                    size_t const mlen3 = mlen
#if defined(__x86_64__)

                                         + (xi ? 3 : 0)
#endif
                       ;
                    unsigned const prot = VM_PROT_READ | VM_PROT_WRITE;

                    unsigned const flags = MAP_FIXED | MAP_PRIVATE | ((xi || 0 == sc->filesize) ? MAP_ANON : 0);
                    int const fdm = ((xi || 0 == sc->filesize) ? MAP_ANON_FD : fdi);
                    off_t_upx_stub const offset = sc->fileoff + fat_offset;

                    DPRINTF("mmap  addr=%%p  len=%%p  prot=%%x  flags=%%x  fd=%%d  off=%%p  reloc=%%p\\n",
                            addr,
                            mlen3,
                            prot,
                            flags,
                            fdm,
                            offset,
                            reloc);
                    {
                         Addr maddr = (Addr)mmap((void *)addr, mlen3, prot, flags, fdm, offset, 0);
                         DPRINTF("maddr=%%p\\n", maddr);
                         if (maddr != addr) {
                              err_exit(8);
                         }
                         addr = maddr;
                    }
                    if (mhdrpp && !*mhdrpp) {
                         *mhdrpp = (Mach_header *)addr;
                    }
               }
               if (xi && 0 != sc->filesize) {
                    if (0 == sc->fileoff) {
                         *mhdrpp = (Mach_header *)(void *)addr;
                    }
                    unpackExtent(xi, &xo, f_exp, f_unf);
               }
               DPRINTF("xi=%%p  mlen=%%p  fileoff=%%p  nsects=%%d\\n", xi, mlen, sc->fileoff, sc->nsects);
               if (xi && mlen && !sc->fileoff && sc->nsects) {

                    union {
                         unsigned char * p0;
                         unsigned short *p1;
                         unsigned int * p2;
                         unsigned long * p3;
                    } u;
                    u.p0 = (unsigned char *)addr;
                    Mach_segment_command *segp = (Mach_segment_command *)((((char *)sc - (char *)mhdr) >> 2) + u.p2);
                    Mach_section_command *const secp = (Mach_section_command *)(1 + segp);
                    unsigned * hatch = -2 + (secp->offset >> 2) + u.p2;
                    DPRINTF("hatch=%%p  segp=%%p  secp=%%p  secp->offset=%%p  mhdr=%%p\\n",
                            hatch,
                            segp,
                            secp,
                            secp->offset,
                            addr);
#if defined(__aarch64__)
                    hatch[0] = 0xd4000001;
                    hatch[1] = 0xd65f03c0;
#elif defined(__arm__)
                    hatch[0] = 0xef000000;
                    hatch[1] = 0xe12fff1e;
#elif defined(__x86_64__)
                    hatch[0] = 0xc3050f90;
#elif defined(__i386__)
                    hatch[0] = 0xc3050f90;
#endif
                    rv = (Addr)hatch;
               }

               frag = (-mlen) & ~PAGE_MASK;
               bzero((void *)(mlen + addr), frag);
               if (0 != mlen && 0 != mprotect((void *)addr, mlen, sc->initprot)) {
                    err_exit(10);
                    ERR_LAB
               }
               addr += mlen + frag;
               if (
#if SIMULATE_ON_LINUX_EABI4
                  0 != addr &&
#endif
                  addr < haddr) {
                    if (0 != addr
                        && addr
                              != (Addr)mmap((void *)addr,
                                            haddr - addr,
                                            sc->initprot,
                                            MAP_FIXED | MAP_PRIVATE | MAP_ANON,
                                            MAP_ANON_FD,
                                            0,
                                            0)) {
                         err_exit(9);
                    }
               }
               else if (xi) {
                    mlen = ~PAGE_MASK & (3 + mlen);
                    if (mlen <= 3) {
                         DPRINTF("munmap  %%x  %%x\\n", addr, mlen);
                         munmap((char *)addr, mlen);
                    }
               }
          }
          else if (!xi && (LC_UNIXTHREAD == sc->cmd || LC_THREAD == sc->cmd)) {
               Mach_thread_command *const thrc = (Mach_thread_command *)sc;
               DPRINTF("thread_command= %%p\\n", sc);
               if (1

               ) {
                    DPRINTF("thread_state= %%p  flavor=%%d  count=%%x  reloc=%%p\\n",
                            &thrc->state,
                            thrc->flavor,
                            thrc->count,
                            reloc);
#if defined(__aarch64__)
                    rv = reloc + thrc->state.pc;
#elif defined(__arm__)
                    rv = reloc + thrc->state.pc;
#elif defined(__x86_64__)
                    rv = reloc + thrc->state.rip;
#elif defined(__i386__)
                    rv = reloc + thrc->state.eip;
#else
#error do_xmap rv $ARCH
#endif
               }
          }
     }
     DPRINTF("do_xmap= %%p\\n", rv);
     return rv;
}

Addr upx_main(Mach_header **const mhdrpp,
              f_unfilter *const f_unf,
              f_expand *const f_decompress,
              Mach_header *const mhdr,
              size_t const sz_mhdr,
              size_t volatile sz_compressed,
              struct l_info const *const li)
{
     Addr entry;
     off_t_upx_stub fat_offset = 0;
     Extent xi, xo, xi0;
     xi.buf = CONST_CAST(unsigned char *, 1 + (struct p_info const *)(1 + li));
     xi.size = sz_compressed - (sizeof(struct l_info) + sizeof(struct p_info));
     xo.buf = (unsigned char *)mhdr;
     xo.size = ((struct b_info const *)(void const *)xi.buf)->sz_unc;
     xi0 = xi;

     DPRINTF("upx_main szc=%%x  f_dec=%%p  f_unf=%%p  "
             "  xo=%%p(%%x %%p)  xi=%%p(%%x %%p)  mhdrpp=%%p\\n",
             sz_compressed,
             f_decompress,
             f_unf,
             &xo,
             xo.size,
             xo.buf,
             &xi,
             xi.size,
             xi.buf,
             mhdrpp);

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
               fat:
                    if ((ssize_t)sz_mhdr != pread(fdi, (void *)mhdr, sz_mhdr, fat_offset, 0)) {
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

                              Fat_header *const fh = (Fat_header *)mhdr;
                              Fat_arch * fa = (Fat_arch *)(1 + fh);
                              bswap(fh, sizeof(*fh) + (fh->nfat_arch >> 24) * sizeof(*fa));
                              for (j = 0; j < fh->nfat_arch; ++j, ++fa) {
                                   if (CPU_TYPE_I386 == fa->cputype) {
                                        fat_offset = fa->offset;
                                        goto fat;
                                   }
                              }
                         } break;
                    }
                    entry = do_xmap(mhdr, fat_offset, 0, fdi, 0, 0, 0);
                    close(fdi);
                    break;
               }
     }

     return entry;
}
