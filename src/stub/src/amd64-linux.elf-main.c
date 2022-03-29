#include "include/linux.h"

#ifndef DEBUG
#define DEBUG 0
#endif

#if !DEBUG
#define DPRINTF(fmt,args...) 
#else

#if defined(__powerpc__)
#define DPRINTF(fmt,args...) \
     ({ \
          char const *r_fmt; \
          asm("bl 0f; .string \"" fmt "\"; .balign 4; 0: mflr %0" : "=r"(r_fmt) : : "lr"); \
          dprintf(r_fmt, args); \
     })
#elif defined(__x86_64)
#define DPRINTF(fmt,args...) \
     ({ \
          char const *r_fmt; \
          asm("call 0f; .asciz \"" fmt "\"; 0: pop %0" : "=r"(r_fmt)); \
          dprintf(r_fmt, args); \
     })
#elif defined(__aarch64__)
#define DPRINTF(fmt,args...) \
     ({ \
          char const *r_fmt; \
          asm("bl 0f; .string \"" fmt "\"; .balign 4; 0: mov %0,x30" : "=r"(r_fmt) : : "x30"); \
          dprintf(r_fmt, args); \
     })

#endif

static int dprintf(char const *fmt, ...);
#endif
#define MAX_ELF_HDR 1024

typedef struct {
     size_t size;
     char * buf;
} Extent;

static void xread(Extent *x, char *buf, size_t count)
{
     DPRINTF("xread x.size=%%x  x.buf=%%p  buf=%%p  count=%%x\\n", x->size, x->buf, buf, count);
     char * p = x->buf, *q = buf;
     size_t j;
     if (x->size < count) {
          exit(127);
     }
     for (j = count; 0 != j--; ++p, ++q) {
          *q = *p;
     }
     x->buf += count;
     x->size -= count;
     DPRINTF("xread done\\n", 0);
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
     (void)a;
     DPRINTF("err_exit %%d\\n", a);
     exit(127);
}
#endif

typedef void f_unfilter(nrv_byte *, nrv_uint, unsigned cto8, unsigned ftid);
typedef int f_expand(const nrv_byte *, nrv_uint, nrv_byte *, size_t *, unsigned);

static void unpackExtent(Extent *const xi, Extent *const xo, f_expand *const f_exp, f_unfilter *f_unf)
{
     while (xo->size) {
          DPRINTF("unpackExtent xi=(%%p %%p)  xo=(%%p %%p)  f_exp=%%p  f_unf=%%p\\n",
                  xi->size,
                  xi->buf,
                  xo->size,
                  xo->buf,
                  f_exp,
                  f_unf);
          struct b_info h;

          xread(xi, (char *)&h, sizeof(h));
          DPRINTF("h.sz_unc=%%x  h.sz_cpr=%%x  h.b_method=%%x\\n", h.sz_unc, h.sz_cpr, h.b_method);
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
               err_exit(5);
          }

          if (h.sz_cpr < h.sz_unc) {
               size_t out_len = h.sz_unc;
               int const j = (*f_exp)((unsigned char *)xi->buf,
                                      h.sz_cpr,
                                      (unsigned char *)xo->buf,
                                      &out_len,
#if defined(__x86_64)
                                      *(int *)(void *)&h.b_method
#elif defined(__powerpc64__) || defined(__aarch64__)
                                      h.b_method
#endif
               );
               if (j != 0 || out_len != (nrv_uint)h.sz_unc) {
                    DPRINTF("j=%%x  out_len=%%x  &h=%%p\\n", j, out_len, &h);
                    err_exit(7);
               }

               if (h.b_ftid != 0 && f_unf && ((512 < out_len) || (xo->size == (unsigned)h.sz_unc))) {
                    (*f_unf)((unsigned char *)xo->buf, out_len, h.b_cto8, h.b_ftid);
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

#if defined(__x86_64__)
static void *make_hatch_x86_64(Elf64_Phdr const *const phdr, Elf64_Addr reloc, unsigned const frag_mask)
{
     unsigned xprot = 0;
     unsigned *hatch = 0;
     DPRINTF("make_hatch %%p %%x %%x\\n", phdr, reloc, frag_mask);
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (

             ((hatch = (void *)(phdr->p_memsz + phdr->p_vaddr + reloc)),
              (phdr->p_memsz == phdr->p_filesz && (1 * 4) <= (frag_mask & -(int)(size_t)hatch)))

             || ((hatch = (void *)(&((Elf64_Ehdr *)(phdr->p_vaddr + reloc))->e_ident[12])), (phdr->p_offset == 0))

             || (xprot = 1, hatch = mmap(0, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))) {
               hatch[0] = 0xc35a050f;
               if (xprot) {
                    mprotect(hatch, 1 * sizeof(unsigned), PROT_EXEC | PROT_READ);
               }
          }
          else {
               hatch = 0;
          }
     }
     return hatch;
}
#elif defined(__powerpc64__)
static unsigned ORRX(unsigned ra, unsigned rs, unsigned rb)
{
     return (31 << 26) | ((037 & (rs)) << 21) | ((037 & (ra)) << 16) | ((037 & (rb)) << 11) | (444 << 1) | 0;
}

static void *make_hatch_ppc64(Elf64_Phdr const *const phdr, Elf64_Addr reloc, unsigned const frag_mask)
{
     unsigned xprot = 0;
     unsigned *hatch = 0;
     DPRINTF("make_hatch %%p %%x %%x\\n", phdr, reloc, frag_mask);
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (

             ((hatch = (void *)(phdr->p_memsz + phdr->p_vaddr + reloc)),
              (phdr->p_memsz == phdr->p_filesz && (3 * 4) <= (frag_mask & -(int)(size_t)hatch)))

             || ((hatch = (void *)(&((Elf64_Phdr *)(1 + ((Elf64_Ehdr *)(phdr->p_vaddr + reloc))))[1].p_paddr)),
                 (phdr->p_offset == 0))

             || (xprot = 1, hatch = mmap(0, 1 << 12, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))) {
               hatch[0] = 0x44000002;
               hatch[1] = ORRX(12, 31, 31);
               hatch[2] = 0x4e800020;
               if (xprot) {
                    mprotect(hatch, 3 * sizeof(unsigned), PROT_EXEC | PROT_READ);
               }
          }
          else {
               hatch = 0;
          }
     }
     return hatch;
}
#elif defined(__aarch64__)
static void *make_hatch_arm64(Elf64_Phdr const *const phdr, uint64_t const reloc, unsigned const frag_mask)
{
     unsigned xprot = 0;
     unsigned *hatch = 0;

     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (

             ((hatch = (void *)(~3ul & (3 + phdr->p_memsz + phdr->p_vaddr + reloc))),
              (phdr->p_memsz == phdr->p_filesz && (2 * 4) <= (frag_mask & -(int)(uint64_t)hatch)))

             || ((hatch = (void *)(&((Elf64_Ehdr *)(phdr->p_vaddr + reloc))->e_ident[8])), (phdr->p_offset == 0))

             || (xprot = 1, hatch = mmap(0, 1 << 12, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))) {
               hatch[0] = 0xd4000001;
               hatch[1] = 0xd65f03c0;
               if (xprot) {
                    mprotect(hatch, 2 * sizeof(unsigned), PROT_EXEC | PROT_READ);
               }
          }
          else {
               hatch = 0;
          }
     }
     return hatch;
}
#endif

#if defined(__powerpc64__) || defined(__aarch64__)
static void upx_bzero(char *p, size_t len)
{
     DPRINTF("bzero %%x  %%x\\n", p, len);
     if (len)
          do {
               *p++ = 0;
          } while (--len);
}
#define bzero upx_bzero
#else
#define bzero(a,b) __builtin_memset(a, 0, b)
#endif

static void auxv_up(Elf64_auxv_t *av, unsigned const type, uint64_t const value)
{
     if (!av || (1 & (size_t)av)) {
          return;
     }
     DPRINTF("\\nauxv_up %%d  %%p\\n", type, value);
     for (;; ++av) {
          DPRINTF("  %%d  %%p\\n", av->a_type, av->a_un.a_val);
          if (av->a_type == type || (av->a_type == AT_IGNORE && type != AT_NULL)) {
               av->a_type = type;
               av->a_un.a_val = value;
               return;
          }
          if (av->a_type == AT_NULL) {

               return;
          }
     }
}

#define REP8(x) ((x) | ((x) << 4) | ((x) << 8) | ((x) << 12) | ((x) << 16) | ((x) << 20) | ((x) << 24) | ((x) << 28))
#define EXP8(y) ((1 & (y)) ? 0xf0f0f0f0 : (2 & (y)) ? 0xff00ff00 : (4 & (y)) ? 0xffff0000 : 0)
#define PF_TO_PROT(pf) \
     ((PROT_READ | PROT_WRITE | PROT_EXEC) \
      & (((REP8(PROT_EXEC) & EXP8(PF_X)) | (REP8(PROT_READ) & EXP8(PF_R)) | (REP8(PROT_WRITE) & EXP8(PF_W))) \
         >> ((pf & (PF_R | PF_W | PF_X)) << 2)))

static Elf64_Addr xfind_pages(unsigned mflags,
                              Elf64_Phdr const *phdr,
                              int phnum,
                              Elf64_Addr *const p_brk,
                              Elf64_Addr const elfaddr
#if defined(__powerpc64__) || defined(__aarch64__)
                              ,
                              size_t const PAGE_MASK
#endif
)
{
     Elf64_Addr lo = ~0, hi = 0, addr = 0;
     mflags += MAP_PRIVATE | MAP_ANONYMOUS;
     DPRINTF("xfind_pages  %%x  %%p  %%d  %%p  %%p\\n", mflags, phdr, phnum, elfaddr, p_brk);
     for (; --phnum >= 0; ++phdr)
          if (PT_LOAD == phdr->p_type) {
               if (phdr->p_vaddr < lo) {
                    lo = phdr->p_vaddr;
               }
               if (hi < (phdr->p_memsz + phdr->p_vaddr)) {
                    hi = phdr->p_memsz + phdr->p_vaddr;
               }
          }
     lo -= ~PAGE_MASK & lo;
     hi = PAGE_MASK & (hi - lo - PAGE_MASK - 1);
     if (MAP_FIXED & mflags) {
          addr = lo;
     }
     else if (0 == lo) {
          addr = elfaddr;
          if (addr) {
               mflags |= MAP_FIXED;
          }
     }
     DPRINTF("  addr=%%p  lo=%%p  hi=%%p\\n", addr, lo, hi);

     addr = (Elf64_Addr)mmap((void *)addr, hi, (DEBUG ? PROT_WRITE : PROT_NONE), mflags, -1, 0);
     DPRINTF("  addr=%%p\\n", addr);
     *p_brk = hi + addr;
     return (Elf64_Addr)(addr - lo);
}

static Elf64_Addr do_xmap(Elf64_Ehdr const *const ehdr,
                          Extent *const xi,
                          int const fdi,
                          Elf64_auxv_t *const av,
                          f_expand *const f_exp,
                          f_unfilter *const f_unf,
                          Elf64_Addr * p_reloc
#if defined(__powerpc64__) || defined(__aarch64__)
                          ,
                          size_t const PAGE_MASK
#endif
)
{
     Elf64_Phdr const *phdr = (Elf64_Phdr const *)(void const *)(ehdr->e_phoff + (char const *)ehdr);
     Elf64_Addr v_brk;
     Elf64_Addr reloc;
     if (xi) {

          Elf64_Addr ehdr0 = *p_reloc;
          Elf64_Phdr *phdr0 = (Elf64_Phdr *)(((Elf64_Ehdr *)ehdr0)->e_phoff + ehdr0);

          ehdr0 -= phdr0[1].p_vaddr;
          if (ET_EXEC == ehdr->e_type) {
               ehdr0 = phdr0[0].p_vaddr;
          }
          v_brk = phdr0->p_memsz + ehdr0;
          reloc = (Elf64_Addr)mmap(
             (void *)ehdr0, phdr0->p_memsz, PROT_NONE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
          if (ET_EXEC == ehdr->e_type) {
               reloc = 0;
          }
     }
     else {
          reloc = xfind_pages(((ET_DYN != ehdr->e_type) ? MAP_FIXED : 0),
                              phdr,
                              ehdr->e_phnum,
                              &v_brk,
                              *p_reloc
#if defined(__powerpc64__) || defined(__aarch64__)
                              ,
                              PAGE_MASK
#endif
          );
     }
     DPRINTF("do_xmap reloc=%%p\\n", reloc);
     int j;
     for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
          if (xi && PT_PHDR == phdr->p_type) {
               auxv_up(av, AT_PHDR, phdr->p_vaddr + reloc);
          }
          else if (PT_LOAD == phdr->p_type) {
               if (xi && !phdr->p_offset) {

                    auxv_up(av, AT_PHDR, phdr->p_vaddr + reloc + ehdr->e_phoff);
                    auxv_up(av, AT_PHNUM, ehdr->e_phnum);
                    auxv_up(av, AT_PHENT, ehdr->e_phentsize);
               }
               unsigned const prot = PF_TO_PROT(phdr->p_flags);
               Extent xo;
               size_t mlen = xo.size = phdr->p_filesz;
               char * addr = xo.buf = reloc + (char *)phdr->p_vaddr;
               char * haddr = phdr->p_memsz + addr;
               size_t frag = (size_t)addr & ~PAGE_MASK;
               mlen += frag;
               addr -= frag;

               if (addr
                   != mmap(addr,
                           mlen,
                           prot | (xi ? PROT_WRITE : 0),
                           MAP_FIXED | MAP_PRIVATE | (xi ? MAP_ANONYMOUS : 0),
                           (xi ? -1 : fdi),
                           phdr->p_offset - frag)) {
                    err_exit(8);
               }
               if (xi) {
                    unpackExtent(xi, &xo, f_exp, f_unf);
               }

               frag = (-mlen) & ~PAGE_MASK;
               if (PROT_WRITE & prot) {
                    bzero(mlen + addr, frag);
               }
               if (xi) {
#if defined(__x86_64)
                    void *const hatch = make_hatch_x86_64(phdr, reloc, ~PAGE_MASK);
#elif defined(__powerpc64__)
                    void *const hatch = make_hatch_ppc64(phdr, reloc, ~PAGE_MASK);
#elif defined(__aarch64__)
                    void *const hatch = make_hatch_arm64(phdr, reloc, ~PAGE_MASK);
#endif
                    if (0 != hatch) {
                         auxv_up((Elf64_auxv_t *)(~1 & (size_t)av), AT_NULL, (size_t)hatch);
                    }
                    if (0 != mprotect(addr, mlen, prot)) {
                         err_exit(10);
                         ERR_LAB
                    }
               }
               addr += mlen + frag;
               if (addr < haddr) {
                    if (addr != mmap(addr, haddr - addr, prot, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) {
                         err_exit(9);
                    }
               }
          }
     if (xi) {
          if (ET_DYN != ehdr->e_type) {
          }
     }
     if (p_reloc) {
          *p_reloc = reloc;
     }
     return ehdr->e_entry + reloc;
}
void *upx_main(struct b_info const *const bi,
               size_t const sz_compressed,
               Elf64_Ehdr *const ehdr,
               Elf64_auxv_t *const av,
               f_expand *const f_exp,
               f_unfilter *const f_unf
#if defined(__x86_64)
               ,
               Elf64_Addr elfaddr
#elif defined(__powerpc64__)
               ,
               Elf64_Addr * p_reloc,
               size_t const PAGE_MASK
#elif defined(__aarch64__)
               ,
               Elf64_Addr elfaddr,
               size_t const PAGE_MASK
#endif
)
{
     Extent xo, xi1, xi2;
     xo.buf = (char *)ehdr;
     xo.size = bi->sz_unc;
     xi2.buf = CONST_CAST(char *, bi);
     xi2.size = bi->sz_cpr + sizeof(*bi);
     xi1.buf = CONST_CAST(char *, bi);
     xi1.size = sz_compressed;

     unpackExtent(&xi2, &xo, f_exp, 0);

#if defined(__x86_64) || defined(__aarch64__)
     Elf64_Addr *const p_reloc = &elfaddr;
#endif
     DPRINTF("upx_main1  .e_entry=%%p  p_reloc=%%p  *p_reloc=%%p  PAGE_MASK=%%p\\n",
             ehdr->e_entry,
             p_reloc,
             *p_reloc,
             PAGE_MASK);
     Elf64_Phdr *phdr = (Elf64_Phdr *)(1 + ehdr);

     Elf64_Addr entry = do_xmap(ehdr,
                                &xi1,
                                0,
                                av,
                                f_exp,
                                f_unf,
                                p_reloc
#if defined(__powerpc64__) || defined(__aarch64__)
                                ,
                                PAGE_MASK
#endif
     );
     DPRINTF("upx_main2  entry=%%p  *p_reloc=%%p\\n", entry, *p_reloc);
     auxv_up(av, AT_ENTRY, entry);

     {
          phdr = (Elf64_Phdr *)(1 + ehdr);
          unsigned j;
          for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
               if (PT_INTERP == phdr->p_type) {
                    char const *const iname = *p_reloc + (char const *)phdr->p_vaddr;
                    int const fdi = open(iname, O_RDONLY, 0);
                    if (0 > fdi) {
                         err_exit(18);
                    }
                    if (MAX_ELF_HDR != read(fdi, (void *)ehdr, MAX_ELF_HDR)) {
                         ERR_LAB
                         err_exit(19);
                    }

                    *p_reloc = 0;
                    entry = do_xmap(ehdr,
                                    0,
                                    fdi,
                                    0,
                                    0,
                                    0,
                                    p_reloc
#if defined(__powerpc64__) || defined(__aarch64__)
                                    ,
                                    PAGE_MASK
#endif
                    );
                    auxv_up(av, AT_BASE, *p_reloc);
                    close(fdi);
               }
     }

     return (void *)entry;
}

#if DEBUG

#if defined(__powerpc64__)
#define __NR_write 4

typedef unsigned long size_t;

#if 0
static int
write(int fd, char const *ptr, size_t len)
{
    register int sys asm("r0") = __NR_write;
    register int a0 asm("r3") = fd;
    register void const *a1 asm("r4") = ptr;
    register size_t const a2 asm("r5") = len;
    __asm__ __volatile__("sc"
    : "=r"(a0)
    : "r"(sys), "r"(a0), "r"(a1), "r"(a2)
    : "r0", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13"
    );
    return a0;
}
#else
ssize_t write(int fd, void const *ptr, size_t len)
{
     register int sys asm("r0") = __NR_write;
     register int a0 asm("r3") = fd;
     register void const *a1 asm("r4") = ptr;
     register size_t a2 asm("r5") = len;
     __asm__ __volatile__("sc"
                          : "+r"(sys), "+r"(a0), "+r"(a1), "+r"(a2)
                          :
                          : "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13");
     return a0;
}
#endif
#endif

static int unsimal(unsigned x, char *ptr, int n)
{
     unsigned m = 10;
     while (10 <= (x / m))
          m *= 10;
     while (10 <= x) {
          unsigned d = x / m;
          x -= m * d;
          m /= 10;
          ptr[n++] = '0' + d;
     }
     ptr[n++] = '0' + x;
     return n;
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

#define va_arg __builtin_va_arg
#define va_end __builtin_va_end
#define va_list __builtin_va_list
#define va_start __builtin_va_start

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
                    n += write(2, buf, heximal(va_arg(va, int), buf, 2));
               } break;
          }
     }
done:
     va_end(va);
     return n;
}
#endif
