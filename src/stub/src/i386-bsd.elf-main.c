#include "include/bsd.h"
#if 1
#define DPRINTF(a) 
#else
#include "stdarg.h"

static int unsimal(unsigned x, char *ptr, int n)
{
     if (10 <= x) {
          n = unsimal(x / 10, ptr, n);
          x %= 10;
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

extern char const *STR_hex();

static int heximal(unsigned x, char *ptr, int n)
{
     if (16 <= x) {
          n = heximal(x >> 4, ptr, n);
          x &= 0xf;
     }
     ptr[n] = STR_hex()[x];
     return 1 + n;
}

#define DPRINTF(a) dprintf a
extern char const *STR_0x();
extern char const *STR_xread();
extern char const *STR_unpackExtent();
extern char const *STR_make_hatch_arm();
extern char const *STR_auxv_up();
extern char const *STR_xfind_pages();
extern char const *STR_do_xmap();
extern char const *STR_upx_main();

static int dprintf(char const *fmt, ...)
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
                    case 'p':
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

#define MAX_ELF_HDR 512

struct Extent {
     size_t size;
     char * buf;
};

static void
#if (ACC_CC_GNUC >= 0x030300) && defined(__i386__)
   __attribute__((__noinline__, __used__, regparm(3), stdcall))
#endif
   xread(struct Extent *x, char *buf, size_t count)
{
     char * p = x->buf, *q = buf;
     size_t j;
     DPRINTF((STR_xread(), x, x->size, x->buf, buf, count));
     if (x->size < count) {
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
static void err_exit(int a) __attribute__((__noreturn__));
{
     (void)a;
     exit(127);
}
#endif

static void *do_brk(void *addr)
{
     return brk(addr);
}

typedef void f_unfilter(nrv_byte *, nrv_uint, unsigned cto8, unsigned ftid);
typedef int f_expand(const nrv_byte *, nrv_uint, nrv_byte *, nrv_uint *, unsigned);

static void
   unpackExtent(struct Extent *const xi, struct Extent *const xo, f_expand *const f_decompress, f_unfilter *f_unf)
{
     DPRINTF((STR_unpackExtent(), xi, xi->size, xi->buf, xo, xo->size, xo->buf, f_decompress, f_unf));
     while (xo->size) {
          struct b_info h;

          xread(xi, (char *)&h, sizeof(h));
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
               nrv_uint out_len = h.sz_unc;
               int const j = (*f_decompress)(
                  (unsigned char *)xi->buf, h.sz_cpr, (unsigned char *)xo->buf, &out_len, *(int *)(void *)&h.b_method);
               if (j != 0 || out_len != (nrv_uint)h.sz_unc)
                    err_exit(7);

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

#if defined(__i386__)

static void *make_hatch_x86(Elf32_Phdr const *const phdr, unsigned const reloc)
{
     unsigned *hatch = 0;
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (((hatch = (void *)(phdr->p_memsz + phdr->p_vaddr + reloc)),
               (phdr->p_memsz == phdr->p_filesz && 4 <= (~PAGE_MASK & -(int)hatch)))

              || ((hatch = (void *)(&((Elf32_Ehdr *)phdr->p_vaddr + reloc)->e_ident[12])), (phdr->p_offset == 0))) {

               unsigned escape = 0xc3c980cd;

               if (*(volatile unsigned *)hatch != escape) {
                    *hatch = escape;
               }
          }
     }
     return hatch;
}
#elif defined(__arm__)
static void *make_hatch_arm(Elf32_Phdr const *const phdr, unsigned const reloc)
{
     unsigned *hatch = 0;
     DPRINTF((STR_make_hatch_arm(), phdr, reloc));
     if (phdr->p_type == PT_LOAD && phdr->p_flags & PF_X) {
          if (((hatch = (void *)(phdr->p_memsz + phdr->p_vaddr + reloc)),
               (phdr->p_memsz == phdr->p_filesz && 8 <= (~PAGE_MASK & -(int)hatch)))

              || ((hatch = (void *)(&((Elf32_Ehdr *)phdr->p_vaddr + reloc)->e_ident[8])), (phdr->p_offset == 0))) {
               hatch[0] = 0xef90005b;
               hatch[1] = 0xe1a0f00e;
          }
     }
     return hatch;
}
#endif

static void
#if defined(__i386__)
   __attribute__((regparm(2), stdcall))
#endif
   upx_bzero(char *p, size_t len)
{
     if (len)
          do {
               *p++ = 0;
          } while (--len);
}
#define bzero upx_bzero

static void
#if defined(__i386__)
   __attribute__((regparm(3), stdcall))
#endif
   auxv_up(Elf32_auxv_t *av, unsigned const type, unsigned const value)
{
     DPRINTF((STR_auxv_up(), av, type, value));
     if (av
#if defined(__i386__)
         && 0 == (1 & (int)av)
#endif
     )
          for (;; ++av) {
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

#define MAP_ANON_FD -1

static unsigned long
#if defined(__i386__)
   __attribute__((regparm(3), stdcall))
#endif
   xfind_pages(unsigned mflags, Elf32_Phdr const *phdr, int phnum, char **const p_brk)
{
     size_t lo = ~0, hi = 0, szlo = 0;
     char * addr;
     DPRINTF((STR_xfind_pages(), mflags, phdr, phnum, p_brk));
     mflags += MAP_PRIVATE | MAP_ANONYMOUS;
     for (; --phnum >= 0; ++phdr)
          if (PT_LOAD == phdr->p_type) {
               if (phdr->p_vaddr < lo) {
                    lo = phdr->p_vaddr;
                    szlo = phdr->p_filesz;
               }
               if (hi < (phdr->p_memsz + phdr->p_vaddr)) {
                    hi = phdr->p_memsz + phdr->p_vaddr;
               }
          }
     szlo += ~PAGE_MASK & lo;
     lo -= ~PAGE_MASK & lo;
     hi = PAGE_MASK & (hi - lo - PAGE_MASK - 1);
     szlo = PAGE_MASK & (szlo - PAGE_MASK - 1);
     addr = mmap((void *)lo, hi, PROT_NONE, mflags, MAP_ANON_FD, 0);
     *p_brk = hi + addr;

     return (unsigned long)addr - lo;
}

static Elf32_Addr do_xmap(int const fdi,
                          Elf32_Ehdr const *const ehdr,
                          struct Extent *const xi,
                          Elf32_auxv_t *const av,
                          unsigned * p_reloc,
                          f_unfilter *const f_unf)
{
     Elf32_Phdr const *phdr = (Elf32_Phdr const *)(ehdr->e_phoff + (void const *)ehdr);
     char * v_brk;
     unsigned const reloc = xfind_pages(((ET_EXEC == ehdr->e_type) ? MAP_FIXED : 0), phdr, ehdr->e_phnum, &v_brk);
     int j;
     DPRINTF((STR_do_xmap(), fdi, ehdr, xi, (xi ? xi->size : 0), (xi ? xi->buf : 0), av, p_reloc, f_unf));
     for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
          if (PT_PHDR == phdr->p_type) {
               if (xi) {
                    auxv_up(av, AT_PHDR, phdr->p_vaddr + reloc);
               }
          }
          else if (PT_LOAD == phdr->p_type) {
               unsigned const prot = PF_TO_PROT(phdr->p_flags);
               struct Extent xo;
               size_t mlen = xo.size = phdr->p_filesz;
               char * addr = xo.buf = (char *)(phdr->p_vaddr + reloc);
               char * haddr = phdr->p_memsz + addr;
               size_t frag = (int)addr & ~PAGE_MASK;
               mlen += frag;
               addr -= frag;

               if (addr
                   != (xi ? mmap(addr,
                                 mlen
#if defined(__i386__)

                                    + 3
#endif
                                 ,
                                 prot | PROT_WRITE,
                                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
                                 MAP_ANON_FD,
                                 0)
                          : mmap(addr, mlen, prot, MAP_FIXED | MAP_PRIVATE, fdi, phdr->p_offset - frag))) {
                    err_exit(8);
               }
               if (xi) {
                    unpackExtent(xi, &xo, (f_expand *)fdi, ((PROT_EXEC & prot) ? f_unf : 0));
               }

               frag = (-mlen) & ~PAGE_MASK;
               if (PROT_WRITE & prot) {
                    bzero(mlen + addr, frag);
               }
               if (xi) {
#if defined(__i386__)
                    void *const hatch = make_hatch_x86(phdr, reloc);
                    if (0 != hatch) {

                         auxv_up((Elf32_auxv_t *)(~1 & (int)av), AT_NULL, (unsigned)hatch);
                    }
#elif defined(__arm__)
                    void *const hatch = make_hatch_arm(phdr, reloc);
                    if (0 != hatch) {
                         auxv_up((Elf32_auxv_t *)(void *)av, AT_NULL, (unsigned)hatch);
                    }
#endif
                    if (0 != mprotect(addr, mlen, prot)) {
                         err_exit(10);
                         ERR_LAB
                    }
               }
               addr += mlen + frag;
               if (addr < haddr) {
                    if (addr
                        != mmap(addr, haddr - addr, prot, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, MAP_ANON_FD, 0)) {
                         err_exit(9);
                    }
               }
#if defined(__i386__)
               else if (xi) {
                    mlen = ~PAGE_MASK & (3 + mlen);
                    if (mlen <= 3) {
                         munmap(addr, mlen);
                    }
               }
#endif
          }
     if (!xi) {
          if (0 != close(fdi)) {
               err_exit(11);
          }
     }
     else {
          if (ET_DYN != ehdr->e_type) {

               do_brk(v_brk);
          }
     }
     if (0 != p_reloc) {
          *p_reloc = reloc;
     }
     return ehdr->e_entry + reloc;
}
void *upx_main(Elf32_auxv_t *const av,
               unsigned const sz_compressed,
               f_expand *const f_decompress,
               f_unfilter * f_unfilter,
               struct Extent xo,
               struct Extent xi,
               unsigned const volatile dynbase) __asm__("upx_main");

void *upx_main(Elf32_auxv_t *const av,
               unsigned const sz_compressed,
               f_expand *const f_decompress,
               f_unfilter * f_unf,
               struct Extent xo,
               struct Extent xi,
               unsigned const volatile dynbase)
{
     Elf32_Ehdr *const ehdr = (Elf32_Ehdr *)(void *)xo.buf;
     Elf32_Phdr const *phdr = (Elf32_Phdr const *)(1 + ehdr);
     Elf32_Addr reloc;
     Elf32_Addr entry;

     size_t const sz_pckhdrs = xi.size;

     DPRINTF(
        (STR_upx_main(), av, sz_compressed, f_decompress, f_unf, &xo, xo.size, xo.buf, &xi, xi.size, xi.buf, dynbase));
#if defined(__i386__)
     f_unf = (f_unfilter *)(2 + (long)f_decompress);
#endif

     unpackExtent(&xi, &xo, f_decompress, 0);

     xi.buf -= sz_pckhdrs;
     xi.size = sz_compressed;

     auxv_up(av, AT_PAGESZ, PAGE_SIZE);
     auxv_up(av, AT_PHNUM, ehdr->e_phnum);
     auxv_up(av, AT_PHENT, ehdr->e_phentsize);
     auxv_up(av, AT_PHDR, dynbase + (unsigned)(1 + (Elf32_Ehdr *)phdr->p_vaddr));

     entry = do_xmap((int)f_decompress, ehdr, &xi, av, &reloc, f_unf);
     auxv_up(av, AT_ENTRY, entry);

     {
          int j;
          for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
               if (PT_INTERP == phdr->p_type) {
                    int const fdi = open(reloc + (char const *)phdr->p_vaddr, O_RDONLY, 0);
                    if (0 > fdi) {
                         err_exit(18);
                    }
                    if (MAX_ELF_HDR != read(fdi, (void *)ehdr, MAX_ELF_HDR)) {
                         ERR_LAB
                         err_exit(19);
                    }
                    entry = do_xmap(fdi, ehdr, 0, 0, &reloc, 0);
                    auxv_up(av, AT_BASE, reloc);
                    break;
               }
     }

     return (void *)entry;
}
