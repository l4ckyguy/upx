#include "include/linux.h"
#define MAX_ELF_HDR 512

struct Extent {
     size_t size;
     char * buf;
};

static void xread(struct Extent *x, char *buf, size_t count)
{
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
     exit(127);
}
#endif

static void *do_brk(void *addr)
{
     return brk(addr);
}

extern char *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);

typedef int f_expand(const nrv_byte *, nrv_uint, nrv_byte *, nrv_uint *, int method);

static void unpackExtent(struct Extent *const xi, struct Extent *const xo, f_expand *const f_decompress)
{
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

static void bzero(char *p, size_t len)
{
     if (len)
          do {
               *p++ = 0;
          } while (--len);
}

#define REP8(x) ((x) | ((x) << 4) | ((x) << 8) | ((x) << 12) | ((x) << 16) | ((x) << 20) | ((x) << 24) | ((x) << 28))
#define EXP8(y) ((1 & (y)) ? 0xf0f0f0f0 : (2 & (y)) ? 0xff00ff00 : (4 & (y)) ? 0xffff0000 : 0)
#define PF_TO_PROT(pf) \
     (7 \
      & (((REP8(PROT_EXEC) & EXP8(PF_X)) | (REP8(PROT_READ) & EXP8(PF_R)) | (REP8(PROT_WRITE) & EXP8(PF_W))) \
         >> ((pf & (PF_R | PF_W | PF_X)) << 2)))

static unsigned long __attribute__((regparm(3), stdcall))
xfind_pages(unsigned mflags, Elf32_Phdr const *phdr, int phnum)
{
     size_t lo = ~0, hi = 0, szlo = 0;
     char * addr;
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
     if (MAP_FIXED & mflags) {
          do_brk((void *)hi);
     }
     szlo += ~PAGE_MASK & lo;
     lo -= ~PAGE_MASK & lo;
     hi = PAGE_MASK & (hi - lo - PAGE_MASK - 1);
     szlo = PAGE_MASK & (szlo - PAGE_MASK - 1);
     addr = mmap((void *)lo, hi, PROT_READ | PROT_WRITE | PROT_EXEC, mflags, -1, 0);

     return (unsigned long)addr - lo;
}
static Elf32_Addr do_xmap(int const fdi, Elf32_Ehdr const *const ehdr, Elf32_auxv_t *const av)
{
#define EM_386 3
     if (EM_386 != ehdr->e_machine) {
          return 1;
     }
     Elf32_Phdr const * phdr = (Elf32_Phdr const *)(ehdr->e_phoff + (char const *)ehdr);
     unsigned long const reloc = xfind_pages(((ET_DYN != ehdr->e_type) ? MAP_FIXED : 0), phdr, ehdr->e_phnum);
     int j;
     for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
          if (PT_PHDR == phdr->p_type) {
               av[AT_PHDR - 1].a_un.a_val = phdr->p_vaddr;
          }
          else if (PT_LOAD == phdr->p_type) {
               unsigned const prot = PF_TO_PROT(phdr->p_flags);
               struct Extent xo;
               size_t mlen = xo.size = phdr->p_filesz;
               char * addr = xo.buf = (char *)phdr->p_vaddr;
               char * haddr = phdr->p_memsz + addr;
               size_t frag = (int)addr & ~PAGE_MASK;
               mlen += frag;
               addr -= frag;
               addr += reloc;
               haddr += reloc;

               if (addr
                   != mmap(addr, mlen, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fdi, phdr->p_offset - frag)) {
                    err_exit(8);
               }
               bzero(addr, frag);
               frag = (-mlen) & ~PAGE_MASK;
               bzero(mlen + addr, frag);
               if (0 != mprotect(addr, mlen, prot)) {
                    err_exit(10);
                    ERR_LAB
               }
               addr += mlen + frag;
               if (addr < haddr) {
                    if (addr != mmap(addr, haddr - addr, prot, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) {
                         err_exit(9);
                    }
               }
          }
     if (0 != close(fdi)) {
          err_exit(11);
     }
     return ehdr->e_entry + reloc;
}

static Elf32_Addr getexec(char const *const fname, Elf32_Ehdr *const ehdr, Elf32_auxv_t *const av)
{
     int const fdi = open(fname, O_RDONLY, 0);
     if (0 > fdi) {
          err_exit(18);
          ERR_LAB
     }
     if (MAX_ELF_HDR != read(fdi, (void *)ehdr, MAX_ELF_HDR)) {
          err_exit(19);
     }
     return do_xmap(fdi, ehdr, av);
}
void *upx_main(Elf32_auxv_t *const av,
               unsigned const junk,
               f_expand *const f_decompress,
               Elf32_Ehdr *const ehdr,
               struct Extent xi,
               struct Extent xo) __asm__("upx_main");

void *upx_main(Elf32_auxv_t *const av,
               unsigned const junk,
               f_expand *const f_decompress,
               Elf32_Ehdr *const ehdr,
               struct Extent xi,
               struct Extent xo)
{

     char *volatile fn = UPX2 + xo.buf;
     char *volatile efn = UPX3 + fn;
     Elf32_Addr entry;

     (void)junk;
     unpackExtent(&xi, &xo, f_decompress);

     {
          char const c = *efn;
          *efn = 0;
          entry = getexec(fn, ehdr, av);
          *efn = c;
          if (1 == entry) {
               return (void *)entry;
          }

          av[AT_PHDR - 1].a_type = AT_PHDR;
          av[AT_PHENT - 1].a_type = AT_PHENT;
          av[AT_PHENT - 1].a_un.a_val = ehdr->e_phentsize;
          av[AT_PHNUM - 1].a_type = AT_PHNUM;
          av[AT_PHNUM - 1].a_un.a_val = ehdr->e_phnum;
          av[AT_PAGESZ - 1].a_type = AT_PAGESZ;
          av[AT_PAGESZ - 1].a_un.a_val = PAGE_SIZE;
          av[AT_ENTRY - 1].a_type = AT_ENTRY;
          av[AT_ENTRY - 1].a_un.a_val = entry;
     }

     {
          Elf32_Phdr const *phdr = (Elf32_Phdr *)(1 + ehdr);
          int j;
          for (j = 0; j < ehdr->e_phnum; ++phdr, ++j)
               if (PT_INTERP == phdr->p_type) {
                    entry = getexec((char const *)phdr->p_vaddr, ehdr, 0);
                    break;
               }
     }

     return (void *)entry;
}
