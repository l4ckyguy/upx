#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <endian.h>
#include <byteswap.h>

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

static char const *progname;

static char const *filename;

static int err(char const *errmsg)
{
     fprintf(stderr, "%s: %s: %s\n", progname, filename, errmsg);
     return FALSE;
}

static int do_reverse_endian;

#define EGET(X) \
     (__extension__({ \
          uint64_t __res; \
          if (!do_reverse_endian) { \
               __res = (X); \
          } \
          else if (sizeof(X) == 1) { \
               __res = (X); \
          } \
          else if (sizeof(X) == 2) { \
               __res = bswap_16((X)); \
          } \
          else if (sizeof(X) == 4) { \
               __res = bswap_32((X)); \
          } \
          else if (sizeof(X) == 8) { \
               __res = bswap_64((X)); \
          } \
          else { \
               fprintf(stderr, "%s: %s: EGET failed for size %ld\n", progname, filename, (long)sizeof(X)); \
               exit(EXIT_FAILURE); \
          } \
          __res; \
     }))

#define ESET(Y,X) \
     do \
          if (!do_reverse_endian) { \
               Y = (X); \
          } \
          else if (sizeof(Y) == 1) { \
               Y = (X); \
          } \
          else if (sizeof(Y) == 2) { \
               Y = bswap_16((uint16_t)(X)); \
          } \
          else if (sizeof(Y) == 4) { \
               Y = bswap_32((uint32_t)(X)); \
          } \
          else if (sizeof(Y) == 8) { \
               Y = bswap_64((uint64_t)(X)); \
          } \
          else { \
               fprintf(stderr, "%s: %s: ESET failed for size %ld\n", progname, filename, (long)sizeof(Y)); \
               exit(EXIT_FAILURE); \
          } \
     while (0)

#define ferr(msg) (err(errno ? strerror(errno) : (msg)))

#define HEADER_FUNCTIONS(CLASS) 

static int readelfheader##CLASS(int fd, Elf##CLASS##_Ehdr *ehdr)
{
     if (read(fd, ((char *)ehdr) + EI_NIDENT, sizeof(*ehdr) - EI_NIDENT) != (ssize_t)sizeof(*ehdr) - EI_NIDENT)
          return ferr("missing or incomplete ELF header.");

     if (EGET(ehdr->e_ehsize) != sizeof(Elf##CLASS##_Ehdr))
          return err("unrecognized ELF header size.");
     if (EGET(ehdr->e_phentsize) != sizeof(Elf##CLASS##_Phdr))
          return err("unrecognized program segment header size.");

     if (EGET(ehdr->e_type) != ET_EXEC && EGET(ehdr->e_type) != ET_DYN)
          return err("not an executable or shared-object library.");

     return TRUE;
}

static int readphdrtable##CLASS(int fd, Elf##CLASS##_Ehdr const *ehdr, Elf##CLASS##_Phdr **phdrs)
{
     size_t size;

     if (!EGET(ehdr->e_phoff) || !EGET(ehdr->e_phnum))
          return err("ELF file has no program header table.");

     size = EGET(ehdr->e_phnum) * sizeof **phdrs;
     if (!(*phdrs = malloc(size)))
          return err("Out of memory!");

     errno = 0;
     if (read(fd, *phdrs, size) != (ssize_t)size)
          return ferr("missing or incomplete program segment header table.");

     return TRUE;
}

static int getmemorysize##CLASS(Elf##CLASS##_Ehdr const *ehdr, Elf##CLASS##_Phdr const *phdrs, unsigned long *newsize)
{
     Elf##CLASS##_Phdr const *phdr;
     unsigned long size, n;
     size_t i;

     size = EGET(ehdr->e_phoff) + EGET(ehdr->e_phnum) * sizeof *phdrs;
     if (size < sizeof *ehdr)
          size = sizeof *ehdr;

     for (i = 0, phdr = phdrs; i < EGET(ehdr->e_phnum); ++i, ++phdr) {
          if (EGET(phdr->p_type) != PT_NULL) {
               n = EGET(phdr->p_offset) + EGET(phdr->p_filesz);
               if (n > size)
                    size = n;
          }
     }

     *newsize = size;
     return TRUE;
}

static int modifyheaders##CLASS(Elf##CLASS##_Ehdr *ehdr, Elf##CLASS##_Phdr *phdrs, unsigned long newsize)
{
     Elf##CLASS##_Phdr *phdr;
     size_t i;

     if (EGET(ehdr->e_shoff) >= newsize) {
          ESET(ehdr->e_shoff, 0);
          ESET(ehdr->e_shnum, 0);
          ESET(ehdr->e_shentsize, sizeof(Elf##CLASS##_Shdr));
          ESET(ehdr->e_shstrndx, 0);
     }

     for (i = 0, phdr = phdrs; i < EGET(ehdr->e_phnum); ++i, ++phdr) {
          if (EGET(phdr->p_offset) >= newsize) {
               ESET(phdr->p_offset, newsize);
               ESET(phdr->p_filesz, 0);
          }
          else if (EGET(phdr->p_offset) + EGET(phdr->p_filesz) > newsize) {
               newsize -= EGET(phdr->p_offset);
               ESET(phdr->p_filesz, newsize);
          }
     }

     return TRUE;
}

static int commitchanges##CLASS(int fd, Elf##CLASS##_Ehdr const *ehdr, Elf##CLASS##_Phdr *phdrs, unsigned long newsize)
{
     size_t n;

     if (lseek(fd, 0, SEEK_SET))
          return ferr("could not rewind file");
     errno = 0;
     if (write(fd, ehdr, sizeof *ehdr) != (ssize_t)sizeof *ehdr)
          return err("could not modify file");

     if (lseek(fd, EGET(ehdr->e_phoff), SEEK_SET) == (off_t)-1) {
          err("could not seek in file.");
          goto warning;
     }
     n = EGET(ehdr->e_phnum) * sizeof *phdrs;
     if (write(fd, phdrs, n) != (ssize_t)n) {
          err("could not write to file");
          goto warning;
     }

     if (newsize < EGET(ehdr->e_phoff) + n)
          newsize = EGET(ehdr->e_phoff) + n;

     if (ftruncate(fd, newsize)) {
          err("could not resize file");
          goto warning;
     }

     return TRUE;

warning:
     return err("ELF file may have been corrupted!");
}

static int readelfheaderident(int fd, Elf32_Ehdr *ehdr)
{
     errno = 0;
     if (read(fd, ehdr, EI_NIDENT) != EI_NIDENT)
          return ferr("missing or incomplete ELF header.");

     if (!(ehdr->e_ident[EI_MAG0] == ELFMAG0 && ehdr->e_ident[EI_MAG1] == ELFMAG1 && ehdr->e_ident[EI_MAG2] == ELFMAG2
           && ehdr->e_ident[EI_MAG3] == ELFMAG3)) {
          err("missing ELF signature.");
          return -1;
     }

#if __BYTE_ORDER == __LITTLE_ENDIAN
     if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB) {
          do_reverse_endian = 0;
     }
     else if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB) {

          do_reverse_endian = 1;
     }
#elif __BYTE_ORDER == __BIG_ENDIAN
     if (ehdr->e_ident[EI_DATA] == ELFDATA2LSB) {

          do_reverse_endian = 1;
     }
     else if (ehdr->e_ident[EI_DATA] == ELFDATA2MSB) {
          do_reverse_endian = 0;
     }
#else
#error unknown endianness
#endif
     else {
          err("Unsupported endianness");
          return -1;
     }

     return ehdr->e_ident[EI_CLASS];
}

HEADER_FUNCTIONS(32)

HEADER_FUNCTIONS(64)

static int truncatezeros(int fd, unsigned long *newsize)
{
     unsigned char contents[1024];
     unsigned long size, n;

     size = *newsize;
     do {
          n = sizeof contents;
          if (n > size)
               n = size;
          if (lseek(fd, size - n, SEEK_SET) == (off_t)-1)
               return ferr("cannot seek in file.");
          if (read(fd, contents, n) != (ssize_t)n)
               return ferr("cannot read file contents");
          while (n && !contents[--n])
               --size;
     } while (size && !n);

     if (!size)
          return err("ELF file is completely blank!");

     *newsize = size;
     return TRUE;
}

int main(int argc, char *argv[])
{
     int fd;
     union {
          Elf32_Ehdr ehdr32;
          Elf64_Ehdr ehdr64;
     } e;
     union {
          Elf32_Phdr *phdrs32;
          Elf64_Phdr *phdrs64;
     } p;
     unsigned long newsize;
     char ** arg;
     int failures = 0;

     if (argc < 2 || argv[1][0] == '-') {
          printf("Usage: sstrip FILE...\n"
                 "sstrip discards all nonessential bytes from an executable.\n\n"
                 "Version 2.0-X Copyright (C) 2000,2001 Brian Raiter.\n"
                 "Cross-devel hacks Copyright (C) 2004 Manuel Novoa III.\n"
                 "This program is free software, licensed under the GNU\n"
                 "General Public License. There is absolutely no warranty.\n");
          return EXIT_SUCCESS;
     }

     progname = argv[0];

     for (arg = argv + 1; *arg != NULL; ++arg) {
          filename = *arg;

          fd = open(*arg, O_RDWR);
          if (fd < 0) {
               ferr("can't open");
               ++failures;
               continue;
          }

          switch (readelfheaderident(fd, &e.ehdr32)) {
               case ELFCLASS32:
                    if (!(readelfheader32(fd, &e.ehdr32) && readphdrtable32(fd, &e.ehdr32, &p.phdrs32)
                          && getmemorysize32(&e.ehdr32, p.phdrs32, &newsize) && truncatezeros(fd, &newsize)
                          && modifyheaders32(&e.ehdr32, p.phdrs32, newsize)
                          && commitchanges32(fd, &e.ehdr32, p.phdrs32, newsize)))
                         ++failures;
                    break;
               case ELFCLASS64:
                    if (!(readelfheader64(fd, &e.ehdr64) && readphdrtable64(fd, &e.ehdr64, &p.phdrs64)
                          && getmemorysize64(&e.ehdr64, p.phdrs64, &newsize) && truncatezeros(fd, &newsize)
                          && modifyheaders64(&e.ehdr64, p.phdrs64, newsize)
                          && commitchanges64(fd, &e.ehdr64, p.phdrs64, newsize)))
                         ++failures;
                    break;
               default:
                    ++failures;
                    break;
          }
          close(fd);
     }

     return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
