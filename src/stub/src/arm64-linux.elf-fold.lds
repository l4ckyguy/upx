/* arm64-linux.elf-fold.lds -- static linker script to build arm64-linux.elf-fold.bin

   This file is part of the UPX executable compressor.

   Copyright (C) 2000-2021 John F. Reiser
   All Rights Reserved.

   UPX and the UCL library are free software; you can redistribute them
   and/or modify them under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of
   the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.
   If not, write to the Free Software Foundation, Inc.,
   59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Markus F.X.J. Oberhumer              Laszlo Molnar
   <markus@oberhumer.com>               <ezerotven+github@gmail.com>

   John F. Reiser

 */


OUTPUT_FORMAT("elf64-littleaarch64", "elf64-bigaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
/*ENTRY(_start)*/
PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS ( 5 ) ;  /* r-x (no -w-) */
    data PT_LOAD ;  /* for setting brk(0) */
}
SECTIONS
{
  . = 0x00100000 + SIZEOF_HEADERS + 12;  /* 12==sizeof(l_info) */
  .text : {
    *(.text)
    *(.data)
  } : text
  .data : {
  } : data
}
