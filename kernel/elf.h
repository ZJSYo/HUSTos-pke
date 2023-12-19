#ifndef _ELF_H_
#define _ELF_H_

#include "util/types.h"
#include "process.h"

#define MAX_CMDLINE_ARGS 64

// elf header structure--elf 头部结构
typedef struct elf_header_t {
  uint32 magic;
  uint8 elf[12];
  uint16 type;      /* Object file type */
  uint16 machine;   /* Architecture */
  uint32 version;   /* Object file version */
  uint64 entry;     /* Entry point virtual address */
  uint64 phoff;     /* Program header table file offset */
  uint64 shoff;     /* Section header table file offset 节头表偏移 */
  uint32 flags;     /* Processor-specific flags */
  uint16 ehsize;    /* ELF header size in bytes */
  uint16 phentsize; /* Program header table entry size */
  uint16 phnum;     /* Program header table entry count */
  uint16 shentsize; /* Section header table entry size 节头表大小*/
  uint16 shnum;     /* Section header table entry count 节的数量 */
  uint16 shstrndx;  /* Section header string table index -- TODO 字符串表索引 */
} elf_header;

// Program segment header. -- 段头
typedef struct elf_prog_header_t {
  uint32 type;   /* Segment type */
  uint32 flags;  /* Segment flags */
  uint64 off;    /* Segment file offset */
  uint64 vaddr;  /* Segment virtual address */
  uint64 paddr;  /* Segment physical address */
  uint64 filesz; /* Segment size in file */
  uint64 memsz;  /* Segment size in memory */
  uint64 align;  /* Segment alignment */
} elf_prog_header;

// Section header. -- 节头
typedef struct elf_sect_header_t{//每个header之间用"\0"隔开
    uint32 sh_name; /* Section name (string tbl index) */
    uint32 sh_type; /* Section type */
    uint64 sh_flags; /* Section flags */
    uint64 sh_addr; /* Section virtual addr at execution 节的虚拟地址*/
    uint64 sh_offset; /* 与文件头的偏移 */
    uint64 sh_size; /* Section size in bytes */
    uint32 sh_link; /* Link to another section */
    uint32 sh_info; /* Additional section information */
    uint64 sh_addralign; /* Section alignment */
    uint64 sh_entsize; /* Entry size if section holds table */
}elf_sect_header;


#define ELF_MAGIC 0x464C457FU  // "\x7FELF" in little endian
#define ELF_PROG_LOAD 1

typedef enum elf_status_t {
  EL_OK = 0,

  EL_EIO,
  EL_ENOMEM,
  EL_NOTELF,
  EL_ERR,

} elf_status;

// elf_symbol --符号表项结构
typedef struct elf_symbol_t {
  uint32 st_name; /* Symbol name (string tbl index) */
  uint8 st_info;  /* Symbol type and binding */
  uint8 st_other; /* Symbol visibility */
  uint16 st_shndx; /* Section index,节的索引 */
  uint64 st_value; /* Symbol value ,地址*/
  uint64 st_size; /* Symbol size ，符号大小*/
} elf_sym;

typedef struct elf_ctx_t {
  void *info;
  elf_header ehdr;
} elf_ctx;

// symbol table -- 符号表
struct elf_sym_table{
    elf_sym sym[64];
    char sym_names[64][32];
    int sym_count;
};
elf_status elf_init(elf_ctx *ctx, void *info);
elf_status elf_load(elf_ctx *ctx);

void load_bincode_from_host_elf(process *p);

#endif
