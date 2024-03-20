/*
 * routines that scan and load a (host) Executable and Linkable Format (ELF) file
 * into the (emulated) memory.
 */

#include "elf.h"
#include "string.h"
#include "riscv.h"
#include "vmm.h"
#include "pmm.h"
#include "vfs.h"
#include "spike_interface/spike_utils.h"

typedef struct elf_info_t {
  struct file *f;
  process *p;
} elf_info;

//
// the implementation of allocater. allocates memory space for later segment loading.
// this allocater is heavily modified @lab2_1, where we do NOT work in bare mode.
//
static void *elf_alloc_mb(elf_ctx *ctx, uint64 elf_pa, uint64 elf_va, uint64 size) {
  elf_info *msg = (elf_info *)ctx->info;
  // we assume that size of proram segment is smaller than a page.
  kassert(size < PGSIZE);
  void *pa = alloc_page();
  if (pa == 0) panic("uvmalloc mem alloc falied\n");

  memset((void *)pa, 0, PGSIZE);
  user_vm_map((pagetable_t)msg->p->pagetable, elf_va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ | PROT_EXEC, 1));

  return pa;
}
static void *elf_process_alloc_mb(process *p, uint64 elf_pa, uint64 elf_va, uint64 size) {
  // we assume that size of proram segment is smaller than a page.
  kassert(size < PGSIZE);
  void *pa = alloc_page();
  if (pa == 0) panic("uvmalloc mem alloc falied\n");

  // memset((void *)pa, 0, PGSIZE);
  user_vm_map(p->pagetable, elf_va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ | PROT_EXEC, 1));
  return pa;
}


// leb128 (little-endian base 128) is a variable-length
// compression algoritm in DWARF
void read_uleb128(uint64 *out, char **off) {
    uint64 value = 0; int shift = 0; uint8 b;
    for (;;) {
        b = *(uint8 *)(*off); (*off)++;
        value |= ((uint64)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (out) *out = value;
}
void read_sleb128(int64 *out, char **off) {
    int64 value = 0; int shift = 0; uint8 b;
    for (;;) {
        b = *(uint8 *)(*off); (*off)++;
        value |= ((uint64_t)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (shift < 64 && (b & 0x40)) value |= -(1 << shift);
    if (out) *out = value;
}

// Since reading below types through pointer cast requires aligned address,
// so we can only read them byte by byte
void read_uint64(uint64 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 8; i++) {
        *out |= (uint64)(**off) << (i << 3); (*off)++;
    }
}
void read_uint32(uint32 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 4; i++) {
        *out |= (uint32)(**off) << (i << 3); (*off)++;
    }
}
void read_uint16(uint16 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 2; i++) {
        *out |= (uint16)(**off) << (i << 3); (*off)++;
    }
}

//
// actual file reading, using the vfs file interface.
//
static uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset) {
  elf_info *msg = (elf_info *)ctx->info;
  vfs_lseek(msg->f, offset, SEEK_SET);
  return vfs_read(msg->f, dest, nb);
}
static uint64 vfs_elf_pread(struct file *elf_file, void *dest, uint64 nb, uint64 offset) {
  vfs_lseek(elf_file, offset, 0);
  return vfs_read(elf_file, dest, nb);
}

//
// init elf_ctx, a data structure that loads the elf.
//
elf_status elf_init(elf_ctx *ctx, void *info) {
  ctx->info = info;

  // load the elf header
  if (elf_fpread(ctx, &ctx->ehdr, sizeof(ctx->ehdr), 0) != sizeof(ctx->ehdr)) return EL_EIO;

  // check the signature (magic value) of the elf
  if (ctx->ehdr.magic != ELF_MAGIC) return EL_NOTELF;

  return EL_OK;
}

elf_status vfs_elf_init(elf_ctx *ctx, struct file *elf_file) {
  if(vfs_elf_pread(elf_file, &ctx->ehdr, sizeof(ctx->ehdr), 0)!= sizeof(ctx->ehdr)) {
    return EL_EIO;
  }
  if (ctx->ehdr.magic != ELF_MAGIC) {
    return EL_NOTELF;
  }
  return EL_OK;
}

/*
* analyzis the data in the debug_line section
*
* the function needs 3 parameters: elf context, data in the debug_line section
* and length of debug_line section
*
* make 3 arrays:
* "process->dir" stores all directory paths of code files
* "process->file" stores all code file names of code files and their directory path index of array "dir"
* "process->line" stores all relationships map instruction addresses to code line numbers
* and their code file name index of array "file"
*/
/*
 * 修改ctx中的info中的process的debug_line(char *)，dir(char **), file(code_file *), line(addr_line *)
 * dir,file,line都是数组，存储在debug_line缓冲区中
 * dir: 存储代码文件的目录名
 * file: 存储代码文件名和目录名的索引
 * line: 存储指令地址、代码行号和代码文件名在file数组中的索引
 * eg. 如某文件第3行为a = 0，被编译成地址为0x1234处的汇编代码li ax, 0和0x1238处的汇编代码sd 0(s0), ax。
 * 那么file数组中就包含两项，addr属性分别为0x1234和0x1238，line属性为3，file属性为“某文件”的文件名在file数组中的索引。
 * 通过解析debug_line中的数据，填充dir、file、line数组
 */
static void make_addr_line(elf_ctx *ctx, char *debug_line, uint64 length,process *p) {
    sprint("make_addr_line\n");
    sprint("\ndebuline=====%s\n",debug_line);
    // p->debugline = debug_line;
    // directory name char pointer array
    p->dir = (char **)((((uint64)debug_line + length + 7) >> 3) << 3); int dir_ind = 0, dir_base;
    // file name char pointer array
    p->file = (code_file *)(p->dir + 64); int file_ind = 0, file_base;
    // table array
    p->line = (addr_line *)(p->file + 64); p->line_ind = 0;
    char *off = debug_line;
    while (off < debug_line + length) { // iterate each compilation unit(CU)
        // sprint("CU\n");
        debug_header *dh = (debug_header *)off; off += sizeof(debug_header);
        dir_base = dir_ind; file_base = file_ind;
        // get directory name char pointer in this CU
        while (*off != 0) {
            // sprint("dir\n");
            p->dir[dir_ind++] = off; while (*off != 0) off++; off++;
        }
        off++;
        // get file name char pointer in this CU
        while (*off != 0) {
            // sprint("file\n");
            p->file[file_ind].file = off; while (*off != 0) off++; off++;
            uint64 dir; read_uleb128(&dir, &off);
            p->file[file_ind++].dir = dir - 1 + dir_base;
            read_uleb128(NULL, &off); read_uleb128(NULL, &off);
        }
        off++; addr_line regs; regs.addr = 0; regs.file = 1; regs.line = 1;
        // simulate the state machine op code
        for (;;) {
            // sprint("op\n");
            uint8 op = *(off++);
            switch (op) {
                case 0: // Extended Opcodes
                    read_uleb128(NULL, &off); op = *(off++);
                    switch (op) {
                        case 1: // DW_LNE_end_sequence
                            if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                            p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                            p->line_ind++; goto endop;
                        case 2: // DW_LNE_set_address
                            read_uint64(&regs.addr, &off); break;
                        // ignore DW_LNE_define_file
                        case 4: // DW_LNE_set_discriminator
                            read_uleb128(NULL, &off); break;
                    }
                    break;
                case 1: // DW_LNS_copy
                    if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                    p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                    p->line_ind++; break;
                case 2: { // DW_LNS_advance_pc
                            uint64 delta; read_uleb128(&delta, &off);
                            regs.addr += delta * dh->min_instruction_length;
                            break;
                        }
                case 3: { // DW_LNS_advance_line
                            int64 delta; read_sleb128(&delta, &off);
                            regs.line += delta; break; } case 4: // DW_LNS_set_file
                        read_uleb128(&regs.file, &off); break;
                case 5: // DW_LNS_set_column
                        read_uleb128(NULL, &off); break;
                case 6: // DW_LNS_negate_stmt
                case 7: // DW_LNS_set_basic_block
                        break;
                case 8: { // DW_LNS_const_add_pc
                            int adjust = 255 - dh->opcode_base;
                            int delta = (adjust / dh->line_range) * dh->min_instruction_length;
                            regs.addr += delta; break;
                        }
                case 9: { // DW_LNS_fixed_advanced_pc
                            uint16 delta; read_uint16(&delta, &off);
                            regs.addr += delta;
                            break;
                        }
                        // ignore 10, 11 and 12
                default: { // Special Opcodes
                             int adjust = op - dh->opcode_base;
                             int addr_delta = (adjust / dh->line_range) * dh->min_instruction_length;
                             int line_delta = dh->line_base + (adjust % dh->line_range);
                             regs.addr += addr_delta;
                             regs.line += line_delta;
                             if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                             p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                             p->line_ind++; break;
                         }
            }
        }
endop:;
    }
}

//
// load the elf segments to memory regions.
//
elf_status elf_load(elf_ctx *ctx) {
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr;
  int i, off;

  // traverse the elf program segment headers
  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
    // read segment headers
    if (elf_fpread(ctx, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) return EL_EIO;

    if (ph_addr.type != ELF_PROG_LOAD) continue;
    if (ph_addr.memsz < ph_addr.filesz) return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

    // allocate memory block before elf loading
    void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);

    // actual loading
    if (elf_fpread(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
      return EL_EIO;

    // record the vm region in proc->mapped_info. added @lab3_1
    int j;
    for( j=0; j<PGSIZE/sizeof(mapped_region); j++ ) //seek the last mapped region
      if( (process*)(((elf_info*)(ctx->info))->p)->mapped_info[j].va == 0x0 ) break;

    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].va = ph_addr.vaddr;
    ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].npages = 1;

    // SEGMENT_READABLE, SEGMENT_EXECUTABLE, SEGMENT_WRITABLE are defined in kernel/elf.h
    if( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_EXECUTABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = CODE_SEGMENT;
      // sprint( "CODE_SEGMENT added at mapped info offset:%d\n", j );
    }else if ( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_WRITABLE) ){
      ((process*)(((elf_info*)(ctx->info))->p))->mapped_info[j].seg_type = DATA_SEGMENT;
      // sprint( "DATA_SEGMENT added at mapped info offset:%d\n", j );
    }else
      panic( "unknown program segment encountered, segment flag:%d.\n", ph_addr.flags );

    ((process*)(((elf_info*)(ctx->info))->p))->total_mapped_region ++;
  }

  return EL_OK;
}
elf_status vfs_elf_load(process *p, elf_ctx *ctx, struct file *elf_file) {
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr;
  int i, off;
  uint64 top = 0;
  // traverse the elf program segment headers
  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
    // read segment headers
    if (vfs_elf_pread(elf_file, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) return EL_EIO;
    
    if (ph_addr.type != ELF_PROG_LOAD) continue;
    if (ph_addr.memsz < ph_addr.filesz) return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

    // allocate memory block before elf loading
    void *dest = elf_process_alloc_mb(p, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);

    // actual loading
    if (vfs_elf_pread(elf_file, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
      return EL_EIO;
      // 更新top--top为elf程序段的最大地址
    if (ph_addr.vaddr + ph_addr.memsz > top) top = ph_addr.vaddr + ph_addr.memsz;

    // record the vm region in proc->mapped_info. added @lab3_1
    int j;
    for( j=0; j<PGSIZE/sizeof(mapped_region); j++ ) //seek the last mapped region
      if( p->mapped_info[j].va == 0x0 ) break;

    p->mapped_info[j].va = ph_addr.vaddr;
    p->mapped_info[j].npages = 1;

    // SEGMENT_READABLE, SEGMENT_EXECUTABLE, SEGMENT_WRITABLE are defined in kernel/elf.h
    if( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_EXECUTABLE) ){
      p->mapped_info[j].seg_type = CODE_SEGMENT;
      // sprint( "CODE_SEGMENT added at mapped info offset:%d\n", j );
    }else if ( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_WRITABLE) ){
      p->mapped_info[j].seg_type = DATA_SEGMENT;
      // sprint( "DATA_SEGMENT added at mapped info offset:%d\n", j );
    }else
      panic( "unknown program segment encountered, segment flag:%d.\n", ph_addr.flags );

    p->total_mapped_region ++;
  }

  elf_sect_header shstrtab,tmp;

  //读入shstrtab
  // elf_fpread(ctx, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)
  // vfs_elf_pread(elf_file, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)
  if(vfs_elf_pread(elf_file,(void*)&shstrtab,sizeof(shstrtab),
                ctx->ehdr.shoff + ctx->ehdr.shstrndx * sizeof(shstrtab)) != sizeof(shstrtab))
      return EL_EIO;
  else{
    sprint("shstrtab 读入成功\n");
  }
  for(i=0,off=ctx->ehdr.shoff;i < ctx->ehdr.shnum;i++,off+=sizeof(tmp)){
      //读入section header_i
    if(vfs_elf_pread(elf_file,(void*)&tmp,sizeof(tmp),off) != sizeof(tmp))
        return EL_EIO;
    else{
      sprint("section header 读入成功\n");
    }
    char all_name[shstrtab.size];
    //读入shstrtab中的所有字符串
    vfs_elf_pread(elf_file,&all_name,shstrtab.size,shstrtab.offset);

    //判断是否为.debug_line section
    if(strcmp(".debug_line",all_name+tmp.name) == 0){
      sprint("debug_line section 开始读入\n");
      if(vfs_elf_pread(elf_file,p->debugline,tmp.size,tmp.offset) != tmp.size)
          return EL_EIO;
      else{
        sprint("debug_line 读入成功\n");
        sprint("debug_line size:%d\n",tmp.size);
        sprint("debug_line == %s\n",p->debugline);
      }
        // make_addr_line(ctx,*,tmp.size,p);
        make_addr_line(ctx,p->debugline,tmp.size,p);
        break;
    }
  }

  return EL_OK;
}


void vfs_load_bincode_from_elf(process *p,char * filename)
{


  sprint("Application: %s\n", filename);

  // elf loading. elf_ctx is defined in kernel/elf.h, used to track the loading process.
  elf_ctx elfloader;
  struct file *elf_file = vfs_open(filename, O_RDONLY);
  sprint("file open status:%d\n", elf_file->status);
  // init elfloader context. vfs_elf_init() is defined above.
  if (vfs_elf_init(&elfloader, elf_file) != EL_OK)
    panic("fail to init elfloader.\n");
  else{
    sprint("elf init success\n");
  }

  // load elf. vfs_elf_load() is defined above.
  if (vfs_elf_load(p, &elfloader, elf_file) != EL_OK)
    panic("Fail on loading elf.\n");
  else{
    sprint("elf load success\n");
  }

  // entry (virtual, also physical in lab1_x) address
  p->trapframe->epc = elfloader.ehdr.entry;

  // close the host spike file
  vfs_close(elf_file);

  sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
}


elf_status elf_change(process *p, elf_ctx *ctx, struct file *file){
  elf_prog_header ph_addr;
  int i, off;

  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr))
  {
    // seek to the program header
    vfs_lseek(file, off, 0); 
    // read the program header
    if(vfs_read(file, (char *)&ph_addr, sizeof(ph_addr)) != sizeof(ph_addr)) 
    {
      return EL_EIO;
    }
    if (ph_addr.type != ELF_PROG_LOAD)
      continue;
    if (ph_addr.memsz < ph_addr.filesz)
      return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr)
      return EL_ERR;
    if (ph_addr.flags == (SEGMENT_READABLE | SEGMENT_EXECUTABLE))
    {
      // 代码段
      for (int j = 0; j < PGSIZE / sizeof(mapped_region); j++)
      {
        if (p->mapped_info[j].seg_type == CODE_SEGMENT)
        {
          // sprint("CODE_SEGMENT added at mapped info offset:%d\n", j);
          // 释放原来的代码段
          user_vm_unmap(p->pagetable, p->mapped_info[j].va, PGSIZE, 0);
          // 重新映射新的代码段
          void *dest = elf_process_alloc_mb(p, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);
          p->mapped_info[j].va = ph_addr.vaddr;
          vfs_lseek(file, ph_addr.off, 0); 
          if(vfs_read(file, dest, ph_addr.memsz) != ph_addr.memsz) {
            return EL_EIO;
          }
          break;
        }
      }
    }
    else if (ph_addr.flags == (SEGMENT_READABLE | SEGMENT_WRITABLE))
    {
      // 数据段
      int found = 0; // 标记是否找到了数据段
      for (int j = 0; j < PGSIZE / sizeof(mapped_region); j++)
      {
        if (p->mapped_info[j].seg_type == DATA_SEGMENT)
        {
          // sprint("DATA_SEGMENT added at mapped info offset:%d\n", j);
          // 释放原来的数据段
          user_vm_unmap((pagetable_t)p->pagetable, p->mapped_info[j].va, PGSIZE, 1);
          // 重新映射新的数据段
          void *dest = elf_process_alloc_mb(p, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);
          vfs_lseek(file, ph_addr.off, 0); // seek to the data segment
          p->mapped_info[j].va = ph_addr.vaddr;
          if(vfs_read(file, dest, ph_addr.memsz) != ph_addr.memsz) {
            return EL_EIO;
          }
          found = 1;
          break;
        }
      }
      if (found == 0)
      { // 不存在数据段, 则不需要释放原来的数据段
        void *dest = elf_process_alloc_mb(p, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);
        vfs_lseek(file, ph_addr.off, 0);
        if(vfs_read(file, dest, ph_addr.memsz) != ph_addr.memsz)
            return EL_EIO;
        for (int j = 0; j < PGSIZE / sizeof(mapped_region); j++)
        {
          if (p->mapped_info[j].va == 0)
          {
            // sprint("DATA_SEGMENT added at mapped info offset:%d\n", j);
            p->mapped_info[j].npages = 1;
            p->mapped_info[j].va = ph_addr.vaddr;
            p->mapped_info[j].seg_type = DATA_SEGMENT;
            p->total_mapped_region++;
            break;
          }
        }
      }
    }
    else
    {
      panic("unknown program segment encountered, segment flag:%d.\n", ph_addr.flags);
    }
  }
  // clear the heap segment
  // for(int j = 0; j < PGSIZE / sizeof(mapped_region); j++) {
  //   if(p->mapped_info[j].seg_type == HEAP_SEGMENT) {
  //     for(uint64 va = p->user_heap.heap_bottom; va < p->user_heap.heap_top; va += PGSIZE) {
  //       user_vm_unmap(p->pagetable, va, PGSIZE, 1); // free the page at the same time
  //     }
  //     p->mapped_info[j].npages = 0;
  //     p->user_heap.heap_top = p->user_heap.heap_bottom;
  //   }
  // }
  return EL_OK;
}

