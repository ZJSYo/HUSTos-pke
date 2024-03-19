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

  // load elf. vfs_elf_load() is defined above.
  if (vfs_elf_load(p, &elfloader, elf_file) != EL_OK)
    panic("Fail on loading elf.\n");

  // entry (virtual, also physical in lab1_x) address
  p->trapframe->epc = elfloader.ehdr.entry;

  // close the host spike file
  vfs_close(elf_file);

  sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
}

// elf_status elf_change(process *p, elf_ctx *ctx, struct file *file){
//   elf_prog_header ph_addr;
//   int i, off;
//   sprint("elf_change\n");
//   for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
//     if(vfs_elf_pread(file, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) {
//       return EL_EIO;}
//     if(ph_addr.type != ELF_PROG_LOAD) continue;
//     if(ph_addr.memsz < ph_addr.filesz) return EL_ERR;
//     if(ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

//     if(ph_addr.flags == (SEGMENT_READABLE|SEGMENT_EXECUTABLE)){
//       //代码段
//       for(int j=0;j<PGSIZE/sizeof(mapped_region);j++){
//         if(p->mapped_info[j].seg_type == CODE_SEGMENT){
//           sprint( "CODE_SEGMENT added at mapped info offset:%d\n", j );
//           // 释放原来的代码段
//           user_vm_unmap((pagetable_t)p->pagetable, p->mapped_info[j].va, PGSIZE, 1);
//           // 重新映射新的代码段
//           void *dest = elf_process_alloc_mb(p, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);
//           if(vfs_elf_pread(file, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
//             return EL_EIO;
//           p->mapped_info[j].va = ph_addr.vaddr;
//           p->mapped_info[j].npages = 1;
//           p->mapped_info[j].seg_type = CODE_SEGMENT;
//           break;
//         }
//       }
//     }else if ( ph_addr.flags == (SEGMENT_READABLE|SEGMENT_WRITABLE) ){
//       int found = 0;//标记是否找到了数据段
//       for(int j=0;j<PGSIZE/sizeof(mapped_region);j++){
//         if(p->mapped_info[j].seg_type == DATA_SEGMENT){
//           sprint( "DATA_SEGMENT added at mapped info offset:%d\n", j );
//           // 释放原来的数据段
//           user_vm_unmap((pagetable_t)p->pagetable, p->mapped_info[j].va, PGSIZE, 1);
//           // 重新映射新的数据段
//           void *dest = elf_process_alloc_mb(p, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);
//           if(vfs_elf_pread(file, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
//             return EL_EIO;
//           p->mapped_info[j].va = ph_addr.vaddr;
//           p->mapped_info[j].npages = 1;
//           p->mapped_info[j].seg_type = DATA_SEGMENT;
//           found = 1;
//           break;
//         }
//       }
//       if(found==0){// 不存在数据段
//         void * dest = elf_process_alloc_mb(p, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);
//         if(vfs_elf_pread(file, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
//           return EL_EIO;
//         for(int j = 0; j < PGSIZE / sizeof(mapped_region); j++) {
//           if(p->mapped_info[j].va == 0) {
//             sprint( "DATA_SEGMENT added at mapped info offset:%d\n", j );
//             p->mapped_info[j].npages = 1;
//             p->mapped_info[j].va = ph_addr.vaddr;
//             p->mapped_info[j].seg_type = DATA_SEGMENT;
//             p->total_mapped_region++;
//             break;
//           }
//         }
//       }
//     }else{
//       panic( "unknown program segment encountered, segment flag:%d.\n", ph_addr.flags );
//     }
//   }
//   return EL_OK;
// }

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