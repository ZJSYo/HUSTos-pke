/*
 * contains the implementation of all syscalls.
 */

#include <stdint.h>
#include <errno.h>

#include "util/types.h"
#include "syscall.h"
#include "string.h"
#include "process.h"
#include "util/functions.h"

#include "spike_interface/spike_utils.h"
#include "elf.h"
extern struct elf_sym_table elf_sym_tab;
//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char* buf, size_t n) {
    sprint(buf);
    return 0;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code) {
    sprint("User exit with code:%d.\n", code);
    // in lab1, PKE considers only one app (one process).
    // therefore, shutdown the system when the app calls exit()
    shutdown(code);
}
int print_func_name(uint64 ret_addr) {
    for(int i=0;i<elf_sym_tab.sym_count;i++){
        if (ret_addr >= elf_sym_tab.sym[i].st_value && ret_addr < elf_sym_tab.sym[i].st_value + elf_sym_tab.sym[i].st_size) {
            sprint("%s\n", elf_sym_tab.sym_names[i]);
            if (strcmp(elf_sym_tab.sym_names[i], "main") == 0)//到main函数就返回
                return 0;
            return 1;
        }
    }
    return 1;
}
ssize_t sys_user_print_backtrace(uint64 n) {
//  sprint("back trace the user app in the following:\n");
//  sprint("sp:%lx,s0:%lx", current->trapframe->regs.sp, current->trapframe->regs.s0);
//  sprint("print backtrace\n");
    uint64 user_s0 = current->trapframe->regs.s0;//得到s0
    uint64 user_sp = user_s0;//sp = s0，得到用户态的sp
    uint64 user_ra = user_sp + 8; //ra = sp + 8，得到用户态的ra
    for (int i=0;i<n;i++){
//      sprint("backtrace %d: ra:%p\n",i,user_ra);
        if(print_func_name(*(uint64*)user_ra)==0)//将ra指向的地址转换为uint64，然后调用print_func_name
        return i;

      user_ra = user_ra + 16;//每次移动2个字长
    }
    return 0;
}

//
// [a0]: the syscall number; [a1] ... [a7]: arguments to the syscalls.
// returns the code of success, (e.g., 0 means success, fail for otherwise)
//
long do_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
    switch (a0) {
        case SYS_user_print:
            return sys_user_print((const char*)a1, a2);
        case SYS_user_exit:
            return sys_user_exit(a1);
        case SYS_user_print_backtrace:
            return sys_user_print_backtrace(a1);
        default:
            panic("Unknown syscall %ld \n", a0);
    }
}
