#ifndef _SYNC_UTILS_H_
#define _SYNC_UTILS_H_

/* 同步屏障
 * 使所有进程同步到某一点
 * 当counter -> local == all时，所有进程都到达了同步点,函数返回，所有hard_thread同步
 * 参数：
 *      counter:目前已经到达的进程数
 *      all:总进程数
 */
static inline void sync_barrier(volatile int *counter, int all) {

  int local;

  asm volatile("amoadd.w %0, %2, (%1)\n"
               : "=r"(local)
               : "r"(counter), "r"(1)
               : "memory");

  if (local + 1 < all) {
    do {
      asm volatile("lw %0, (%1)\n" : "=r"(local) : "r"(counter) : "memory");
    } while (local < all);
  }
}

#endif