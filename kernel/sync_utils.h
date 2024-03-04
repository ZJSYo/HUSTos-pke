#ifndef _SYNC_UTILS_H_
#define _SYNC_UTILS_H_

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
static inline void lock(volatile int *lock) {
  int local = 0;
  do {
    asm volatile("amoswap.w %0, %2, (%1)"
                : "=r"(local)
                : "r"(lock), "r"(1)
                : "memory");
  } while(local);
}

static inline void unlock(volatile int *lock) {
  asm volatile("sw zero, (%0)"
              :
              : "r"(lock)
              : "memory");
}

#endif