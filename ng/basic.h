
#pragma once
#ifndef NIGHTINGALE_BASIC_H
#define NIGHTINGALE_BASIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CAT_(x, y) x##y
#define CAT(x, y) CAT_(x, y)

#define X86_64 1
#define I686 0

// Compiler independant attributes

// You could make the argument that I choose bad names, since '__' is
// reserved for the compiler, but the odds they use these in the near
// future (esp. since the Linux kernel uses these exact #defines) is
// so low I don't really care.  I like that it's clear that these are
// attributes, and prefer them over the alternatives I know of, (PACKED,
// _packed, or just packed).

#ifdef __GNUC__
#define __packed __attribute__((packed))
#define __noreturn __attribute__((noreturn))
#define __used __attribute__((used))

// maybe switch to this
#define PACKED __packed
#define NORETURN __noreturn
#define USED __used

#ifndef noreturn
#define noreturn __noreturn
#endif

#else
#error                                                                         \
    "Need to support non-__GNUC__ attributes.  Edit basic.h for your compiler"
#endif

// GCC stack smasking protection
extern uintptr_t __stack_chk_guard;
void __stack_chk_fail(void);

#define asm __asm__

static inline intptr_t max(intptr_t a, intptr_t b) {
        return (a > b) ? a : b;
}

static inline intptr_t min(intptr_t a, intptr_t b) {
        return (a < b) ? a : b;
}

static inline size_t umax(size_t a, size_t b) {
        return (a > b) ? a : b;
}

static inline size_t umin(size_t a, size_t b) {
        return (a < b) ? a : b;
}

static inline uintptr_t round_up(uintptr_t val, uintptr_t place) {
        return (val + place - 1) & ~(place - 1);
}

static inline uintptr_t round_down(uintptr_t val, uintptr_t place) {
        return val & ~(place - 1);
}

#endif
