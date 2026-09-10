#ifndef ATTR_H
#define ATTR_H

// wrapper: __has_attribute
#ifndef __has_attribute
#define __has_attribute(attr) 0
#endif

// attribute: unused
#if __has_attribute(unused)
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

// attribute: nonnull
#if __has_attribute(nonnull)
#define NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define NONNULL(...)
#endif

// attribute: noreturn
#if __has_attribute(__noreturn__)
#define NORETURN __attribute__((__noreturn__))
#else
#define NORETURN
#endif

// attribute: packed
#if __has_attribute(__packed__)
#define PACKIT __attribute__((__packed__))
#else
#define PACKIT
#endif

#endif
