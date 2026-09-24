/*
 * The second flag decision this build makes, checked rather than assumed.
 *
 * `cmake/project-defaults.cmake` asks for `-fexceptions`, and `yoga/debug/AssertFatal.cpp` only
 * throws behind `#if defined(__cpp_exceptions)` — without exceptions the same fatal assert calls
 * `std::terminate()`. Yoga has no `catch` of its own, so a caller that can report a malformed tree
 * instead of dying depends on the exception propagating out of the C API and being unwound by the
 * C++ runtime the *consumer* links. That runtime is libc++/libc++abi, which a Zig build does not
 * get for free: this program throws through Yoga and catches, and fails loudly if the throw is
 * instead fatal.
 *
 * Copyright (c) the zurtr authors. MIT, like the library it exercises.
 */

#include <cstdio>
#include <stdexcept>

#include <yoga/YGNode.h>

int main() {
  std::printf("Yoga C API exception smoke\n");

  YGNodeRef parent = YGNodeNew();
  YGNodeRef other = YGNodeNew();
  YGNodeRef child = YGNodeNew();
  YGNodeInsertChild(parent, child, 0);

  /* A node has one owner: the second insert is a fatal assert. */
  try {
    YGNodeInsertChild(other, child, 0);
    std::fprintf(
        stderr,
        "FAILED: the second YGNodeInsertChild returned instead of throwing\n");
    YGNodeFreeRecursive(parent);
    YGNodeFree(other);
    return 1;
  } catch (const std::logic_error& error) {
    std::printf("  caught std::logic_error: %s\n", error.what());
  }

  YGNodeFreeRecursive(parent);
  YGNodeFree(other);
  std::printf("OK\n");
  return 0;
}
