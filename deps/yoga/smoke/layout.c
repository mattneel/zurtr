/*
 * Yoga's C API, exercised from C the way a consumer uses it.
 *
 * This is the proof that the vendored library is not merely compiling: it includes Yoga's headers
 * by their installed path (`<yoga/YGNode.h>`, not a relative include), builds a tree, asks Yoga to
 * lay it out, and prints the geometry Yoga computed. The numbers below 180 are never mentioned to
 * Yoga — it derives them from the fixed root, the padding, and the two flex factors — so a program
 * that prints them is a program that ran the layout engine.
 *
 * Copyright (c) the zurtr authors. MIT, like the library it exercises.
 */

#include <stdio.h>

#include <yoga/YGEnums.h>
#include <yoga/YGNode.h>
#include <yoga/YGNodeLayout.h>
#include <yoga/YGNodeStyle.h>
#include <yoga/YGValue.h>

static int failures;

/* Print a node's computed box, and check it against the geometry the styles imply. */
static void report(
    const char* name,
    YGNodeConstRef node,
    float wantLeft,
    float wantTop,
    float wantWidth,
    float wantHeight) {
  const float got[4] = {
      YGNodeLayoutGetLeft(node),
      YGNodeLayoutGetTop(node),
      YGNodeLayoutGetWidth(node),
      YGNodeLayoutGetHeight(node),
  };
  const float want[4] = {wantLeft, wantTop, wantWidth, wantHeight};
  const char* const field[4] = {"left", "top", "width", "height"};

  printf(
      "  %-7s left %6.1f  top %6.1f  width %6.1f  height %6.1f\n",
      name,
      got[0],
      got[1],
      got[2],
      got[3]);

  for (int i = 0; i < 4; ++i) {
    if (got[i] < want[i] - 0.01f || got[i] > want[i] + 0.01f) {
      fprintf(
          stderr,
          "  %s: %s is %.2f, expected %.2f\n",
          name,
          field[i],
          got[i],
          want[i]);
      ++failures;
    }
  }
}

int main(void) {
  printf("Yoga C API layout smoke\n");

  /* A fixed root: 200x100, row direction, 10pt padding -> a 180x80 content box to divide. */
  YGNodeRef root = YGNodeNew();
  YGNodeStyleSetWidth(root, 200.0f);
  YGNodeStyleSetHeight(root, 100.0f);
  YGNodeStyleSetFlexDirection(root, YGFlexDirectionRow);
  YGNodeStyleSetPadding(root, YGEdgeAll, 10.0f);

  /* Two children with different flex styles: growth weights 1 and 2 (so 60/120 of the content
   * box), different fixed heights, and a top margin that only the second one has. */
  YGNodeRef first = YGNodeNew();
  YGNodeStyleSetFlexGrow(first, 1.0f);
  YGNodeStyleSetHeight(first, 40.0f);

  YGNodeRef second = YGNodeNew();
  YGNodeStyleSetFlexGrow(second, 2.0f);
  YGNodeStyleSetHeight(second, 60.0f);
  YGNodeStyleSetMargin(second, YGEdgeTop, 12.0f);

  YGNodeInsertChild(root, first, 0);
  YGNodeInsertChild(root, second, 1);

  printf(
      "  root 200x100, %s, padding 10 -> content box 180; children grow 1 : 2\n",
      YGFlexDirectionToString(YGNodeStyleGetFlexDirection(root)));

  /* The sizes are left to the root's own style, so both dimensions are undefined here. */
  YGNodeCalculateLayout(root, YGUndefined, YGUndefined, YGDirectionLTR);

  report("root", root, 0.0f, 0.0f, 200.0f, 100.0f);
  report("first", first, 10.0f, 10.0f, 60.0f, 40.0f);
  report("second", second, 70.0f, 22.0f, 120.0f, 60.0f);

  YGNodeFreeRecursive(root);

  if (failures != 0) {
    fprintf(stderr, "FAILED: %d layout value(s) differ\n", failures);
    return 1;
  }

  printf("OK\n");
  return 0;
}
