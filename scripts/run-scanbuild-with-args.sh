#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset

# following checkers are disabled on purpose:
# Clann does not suppor attribute cleanup and this is causing false positives in following checkers:
# unix.Malloc
# alpha.unix.SimpleStream
# alpha.unix.Stream
# https://bugs.llvm.org/show_bug.cgi?id=3888

# These are disabled for other reasons:
# alpha.clone.CloneChecker # way too many false positives
# alpha.core.CastToStruct # we use this pattern too much, hard to avoid in many cases
# alpha.deadcode.UnreachableCode # false positives/flags sanity checks depending on implementation details
# alpha.security.MallocOverflow # not smart enough to infer max values from data types

exec scan-build --status-bugs -no-failure-reports \
-disable-checker  unix.Malloc \
-enable-checker   alpha.core.BoolAssignment \
-enable-checker   alpha.core.CallAndMessageUnInitRefArg \
-enable-checker   alpha.core.CastSize \
-enable-checker   alpha.core.Conversion \
-enable-checker   alpha.core.DynamicTypeChecker \
-enable-checker   alpha.core.FixedAddr \
-enable-checker   alpha.core.IdenticalExpr \
-enable-checker   alpha.core.PointerArithm \
-enable-checker   alpha.core.PointerSub \
-enable-checker   alpha.core.SizeofPtr \
-enable-checker   alpha.core.TestAfterDivZero \
-enable-checker   alpha.cplusplus.IteratorRange \
-enable-checker   alpha.cplusplus.MisusedMovedObject \
-enable-checker   alpha.security.ArrayBound \
-enable-checker   alpha.security.ArrayBoundV2 \
-enable-checker   alpha.security.ReturnPtrRange \
-enable-checker   alpha.security.taint.TaintPropagation \
-enable-checker   alpha.unix.BlockInCriticalSection \
-enable-checker   alpha.unix.Chroot \
-enable-checker   alpha.unix.PthreadLock \
-enable-checker   alpha.unix.cstring.BufferOverlap \
-enable-checker   alpha.unix.cstring.NotNullTerminated \
-enable-checker   alpha.unix.cstring.OutOfBounds \
-enable-checker   nullability.NullableDereferenced \
-enable-checker   nullability.NullablePassedToNonnull \
-enable-checker   nullability.NullableReturnedFromNonnull \
-enable-checker   optin.performance.Padding \
-enable-checker   optin.portability.UnixAPI \
-enable-checker   security.FloatLoopCounter \
-enable-checker   valist.CopyToSelf \
-enable-checker   valist.Uninitialized \
-enable-checker   valist.Unterminated

