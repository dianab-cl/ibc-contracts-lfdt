// SPDX-License-Identifier: Apache-2.0

//! Global allocator for the program.
//!
//! Tendermint header verification needs more than 32 KiB of heap, so the relayer sends
//! `ComputeBudgetInstruction::request_heap_frame` with a bigger size. The program does not learn
//! that size, and the entrypoint's built-in allocator only ever hands out the first 32 KiB.
//! [`BumpAllocator`] puts its bookkeeping at the bottom of the heap and hands out memory towards
//! higher addresses, so it can use as much of the heap as the transaction requested. If it hands
//! out memory beyond that, the first access to it fails with an access violation and the
//! transaction aborts.

use core::{
    alloc::{GlobalAlloc, Layout},
    ptr::{self, null_mut},
};

/// Start of the program heap region (`solana_program_entrypoint::HEAP_START_ADDRESS`).
#[cfg(all(target_os = "solana", feature = "custom-heap"))]
const HEAP_START: usize = 0x3_0000_0000;

/// Largest heap a transaction can request (`MAX_HEAP_FRAME_BYTES`).
#[cfg(all(target_os = "solana", feature = "custom-heap"))]
const MAX_HEAP_LENGTH: usize = 256 * 1024;

#[cfg(all(target_os = "solana", feature = "custom-heap"))]
#[global_allocator]
// SAFETY: the runtime maps a zero-initialised heap at `HEAP_START` that only this allocator uses.
static ALLOCATOR: BumpAllocator = unsafe { BumpAllocator::new(HEAP_START, MAX_HEAP_LENGTH) };

/// A bump allocator over a fixed memory region.
///
/// The first word of the region holds the address of the next free byte; zero means nothing has
/// been allocated yet. Memory is only reclaimed when the most recent allocation is freed or
/// resized.
pub struct BumpAllocator {
    start: usize,
    end: usize,
}

impl BumpAllocator {
    /// Creates an allocator over `len` bytes starting at address `start`.
    ///
    /// # Safety
    /// The region must be writable, aligned to `usize`, larger than a `usize`, start
    /// zero-initialised and not be used by anything else while the allocator or any of its
    /// allocations are alive.
    pub const unsafe fn new(start: usize, len: usize) -> Self {
        Self {
            start,
            end: start + len,
        }
    }

    const fn cursor(&self) -> *mut usize {
        self.start as *mut usize
    }

    /// Returns the address of the next free byte.
    unsafe fn next_free(&self) -> usize {
        match *self.cursor() {
            0 => self.start + size_of::<usize>(),
            next => next,
        }
    }

    /// Moves the end of the allocated memory to `end`, if it fits in the region.
    unsafe fn bump_to(&self, end: Option<usize>) -> bool {
        match end {
            Some(end) if end <= self.end => {
                *self.cursor() = end;
                true
            }
            _ => false,
        }
    }

    /// Whether `ptr` with `layout` is the most recent allocation.
    unsafe fn is_last(&self, ptr: *mut u8, layout: Layout) -> bool {
        ptr as usize + layout.size() == self.next_free()
    }
}

unsafe impl GlobalAlloc for BumpAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // `layout.align()` is a power of two.
        let mask = layout.align() - 1;
        let Some(start) = self.next_free().checked_add(mask).map(|addr| addr & !mask) else {
            return null_mut();
        };
        if self.bump_to(start.checked_add(layout.size())) {
            start as *mut u8
        } else {
            null_mut()
        }
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if self.is_last(ptr, layout) {
            *self.cursor() = ptr as usize;
        }
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Resize the most recent allocation in place, which is common when a `Vec` grows.
        if self.is_last(ptr, layout) {
            return if self.bump_to((ptr as usize).checked_add(new_size)) {
                ptr
            } else {
                null_mut()
            };
        }

        // An earlier allocation keeps its place when it shrinks; the freed tail is not reused.
        if new_size <= layout.size() {
            return ptr;
        }

        // SAFETY: the caller guarantees `new_size`, rounded up to `layout.align()`, fits in `isize`.
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
        }
        new_ptr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEN: usize = 1024;

    #[repr(align(16))]
    struct Arena([u8; LEN]);

    fn with_allocator(f: impl FnOnce(&BumpAllocator, usize)) {
        let mut arena = Box::new(Arena([0; LEN]));
        let start = arena.0.as_mut_ptr() as usize;
        // SAFETY: the arena is zeroed, aligned and outlives the allocator.
        let allocator = unsafe { BumpAllocator::new(start, LEN) };
        f(&allocator, start);
    }

    #[test]
    fn allocates_upwards_and_aligned() {
        with_allocator(|a, start| unsafe {
            let first = a.alloc(Layout::from_size_align(3, 1).unwrap()) as usize;
            assert_eq!(first, start + size_of::<usize>());
            let second = a.alloc(Layout::from_size_align(8, 8).unwrap()) as usize;
            assert_eq!(second % 8, 0);
            assert!(second >= first + 3);
            let third = a.alloc(Layout::from_size_align(1, 16).unwrap()) as usize;
            assert_eq!(third % 16, 0);
            assert!(third >= second + 8);
        });
    }

    #[test]
    fn returns_null_when_exhausted() {
        with_allocator(|a, start| unsafe {
            let all = LEN - size_of::<usize>();
            let ptr = a.alloc(Layout::from_size_align(all, 1).unwrap());
            assert_eq!(ptr as usize, start + size_of::<usize>());
            assert!(a.alloc(Layout::from_size_align(1, 1).unwrap()).is_null());
        });
        with_allocator(|a, _| unsafe {
            assert!(a.alloc(Layout::from_size_align(LEN, 1).unwrap()).is_null());
            // A failed allocation does not consume memory.
            assert!(!a.alloc(Layout::from_size_align(16, 1).unwrap()).is_null());
        });
    }

    #[test]
    fn reuses_memory_of_last_allocation() {
        with_allocator(|a, _| unsafe {
            let layout = Layout::from_size_align(32, 8).unwrap();
            let first = a.alloc(layout);
            let second = a.alloc(layout);
            // Freeing an earlier allocation does not reclaim anything.
            a.dealloc(first, layout);
            assert_ne!(a.alloc(layout), first);
            let third = a.alloc(layout);
            a.dealloc(third, layout);
            assert_eq!(a.alloc(layout), third);
            assert_ne!(second, third);
        });
    }

    #[test]
    fn realloc_in_place_and_by_copy() {
        with_allocator(|a, _| unsafe {
            let layout = Layout::from_size_align(4, 4).unwrap();
            let first = a.alloc(layout);
            first.copy_from(b"abcd".as_ptr(), 4);

            // Last allocation grows in place.
            let grown = a.realloc(first, layout, 64);
            assert_eq!(grown, first);
            let layout = Layout::from_size_align(64, 4).unwrap();

            // Not the last allocation any more: moved and copied.
            let _other = a.alloc(Layout::from_size_align(1, 1).unwrap());
            let moved = a.realloc(grown, layout, 128);
            assert_ne!(moved, grown);
            assert_eq!(core::slice::from_raw_parts(moved, 4), b"abcd");

            // Growing past the end fails and leaves the allocation alone.
            let layout = Layout::from_size_align(128, 4).unwrap();
            assert!(a.realloc(moved, layout, LEN).is_null());
            assert_eq!(core::slice::from_raw_parts(moved, 4), b"abcd");
        });
    }

    #[test]
    fn realloc_shrinks_in_place() {
        with_allocator(|a, _| unsafe {
            let layout = Layout::from_size_align(64, 8).unwrap();
            let first = a.alloc(layout);
            first.copy_from(b"abcd".as_ptr(), 4);
            let other = a.alloc(Layout::from_size_align(1, 1).unwrap()) as usize;

            // Not the last allocation: shrinking keeps the pointer and uses no more memory.
            assert_eq!(a.realloc(first, layout, 4), first);
            assert_eq!(core::slice::from_raw_parts(first, 4), b"abcd");
            assert_eq!(
                a.alloc(Layout::from_size_align(1, 1).unwrap()) as usize,
                other + 1
            );

            // The last allocation shrinks in place and gives back its tail.
            let layout = Layout::from_size_align(32, 8).unwrap();
            let last = a.alloc(layout);
            assert_eq!(a.realloc(last, layout, 8), last);
            assert_eq!(
                a.alloc(Layout::from_size_align(1, 1).unwrap()) as usize,
                last as usize + 8
            );
        });
    }
}
