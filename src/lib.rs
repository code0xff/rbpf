// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for syscalls)
// Copyright 2020 Solana Maintainers <maintainers@solana.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Virtual machine and JIT compiler for eBPF programs.
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.png",
    html_favicon_url = "https://raw.githubusercontent.com/qmonnet/rbpf/master/misc/rbpf.ico"
)]
#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::ptr_as_ptr)]

#[cfg(not(feature = "std"))]
extern crate alloc;

extern crate byteorder;
extern crate combine;
extern crate hash32;
extern crate log;
extern crate rand;
extern crate thiserror;

pub mod aligned_memory;
#[cfg(feature = "std")]
mod asm_parser;
#[cfg(feature = "std")]
pub mod assembler;
#[cfg(feature = "debugger")]
pub mod debugger;
pub mod disassembler;
pub mod ebpf;
pub mod elf;
pub mod elf_parser;
pub mod error;
#[cfg(feature = "std")]
pub mod fuzz;
#[cfg(feature = "std")]
pub mod insn_builder;
pub mod interpreter;
#[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
mod jit;
#[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
mod memory_management;
pub mod memory_region;
pub mod program;
pub mod static_analysis;
#[cfg(feature = "std")]
pub mod syscalls;
pub mod verifier;
pub mod vm;
#[cfg(all(feature = "jit", not(target_os = "windows"), target_arch = "x86_64"))]
mod x86;

mod lib {
    #[cfg(feature = "std")]
    pub use std::{
        array,
        cell::{Cell, UnsafeCell},
        cmp,
        collections::{btree_map::Entry, BTreeMap, BTreeSet, HashMap, HashSet},
        error, fmt,
        fmt::Debug,
        io, mem,
        ops::{self, Range},
        ptr::{self, copy_nonoverlapping},
        slice, str,
    };
    #[cfg(not(feature = "std"))]
    pub use {
        alloc::{
            boxed::Box,
            collections::{btree_map::Entry, BTreeMap, BTreeSet},
            format, slice,
            string::{String, ToString},
            vec::Vec,
        },
        core::{
            array,
            cell::{Cell, UnsafeCell},
            cmp, fmt,
            fmt::Debug,
            mem,
            ops::{self, Range},
            ptr::{self, copy_nonoverlapping},
        },
        core2::io,
        hashbrown::{HashMap, HashSet},
    };
}

trait ErrCheckedArithmetic: Sized {
    fn err_checked_add(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    fn err_checked_sub(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    fn err_checked_mul(self, other: Self) -> Result<Self, ArithmeticOverflow>;
    #[allow(dead_code)]
    fn err_checked_div(self, other: Self) -> Result<Self, ArithmeticOverflow>;
}
struct ArithmeticOverflow;

macro_rules! impl_err_checked_arithmetic {
    ($($ty:ty),*) => {
        $(
            impl ErrCheckedArithmetic for $ty {
                fn err_checked_add(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_add(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_sub(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_sub(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_mul(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_mul(other).ok_or(ArithmeticOverflow)
                }

                fn err_checked_div(self, other: $ty) -> Result<Self, ArithmeticOverflow> {
                    self.checked_div(other).ok_or(ArithmeticOverflow)
                }
            }
        )*
    }
}

impl_err_checked_arithmetic!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
