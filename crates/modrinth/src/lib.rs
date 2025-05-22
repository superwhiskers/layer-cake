// SPDX-LICENSE-IDENTIFIER: GPL-3.0-or-later

#![warn(
    clippy::cargo_common_metadata,
    clippy::dbg_macro,
    clippy::expect_used,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_pass_by_value,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::todo,
    clippy::unimplemented
)]
#![deny(
    clippy::await_holding_lock,
    rustdoc::broken_intra_doc_links,
    clippy::cast_lossless,
    clippy::clone_on_ref_ptr,
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::exit,
    clippy::explicit_deref_methods,
    clippy::explicit_into_iter_loop,
    clippy::explicit_iter_loop,
    clippy::fallible_impl_from,
    clippy::filetype_is_file,
    clippy::float_cmp,
    clippy::float_cmp_const,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::large_digit_groups,
    clippy::large_stack_arrays,
    clippy::manual_filter_map,
    clippy::match_like_matches_macro,
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_safety_doc,
    clippy::mut_mut,
    clippy::option_option,
    clippy::panic_in_result_fn,
    clippy::redundant_clone,
    clippy::redundant_else,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::single_match_else,
    clippy::string_to_string,
    trivial_casts,
    trivial_numeric_casts,
    clippy::undocumented_unsafe_blocks,
    clippy::unused_self,
    clippy::unwrap_used,
    clippy::wildcard_dependencies,
    clippy::wildcard_imports
)]

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
