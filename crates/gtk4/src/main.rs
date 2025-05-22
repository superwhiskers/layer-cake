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

use anyhow::Context;
use relm4::{
    adw::{
        gio::{prelude::*, Settings},
        gtk, Application,
    },
    RelmApp,
};

mod appearance;
mod config;
mod i18n;
mod logging;
mod resources;
mod application;

fn main() -> anyhow::Result<()> {
    logging::init().context("Unable to intialize logging")?;
    gtk::init().context("Unable to initialize GTK")?;
    resources::init().context("Unable to initalize resources")?;

    let settings = Settings::new(config::APP_ID);

    appearance::init(&settings);

    let app = RelmApp::with_app(
        Application::builder()
            .application_id(config::APP_ID)
            .build(),
    );

    Ok(())
}
