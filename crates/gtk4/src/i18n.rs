use i18n_embed::{
    fluent::{fluent_language_loader, FluentLanguageLoader},
    DesktopLanguageRequester,
};
use once_cell::sync::Lazy;
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Localizations;

pub static LANGUAGE_LOADER: Lazy<FluentLanguageLoader> = Lazy::new(|| {
    let language_loader = fluent_language_loader!();
    let requested_languages = DesktopLanguageRequester::requested_languages();

    i18n_embed::select(&language_loader, &Localizations, &requested_languages)
        .expect("Unable to negotiate languages");

    language_loader
});

#[macro_export]
macro_rules! fl {
    ($message_id:literal) => {{
        &i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id)
    }};

    ($message_id:literal, $($args:expr),*) => {{
        &i18n_embed_fl::fl!($crate::i18n::LANGUAGE_LOADER, $message_id, $($args), *)
    }};
}
