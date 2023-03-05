use relm4::adw::{
    gio::{prelude::*, Settings},
    ColorScheme, StyleManager,
};

pub fn init(settings: &Settings) {
    StyleManager::default().set_color_scheme(match settings.enum_("color-scheme-preference") {
        2 => ColorScheme::ForceDark,
        3 => ColorScheme::ForceLight,
        _ => ColorScheme::Default,
    });
}
