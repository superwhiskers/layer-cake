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
