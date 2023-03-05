use anyhow::Context;
use relm4::adw::{
    gio::{self, Resource},
    glib, gtk,
};
use std::env;

use crate::{config, fl};

pub fn init() -> anyhow::Result<()> {
    glib::set_application_name(fl!("application-name"));
    gtk::Window::set_default_icon_name(config::APP_ID);

    let resources = Resource::load(env::var("LAYER_CAKE_RESOURCES").unwrap_or(format!(
        "{}/{}/{}.gresource",
        config::DATADIR,
        config::PKGNAME,
        config::APP_ID,
    )))
    .context("Unable to load the application's resources")?;

    gio::resources_register(&resources);

    Ok(())
}
