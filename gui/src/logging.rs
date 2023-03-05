use anyhow::Context;
use tracing_log::LogTracer;
use tracing_subscriber::{
    filter::{EnvFilter, LevelFilter},
    FmtSubscriber,
};

pub fn init() -> anyhow::Result<()> {
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .with_env_var("LAYER_CAKE_LOG")
                    .from_env_lossy(),
            )
            .finish(),
    )
    .context("Unable to set the default log filter")?;

    LogTracer::init().context("Unable to initialize the tracing adapter for the log crate")?;

    Ok(())
}
