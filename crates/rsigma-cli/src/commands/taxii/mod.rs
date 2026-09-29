//! TAXII sync and local STIX bundle import into a store (`taxii-sync` feature).

mod store;
mod sync;

use clap::Subcommand;

use crate::output::OutputCtx;

pub(crate) use store::{TaxiiStoreArgs, cmd_taxii_store};
pub(crate) use sync::{TaxiiSyncArgs, cmd_taxii_sync};

#[derive(Subcommand)]
pub(crate) enum TaxiiCommands {
    /// Fetch a TAXII collection and persist objects in a local store
    Sync(Box<TaxiiSyncArgs>),
    /// Import a local STIX bundle JSON file into a store
    Store(TaxiiStoreArgs),
}

pub(crate) fn dispatch_taxii(cmd: TaxiiCommands, ctx: OutputCtx) {
    match cmd {
        TaxiiCommands::Sync(args) => cmd_taxii_sync(*args, ctx),
        TaxiiCommands::Store(args) => cmd_taxii_store(args, ctx),
    }
}
