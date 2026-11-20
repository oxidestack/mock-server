//! Extensions named in `extensions` (the extension loader's start-up rule). Upstream's `ExtensionLoader` splits the
//! property on `,`, trims each name, skips empty ones and loads each class through the class loader class callbacks
//! use; the first one that is not on the class path refuses start-up (`ExtensionLoader.java:40-50`, `:99-104`).
//! Here a name resolves through the callback providers in their order, the in-process registry, then native
//! plugins, then WASM plugins, and only among the extensions they export: a callback class of the same name does not
//! count. No provider exports extensions yet (the hooks they would offer are still open questions), so the first name refuses start-up with the oracle's text for a class that is not on its class path.
//! `extensionScanning` alone loads what the providers export, which is nothing, so the server starts unchanged.

use crate::class_callback::{Plugins, Registry};
use crate::config::Config;

/// An extension a provider exports. None can be built yet: no provider exports extensions.
pub(crate) enum Extension {}

/// What a callback provider exports as extensions, by name.
trait ExtensionProvider {
    fn extension(&self, name: &str) -> Option<Extension>;
}

impl ExtensionProvider for Registry {
    fn extension(&self, _name: &str) -> Option<Extension> {
        None
    }
}

impl ExtensionProvider for Plugins {
    fn extension(&self, _name: &str) -> Option<Extension> {
        None
    }
}

/// The names in `extensions`, in order: split on `,`, trimmed, empty ones skipped.
pub(crate) fn names(config: &Config) -> Vec<String> {
    config.property("extensions").unwrap_or_default().split(',').map(str::trim).filter(|n| !n.is_empty()).map(String::from).collect()
}

/// `ExtensionRegistry.start`'s loading step: every named extension resolved, or the failure `Main.logStartupFailure`
/// prints after `exception while starting:{}` (`org.mockserver.extension.ExtensionException: …`) for the first name no
/// provider exports. `report` receives what loading the plugins of `callbackPlugins` reports (a jar in `/extensions`
/// is named there), and plugins are read only when a name is configured.
pub(crate) fn load(config: &Config, report: impl Fn(String)) -> Result<Vec<Extension>, String> {
    let names = names(config);
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let plugins = Plugins::load(&config.property("callbackPlugins").unwrap_or_default(), report);
    let providers: [&dyn ExtensionProvider; 2] = [config.callback_classes.as_ref(), &plugins];
    names.iter().map(|name| providers.iter().find_map(|p| p.extension(name)).ok_or_else(|| not_on_class_path(name))).collect()
}

/// `ExtensionLoader.loadClass`'s refusal of a class `Class.forName` cannot find, with the `ClassNotFoundException`
/// as its cause.
fn not_on_class_path(name: &str) -> String {
    format!(
        "org.mockserver.extension.ExtensionException: extension class {name} could not be loaded, check it is on the classpath: java.lang.ClassNotFoundException: {name}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extensions: &str) -> Config {
        Config::default().with_property("extensions", extensions)
    }

    #[test]
    fn splits_trims_and_skips_empty_names() {
        assert_eq!(names(&config(" a.B , ,c.D,")), vec!["a.B", "c.D"]);
        assert!(names(&config(" , ")).is_empty());
        assert!(names(&Config::default()).is_empty());
    }

    #[test]
    fn blank_entries_load_nothing() {
        assert!(load(&config(" , "), |_| {}).is_ok_and(|loaded| loaded.is_empty()));
    }

    #[test]
    fn the_first_name_no_provider_exports_is_refused() {
        assert_eq!(
            load(&config("com.acme.First, com.acme.Second"), |_| {}).err().as_deref(),
            Some("org.mockserver.extension.ExtensionException: extension class com.acme.First could not be loaded, check it is on the classpath: java.lang.ClassNotFoundException: com.acme.First")
        );
    }

    #[test]
    fn a_callback_class_of_the_same_name_is_not_an_extension() {
        let config = config("com.acme.Callback").with_callback_class("com.acme.Callback", crate::class_callback::CallbackClass::default());
        assert!(load(&config, |_| {}).is_err());
    }
}
