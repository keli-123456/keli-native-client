pub mod commands;
pub mod dependencies;
pub mod managed;
pub mod readiness;
pub mod service;
pub mod status;
pub mod subscription;
pub mod support;

pub use commands::{DesktopCommandError, DesktopCommandService};
pub use dependencies::{
    DesktopDependencyError, DesktopDependencyReport, DesktopSystemProxyDependency,
    DesktopTunBackendDependency, DesktopWintunInstallSummary,
};
pub use managed::{DesktopManagedCoreService, DesktopManagedStartOptions};
pub use readiness::{DesktopBlocker, DesktopFirstRunReport};
pub use service::{DesktopRuntimeCommand, DesktopRuntimeError, DesktopRuntimeService};
pub use status::{DesktopRunState, DesktopStatusSnapshot, DesktopTrafficMode};
pub use subscription::{
    DesktopNodeSummary, DesktopSubscriptionSummary, DesktopSubscriptionUpdateSummary,
    DesktopSubscriptionUrlFetchSummary, DesktopSubscriptionUrlImportSummary,
    DesktopSubscriptionUrlUpdateSummary,
};
pub use support::{DesktopSupportBundleExport, DESKTOP_SUPPORT_BUNDLE_SCHEMA_VERSION};

#[cfg(test)]
mod tests {
    #[test]
    fn desktop_crate_exports_public_modules() {
        assert_eq!("keli-desktop", env!("CARGO_PKG_NAME"));
    }
}
