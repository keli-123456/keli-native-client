#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopRunState {
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopTrafficMode {
    SystemProxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopStatusSnapshot;
