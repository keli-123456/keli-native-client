use std::path::PathBuf;

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }

    let manifest = PathBuf::from("keli-desktop-shell.exe.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());

    let manifest = std::env::current_dir()
        .expect("desktop shell crate dir")
        .join(manifest);
    println!("cargo:rustc-link-arg-bin=keli-desktop-shell=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bin=keli-desktop-shell=/MANIFESTINPUT:{}",
        manifest.display()
    );
}
