// SPDX-License-Identifier: AGPL-3.0-only

//! WritersProof desktop GUI (Linux).
//!
//! A thin GTK4/libadwaita client over the witnessing daemon's Unix-socket IPC
//! (`cpoe::ipc`). This is the P2.1 scaffold: an Adwaita application window that
//! builds and runs. Subsequent phases add the IPC bridge, live status, and the
//! tracking / evidence / forensics views.

use gtk4::prelude::*;
use gtk4::{Application, Box as GtkBox, Orientation};
use libadwaita as adw;

/// Reverse-DNS application id (company namespace `writerslogic`, product
/// `WritersProof`).
const APP_ID: &str = "com.writerslogic.WritersProof";

fn main() {
    let app = Application::builder().application_id(APP_ID).build();
    // libadwaita 1.1 has no AdwApplication, so init Adwaita on startup and use
    // a plain GtkApplication.
    app.connect_startup(|_| {
        adw::init().expect("failed to initialize libadwaita");
    });
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    let header = adw::HeaderBar::new();

    let status = adw::StatusPage::builder()
        .icon_name("security-high-symbolic")
        .title("WritersProof")
        .description("Connecting to the witnessing daemon…")
        .vexpand(true)
        .build();

    let content = GtkBox::new(Orientation::Vertical, 0);
    content.append(&header);
    content.append(&status);

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("WritersProof")
        .default_width(420)
        .default_height(640)
        .content(&content)
        .build();

    window.present();
}
