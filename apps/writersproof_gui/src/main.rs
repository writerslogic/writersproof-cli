// SPDX-License-Identifier: AGPL-3.0-only

//! WritersProof desktop GUI (Linux) — a thin GTK4/libadwaita client over the
//! witnessing daemon's Unix-socket IPC (`cpoe::ipc`). See [`ipc`] for the
//! worker that bridges the daemon to the GTK main loop.

mod ipc;

use gtk4::glib;
use gtk4::prelude::*;
use libadwaita::prelude::*;
use gtk4::{
    Align, Application, Box as GtkBox, Button, FileChooserAction, FileChooserNative, ListBox,
    Orientation, ResponseType, ScrolledWindow, SelectionMode,
};
use ipc::{base_name, Command, UiEvent};
use libadwaita as adw;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use tokio::sync::mpsc::UnboundedSender;

const APP_ID: &str = "com.writerslogic.WritersProof";

fn main() {
    let app = Application::builder().application_id(APP_ID).build();
    app.connect_startup(|_| {
        adw::init().expect("failed to initialize libadwaita");
    });
    app.connect_activate(build_ui);
    app.run();
}

fn build_ui(app: &Application) {
    // Command channel (UI -> worker) and event channel (worker -> UI).
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<Command>();
    let (evt_tx, evt_rx) = glib::MainContext::channel::<UiEvent>(glib::PRIORITY_DEFAULT);
    ipc::spawn_worker(cmd_rx, evt_tx);

    // Dev/demo hook: WP_DEMO_TRACK=/path/a:/path/b pre-tracks files on launch.
    if let Ok(files) = std::env::var("WP_DEMO_TRACK") {
        for f in files.split(':').filter(|s| !s.is_empty()) {
            let _ = cmd_tx.send(Command::Track(PathBuf::from(f)));
        }
    }

    // ---- Header bar ---------------------------------------------------------
    let header = adw::HeaderBar::new();
    let add_button = Button::from_icon_name("list-add-symbolic");
    add_button.set_tooltip_text(Some("Witness a document…"));
    add_button.add_css_class("suggested-action");
    header.pack_start(&add_button);

    // ---- Daemon status group ------------------------------------------------
    let status_group = adw::PreferencesGroup::builder().title("Daemon").build();
    let status_row = adw::ActionRow::builder()
        .title("Connecting…")
        .subtitle("Reaching the witnessing daemon")
        .build();
    let status_icon = gtk4::Image::from_icon_name("content-loading-symbolic");
    status_row.add_prefix(&status_icon);
    status_group.add(&status_row);

    // ---- Tracked documents group -------------------------------------------
    let docs_group = adw::PreferencesGroup::builder()
        .title("Tracked documents")
        .build();
    let docs_list = ListBox::new();
    docs_list.add_css_class("boxed-list");
    docs_list.set_selection_mode(SelectionMode::None);
    docs_group.add(&docs_list);

    // ---- Layout -------------------------------------------------------------
    let page = GtkBox::new(Orientation::Vertical, 18);
    page.set_margin_top(18);
    page.set_margin_bottom(18);
    page.set_margin_start(12);
    page.set_margin_end(12);
    page.append(&status_group);
    page.append(&docs_group);

    let clamp = adw::Clamp::builder().maximum_size(620).child(&page).build();
    let scrolled = ScrolledWindow::builder()
        .vexpand(true)
        .hscrollbar_policy(gtk4::PolicyType::Never)
        .child(&clamp)
        .build();

    let outer = GtkBox::new(Orientation::Vertical, 0);
    outer.append(&header);
    outer.append(&scrolled);

    let toast_overlay = adw::ToastOverlay::new();
    toast_overlay.set_child(Some(&outer));

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .title("WritersProof")
        .default_width(460)
        .default_height(680)
        .content(&toast_overlay)
        .build();

    // ---- Add button -> file chooser -> Track --------------------------------
    {
        let win = window.clone();
        let cmd_tx = cmd_tx.clone();
        add_button.connect_clicked(move |_| {
            let chooser = FileChooserNative::new(
                Some("Witness a document"),
                Some(&win),
                FileChooserAction::Open,
                Some("_Witness"),
                Some("_Cancel"),
            );
            let cmd_tx = cmd_tx.clone();
            chooser.connect_response(move |c, resp| {
                if resp == ResponseType::Accept {
                    if let Some(path) = c.file().and_then(|f| f.path()) {
                        let _ = cmd_tx.send(Command::Track(path));
                    }
                }
            });
            chooser.show();
            // Keep the native dialog alive until it responds.
            std::mem::forget(chooser);
        });
    }

    // ---- Worker events -> UI ------------------------------------------------
    let rows: Rc<RefCell<Vec<gtk4::Widget>>> = Rc::new(RefCell::new(Vec::new()));
    let ctx = RenderCtx {
        status_row,
        status_icon,
        docs_list,
        cmd_tx: cmd_tx.clone(),
        rows,
        toast_overlay: toast_overlay.clone(),
    };
    evt_rx.attach(None, move |event| {
        ctx.handle(event);
        glib::Continue(true)
    });

    window.present();
}

/// Widgets the event handler mutates, bundled so the `attach` closure owns one
/// value.
struct RenderCtx {
    status_row: adw::ActionRow,
    status_icon: gtk4::Image,
    docs_list: ListBox,
    cmd_tx: UnboundedSender<Command>,
    rows: Rc<RefCell<Vec<gtk4::Widget>>>,
    toast_overlay: adw::ToastOverlay,
}

impl RenderCtx {
    fn handle(&self, event: UiEvent) {
        match event {
            UiEvent::Status {
                running,
                tracked,
                uptime,
            } => {
                self.status_row.set_title(if running {
                    "Witnessing active"
                } else {
                    "Daemon idle"
                });
                self.status_row
                    .set_subtitle(&format!("Up {}", format_uptime(uptime)));
                self.status_icon.set_icon_name(Some(if running {
                    "security-high-symbolic"
                } else {
                    "security-medium-symbolic"
                }));
                self.rebuild_docs(&tracked);
            }
            UiEvent::Disconnected(reason) => {
                self.status_row.set_title("Daemon not running");
                self.status_row.set_subtitle(&reason);
                self.status_icon
                    .set_icon_name(Some("security-low-symbolic"));
                self.rebuild_docs(&[]);
            }
            UiEvent::Toast(message) => {
                self.toast_overlay.add_toast(&adw::Toast::new(&message));
            }
        }
    }

    /// Replace the tracked-documents list with one row per path (or an
    /// empty-state placeholder).
    fn rebuild_docs(&self, tracked: &[String]) {
        for row in self.rows.borrow_mut().drain(..) {
            self.docs_list.remove(&row);
        }
        if tracked.is_empty() {
            let placeholder = adw::ActionRow::builder()
                .title("No documents tracked")
                .subtitle("Click the ＋ button to start witnessing a file")
                .build();
            placeholder.set_sensitive(false);
            self.docs_list.append(&placeholder);
            self.rows.borrow_mut().push(placeholder.upcast());
            return;
        }
        for path_str in tracked {
            let path = PathBuf::from(path_str);
            let row = adw::ActionRow::builder()
                .title(&base_name(&path))
                .subtitle(path_str)
                .build();
            row.add_suffix(&self.doc_actions(&path));
            self.docs_list.append(&row);
            self.rows.borrow_mut().push(row.upcast());
        }
    }

    /// The Export / Verify / Untrack buttons for one document row.
    fn doc_actions(&self, path: &PathBuf) -> GtkBox {
        let bx = GtkBox::new(Orientation::Horizontal, 6);
        bx.set_valign(Align::Center);

        let export = icon_button("document-save-symbolic", "Export evidence (standard tier)");
        let verify = icon_button("emblem-ok-symbolic", "Verify evidence");
        let untrack = icon_button("user-trash-symbolic", "Stop witnessing");
        untrack.add_css_class("destructive-action");

        let tx = self.cmd_tx.clone();
        let p = path.clone();
        export.connect_clicked(move |_| {
            let _ = tx.send(Command::Export {
                path: p.clone(),
                tier: "standard".into(),
            });
        });
        let tx = self.cmd_tx.clone();
        let p = path.with_extension("evidence.json");
        verify.connect_clicked(move |_| {
            let _ = tx.send(Command::Verify(p.clone()));
        });
        let tx = self.cmd_tx.clone();
        let p = path.clone();
        untrack.connect_clicked(move |_| {
            let _ = tx.send(Command::Untrack(p.clone()));
        });

        bx.append(&export);
        bx.append(&verify);
        bx.append(&untrack);
        bx
    }
}

fn icon_button(icon: &str, tooltip: &str) -> Button {
    let b = Button::from_icon_name(icon);
    b.set_tooltip_text(Some(tooltip));
    b.add_css_class("flat");
    b.set_valign(Align::Center);
    b
}

fn format_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}
