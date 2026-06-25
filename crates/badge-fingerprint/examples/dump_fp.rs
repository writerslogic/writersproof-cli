//! Dev helper: dump the raw deterministic fingerprint SVG for an id, so the
//! real flow-field print can be inspected in isolation.
use badge_fingerprint::render_fingerprint_svg;

fn main() {
    let id = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "WP-7F3C-A9B1".to_string());
    print!("{}", render_fingerprint_svg(&id));
}
