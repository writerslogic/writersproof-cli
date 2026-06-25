//! Dev helper: render a full badge SVG for a given id / mode / tier.
use badge_fingerprint::{render_badge_svg, short_id_from_identifier, Mode, Tier};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let arg = a
        .get(1)
        .cloned()
        .unwrap_or_else(|| "did:key:z6MkExample".to_string());
    // A `WP-…` arg is used verbatim; anything else is treated as an identifier
    // (e.g. a DID) and run through the real derivation.
    let id = if arg.starts_with("WP-") {
        arg
    } else {
        short_id_from_identifier(&arg)
    };
    let mode = Mode::from_slug(a.get(2).map(String::as_str).unwrap_or("human-authored"));
    let tier = Tier::from_slug(a.get(3).map(String::as_str).unwrap_or("verified"));
    print!("{}", render_badge_svg(&id, mode, tier));
}
