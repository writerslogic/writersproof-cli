//! Gallery + degradation harness.
//!
//! Generates ~20 distinct short-ids spanning all modes/tiers, renders each
//! badge to SVG, rasterizes to PNG at inspect (600px) and digital-0.5" (256px)
//! sizes, fax-simulates each (downscale to 100px, 1-bit threshold, blur +
//! dilation for dot-gain), then assembles two labeled contact sheets:
//!   gallery/gallery-crisp.png   (inspect-size badges)
//!   gallery/gallery-fax.png     (fax-simulated badges)
//!
//! Requires `rsvg-convert` (or `magick`) and `magick` on PATH.

use badge_fingerprint::{render_badge_svg, Mode, Tier};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const INSPECT: u32 = 600;
const DIGITAL: u32 = 256; // ~0.5" at screen dpi
const FAX: u32 = 100; // 0.5" @ 200 dpi

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let gallery = root.join("gallery");
    let work = gallery.join("work");
    let _ = fs::create_dir_all(&work);

    let has_rsvg = which("rsvg-convert");
    let has_magick = which("magick");
    if !has_magick {
        eprintln!("error: ImageMagick `magick` not found on PATH; cannot build gallery.");
        std::process::exit(1);
    }

    let modes = [Mode::HumanAuthored, Mode::AiAssisted, Mode::HumanRevised];
    let tiers = [Tier::Verified, Tier::Corroborated, Tier::Declared];

    let mut crisp_tiles: Vec<PathBuf> = Vec::new();
    let mut fax_tiles: Vec<PathBuf> = Vec::new();

    // 21 ids = 3 modes x 3 tiers + extras, spanning the combination space.
    let mut combos: Vec<(Mode, Tier)> = Vec::new();
    for m in modes {
        for t in tiers {
            combos.push((m, t));
        }
    }
    // a few extra to reach ~20, cycling modes/tiers.
    // pad to 20 by cycling the mode/tier space with a different stride.
    let mut k = 0usize;
    while combos.len() < 20 {
        combos.push((modes[k % 3], tiers[(k * 2 + 1) % 3]));
        k += 1;
    }

    for (i, (mode, tier)) in combos.iter().enumerate() {
        let id = gen_id(i as u32);
        let svg = render_badge_svg(&id, *mode, *tier);
        let svg_path = work.join(format!("badge_{i:02}.svg"));
        fs::write(&svg_path, &svg).expect("write svg");

        // Rasterize: crisp (inspect) + digital(0.5").
        let crisp = work.join(format!("crisp_{i:02}.png"));
        let digital = work.join(format!("digital_{i:02}.png"));
        rasterize(&svg_path, &crisp, INSPECT, has_rsvg);
        rasterize(&svg_path, &digital, DIGITAL, has_rsvg);

        // Fax-simulate from the digital render.
        let fax = work.join(format!("fax_{i:02}.png"));
        fax_simulate(&digital, &fax);

        // Label each tile with the short-id (and mode/tier).
        let crisp_lbl = work.join(format!("crispL_{i:02}.png"));
        let fax_lbl = work.join(format!("faxL_{i:02}.png"));
        label(
            &crisp,
            &crisp_lbl,
            &format!("{id}  {}/{}", mode_str(*mode), tier.label()),
        );
        label(&fax, &fax_lbl, &id);

        crisp_tiles.push(crisp_lbl);
        fax_tiles.push(fax_lbl);
    }

    let crisp_sheet = gallery.join("gallery-crisp.png");
    let fax_sheet = gallery.join("gallery-fax.png");
    montage(&crisp_tiles, &crisp_sheet, "5x");
    montage(&fax_tiles, &fax_sheet, "5x");

    println!("CRISP_SHEET={}", crisp_sheet.display());
    println!("FAX_SHEET={}", fax_sheet.display());
}

fn gen_id(n: u32) -> String {
    // Real production short-ids, derived from a sample identifier so the gallery
    // reflects the actual WP-XXXX-XXXX-XXXX-XXXX format and width.
    badge_fingerprint::short_id_from_identifier(&format!("did:key:gallery-{n}"))
}

fn mode_str(m: Mode) -> &'static str {
    match m {
        Mode::HumanAuthored => "HUMAN",
        Mode::AiAssisted => "AI",
        Mode::HumanRevised => "REVISED",
    }
}

fn rasterize(svg: &Path, out: &Path, px: u32, has_rsvg: bool) {
    if has_rsvg {
        run(
            "rsvg-convert",
            &[
                "-w",
                &px.to_string(),
                "-h",
                &px.to_string(),
                "--keep-aspect-ratio",
                "-b",
                "white",
                svg.to_str().unwrap(),
                "-o",
                out.to_str().unwrap(),
            ],
        );
    } else {
        run(
            "magick",
            &[
                "-background",
                "white",
                "-density",
                "300",
                svg.to_str().unwrap(),
                "-resize",
                &format!("{px}x{px}"),
                out.to_str().unwrap(),
            ],
        );
    }
}

/// Fax / photocopy simulation: downscale to ~100px, 1-bit threshold, slight
/// blur + dilation (dot-gain), then scale back up for visibility.
fn fax_simulate(src: &Path, out: &Path) {
    run(
        "magick",
        &[
            src.to_str().unwrap(),
            "-colorspace",
            "Gray",
            "-resize",
            &format!("{FAX}x{FAX}"),
            "-blur",
            "0x0.4",
            // threshold high enough that partially-gray thin strokes survive,
            // matching a forgiving photocopier rather than a harsh scanner.
            "-threshold",
            "72%",
            // dot-gain: dilate black slightly via morphology
            "-morphology",
            "Dilate",
            "Disk:1",
            "-resize",
            "300x300",
            "-filter",
            "point",
            out.to_str().unwrap(),
        ],
    );
}

fn label(src: &Path, out: &Path, text: &str) {
    run(
        "magick",
        &[
            src.to_str().unwrap(),
            "-font",
            font_path(),
            "-gravity",
            "South",
            "-background",
            "white",
            "-splice",
            "0x22",
            "-pointsize",
            "16",
            "-fill",
            "#16243f",
            "-gravity",
            "South",
            "-annotate",
            "+0+3",
            text,
            out.to_str().unwrap(),
        ],
    );
}

fn montage(tiles: &[PathBuf], out: &Path, tile: &str) {
    let mut args: Vec<String> = tiles
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    args.push("-font".into());
    args.push(font_path().into());
    args.push("-tile".into());
    args.push(tile.into());
    args.push("-geometry".into());
    args.push("+8+8".into());
    args.push("-background".into());
    args.push("white".into());
    args.push(out.to_string_lossy().into_owned());
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run("montage", &refs);
}

/// First available system font for ImageMagick `-annotate` (which has no
/// default font configured on macOS).
fn font_path() -> &'static str {
    const CANDIDATES: [&str; 3] = [
        "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ];
    for c in CANDIDATES {
        if Path::new(c).exists() {
            return c;
        }
    }
    "Helvetica"
}

fn which(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[&str]) {
    let status = Command::new(cmd).args(args).status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("warn: `{cmd}` exited with {s}");
        }
        Err(e) => {
            eprintln!("error: failed to spawn `{cmd}`: {e}");
            std::process::exit(1);
        }
    }
}
