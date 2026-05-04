// Generates a polished demo wallpaper PNG.
// Run: /usr/bin/swift generate_demo_wallpaper.swift
//
// Output: ~/Downloads/writerslogic_demo_wallpaper.png (5120 x 2880, sRGB)

import AppKit
import CoreGraphics
import CoreText
import Foundation

let width: CGFloat = 5120
let height: CGFloat = 2880

let cs = CGColorSpace(name: CGColorSpace.sRGB)!
guard let ctx = CGContext(
    data: nil,
    width: Int(width),
    height: Int(height),
    bitsPerComponent: 8,
    bytesPerRow: 0,
    space: cs,
    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
) else {
    FileHandle.standardError.write("failed to create context\n".data(using: .utf8)!)
    exit(1)
}

// ── 1. Vertical background gradient (deep blue → slightly lighter blue) ─────
let bgColors = [
    CGColor(srgbRed: 0.035, green: 0.055, blue: 0.110, alpha: 1.0),
    CGColor(srgbRed: 0.090, green: 0.125, blue: 0.205, alpha: 1.0),
] as CFArray
if let g = CGGradient(colorsSpace: cs, colors: bgColors, locations: [0.0, 1.0]) {
    ctx.drawLinearGradient(
        g,
        start: CGPoint(x: width / 2, y: height),
        end:   CGPoint(x: width / 2, y: 0),
        options: []
    )
}

// ── 2. Soft radial vignette to lift the centre ──────────────────────────────
let radialColors = [
    CGColor(srgbRed: 0.21, green: 0.30, blue: 0.42, alpha: 0.45),
    CGColor(srgbRed: 0.0,  green: 0.0,  blue: 0.0,  alpha: 0.0),
] as CFArray
if let g = CGGradient(colorsSpace: cs, colors: radialColors, locations: [0.0, 1.0]) {
    ctx.drawRadialGradient(
        g,
        startCenter: CGPoint(x: width / 2, y: height * 0.58),
        startRadius: 0,
        endCenter:   CGPoint(x: width / 2, y: height * 0.58),
        endRadius:   width * 0.55,
        options: []
    )
}

// ── 3. Subtle dot lattice (cryptographic / data feel) ───────────────────────
ctx.setFillColor(CGColor(srgbRed: 0.31, green: 0.76, blue: 0.97, alpha: 0.045))
let spacing: CGFloat = 110
let dotR: CGFloat = 1.8
var dy: CGFloat = spacing / 2
while dy < height {
    var dx: CGFloat = (Int(dy / spacing) % 2 == 0) ? spacing / 2 : spacing
    while dx < width {
        ctx.fillEllipse(in: CGRect(x: dx - dotR, y: dy - dotR, width: dotR * 2, height: dotR * 2))
        dx += spacing
    }
    dy += spacing
}

// ── 4. Drop the app icon (the WITNESSD seal) into the upper-middle ─────────
let scriptDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
let repoRoot = (scriptDir as NSString).deletingLastPathComponent
let iconPath = "\(repoRoot)/apps/cpoe_macos/cpoe/Assets.xcassets/AppIcon.appiconset/icon_512x512@2x.png"
let iconSize: CGFloat = 760
let iconCenterY = height * 0.62
let iconRect = CGRect(
    x: (width - iconSize) / 2,
    y: iconCenterY - iconSize / 2,
    width: iconSize,
    height: iconSize
)

// Soft glow underneath the icon for depth.
ctx.saveGState()
ctx.setShadow(
    offset: CGSize(width: 0, height: -8),
    blur: 80,
    color: CGColor(srgbRed: 0.31, green: 0.76, blue: 0.97, alpha: 0.35)
)
if let icon = NSImage(contentsOfFile: iconPath),
   let iconCG = icon.cgImage(forProposedRect: nil, context: nil, hints: nil) {
    ctx.draw(iconCG, in: iconRect)
}
ctx.restoreGState()

// ── 5. Brand text (URL prominent) ───────────────────────────────────────────
func drawCenteredText(
    _ text: String,
    fontSize: CGFloat,
    weight: NSFont.Weight,
    color: CGColor,
    kern: CGFloat,
    centerX: CGFloat,
    baselineY: CGFloat
) {
    let font = NSFont.systemFont(ofSize: fontSize, weight: weight)
    let attrs: [NSAttributedString.Key: Any] = [
        .font: font,
        .foregroundColor: NSColor(cgColor: color) ?? NSColor.white,
        .kern: kern,
    ]
    let attr = NSAttributedString(string: text, attributes: attrs)
    let line = CTLineCreateWithAttributedString(attr)
    let bounds = CTLineGetBoundsWithOptions(line, .useOpticalBounds)
    ctx.textPosition = CGPoint(x: centerX - bounds.width / 2, y: baselineY)
    CTLineDraw(line, ctx)
}

let urlBaseline = iconRect.minY - 220
let taglineBaseline = urlBaseline - 110

// "writerslogic.com" — large, bright, brand accent blue.
drawCenteredText(
    "writerslogic.com",
    fontSize: 220,
    weight: .light,
    color: CGColor(srgbRed: 0.78, green: 0.92, blue: 1.00, alpha: 1.0),
    kern: 12,
    centerX: width / 2,
    baselineY: urlBaseline
)

// Tagline — quieter, smaller. Reinforces what the demo is about.
drawCenteredText(
    "Cryptographic proof of human authorship",
    fontSize: 64,
    weight: .regular,
    color: CGColor(srgbRed: 0.55, green: 0.66, blue: 0.80, alpha: 1.0),
    kern: 18,
    centerX: width / 2,
    baselineY: taglineBaseline
)

// ── 6. Hairline accent under the URL for polish ─────────────────────────────
ctx.setStrokeColor(CGColor(srgbRed: 0.31, green: 0.76, blue: 0.97, alpha: 0.35))
ctx.setLineWidth(2)
let lineY = urlBaseline - 60
let lineHalf: CGFloat = 220
ctx.move(to:    CGPoint(x: width / 2 - lineHalf, y: lineY))
ctx.addLine(to: CGPoint(x: width / 2 + lineHalf, y: lineY))
ctx.strokePath()

// ── 7. Encode PNG ──────────────────────────────────────────────────────────
guard let image = ctx.makeImage() else { exit(1) }
let rep = NSBitmapImageRep(cgImage: image)
rep.size = NSSize(width: width, height: height)
guard let pngData = rep.representation(using: .png, properties: [:]) else { exit(1) }

let home = FileManager.default.homeDirectoryForCurrentUser
let outURL = home.appendingPathComponent("Downloads/writerslogic_demo_wallpaper.png")
try? pngData.write(to: outURL)
print("Wrote: \(outURL.path)")
