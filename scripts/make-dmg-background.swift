#!/usr/bin/env swift
//
// Draws the disk image's install window background, at 1x and 2x, and packs
// the two into one multi-representation TIFF -- which is how a .dmg background
// gets a Retina version at all: the Finder picks the representation matching
// the display, and a lone 600x400 PNG is simply drawn blurry on every Mac sold
// in the last decade.
//
// Rendered with Core Graphics rather than an SVG converted by some tool: the
// icon in this project was first attempted through ImageMagick's SVG parser,
// which silently rendered a gradient as solid black. Drawing directly is the
// only way the file on disk is the thing that was described.
//
//   swift scripts/make-dmg-background.swift brand/dmg-background.tiff
//
import AppKit

// Matches the window bounds make-dmg.sh sets, and the icon positions in it:
// the app at (150, 190) and the Applications alias at (450, 190), measured
// from the window's top-left. Everything below is placed against those.
let width = 600.0
let height = 400.0
let iconY = 190.0
let leftIconX = 150.0
let rightIconX = 450.0

// The palette the app's own two web pages use, so the installer, the pages and
// the app all look like one product.
func srgb(_ hex: UInt32, alpha: Double = 1) -> NSColor {
    NSColor(
        srgbRed: Double((hex >> 16) & 0xFF) / 255,
        green: Double((hex >> 8) & 0xFF) / 255,
        blue: Double(hex & 0xFF) / 255,
        alpha: alpha
    )
}
let ink = srgb(0x1C2024)
let muted = srgb(0x6B7280)
let faint = srgb(0x9AA1AC)
let accent = srgb(0x2F6FED)

func draw(scale: Double) -> NSBitmapImageRep {
    let pixelsWide = Int(width * scale)
    let pixelsHigh = Int(height * scale)
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: pixelsWide, pixelsHigh: pixelsHigh,
        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
    )!
    rep.size = NSSize(width: width, height: height)

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let context = NSGraphicsContext.current!.cgContext
    context.setShouldAntialias(true)

    // AppKit draws from the bottom left; every measurement above is from the
    // top left, the way the Finder positions icons. One flip here rather than
    // subtracting from `height` at a dozen call sites and getting one wrong.
    context.translateBy(x: 0, y: height)
    context.scaleBy(x: 1, y: -1)

    // A very slight vertical gradient rather than a flat fill: flat white
    // reads as "no background was set" next to the Finder's own chrome.
    let gradient = NSGradient(colors: [srgb(0xFFFFFF), srgb(0xEEF1F5)])!
    NSGraphicsContext.current!.cgContext.saveGState()
    context.translateBy(x: 0, y: height)
    context.scaleBy(x: 1, y: -1)
    gradient.draw(in: NSRect(x: 0, y: 0, width: width, height: height), angle: 90)
    context.restoreGState()

    func text(_ string: String, y: Double, size: Double, weight: NSFont.Weight, color: NSColor) {
        let font = NSFont.systemFont(ofSize: size, weight: weight)
        let attributes: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: color]
        let attributed = NSAttributedString(string: string, attributes: attributes)
        let measured = attributed.size()
        context.saveGState()
        // Flip back for the text itself, which Core Text draws upright.
        context.translateBy(x: 0, y: y + measured.height)
        context.scaleBy(x: 1, y: -1)
        attributed.draw(at: NSPoint(x: (width - measured.width) / 2, y: 0))
        context.restoreGState()
    }

    text("OpenImzo", y: 34, size: 30, weight: .semibold, color: ink)

    // The arrow sits on the icons' own centre line, between the two of them,
    // and is the only instruction that needs no language at all.
    let arrowY = iconY
    let start = leftIconX + 100
    let end = rightIconX - 100
    let head = 16.0
    context.setStrokeColor(accent.withAlphaComponent(0.55).cgColor)
    context.setLineWidth(5)
    context.setLineCap(.round)
    context.move(to: CGPoint(x: start, y: arrowY))
    context.addLine(to: CGPoint(x: end - head * 0.6, y: arrowY))
    context.strokePath()
    context.setFillColor(accent.withAlphaComponent(0.55).cgColor)
    context.move(to: CGPoint(x: end, y: arrowY))
    context.addLine(to: CGPoint(x: end - head, y: arrowY - head * 0.62))
    context.addLine(to: CGPoint(x: end - head, y: arrowY + head * 0.62))
    context.closePath()
    context.fillPath()

    // Under the icon labels, in all three languages the app itself speaks --
    // the people installing this read Uzbek and Russian, and an English-only
    // installer window would be the first thing they saw.
    text("Перетащите OpenImzo в папку Applications", y: 300, size: 11.5, weight: .regular, color: muted)
    text("OpenImzo ilovasini Applications jildiga torting", y: 320, size: 11.5, weight: .regular, color: muted)
    text("Drag OpenImzo into your Applications folder", y: 340, size: 11.5, weight: .regular, color: muted)

    text("GPL-3.0  ·  github.com/ganiyevuz/openimzo", y: 370, size: 9.5, weight: .regular, color: faint)

    NSGraphicsContext.restoreGraphicsState()
    return rep
}

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "brand/dmg-background.tiff"
let image = NSImage(size: NSSize(width: width, height: height))
image.addRepresentation(draw(scale: 1))
image.addRepresentation(draw(scale: 2))
// LZW, not none: this is flat colour and large text, which lossless
// compression takes from ~4.8 MB to a few hundred kilobytes -- and it goes
// inside a disk image people download over Uzbek home connections.
guard let data = NSBitmapImageRep.representationOfImageReps(
    in: image.representations, using: .tiff,
    properties: [.compressionMethod: NSBitmapImageRep.TIFFCompression.lzw.rawValue]
) else {
    FileHandle.standardError.write(Data("could not encode the TIFF\n".utf8))
    exit(1)
}
try data.write(to: URL(fileURLWithPath: out))
print("==> \(out)  (\(Int(width))x\(Int(height)) @1x and @2x, \(data.count) bytes)")
