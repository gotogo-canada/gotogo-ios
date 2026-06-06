//
//  MediaProcessing.swift
//  Gotogo
//
//  Image hygiene before encryption: strip EXIF/GPS metadata by re-encoding, and
//  build a small encrypted-thumbnail source. Uses ImageIO so it works without
//  UIKit (plan section 6: EXIF removed before encryption).
//
import Foundation
import ImageIO
import UniformTypeIdentifiers
import CoreGraphics

/// Metadata-stripping and thumbnailing for images, prior to media encryption.
public enum MediaProcessing {

    /// Re-encodes image data dropping ALL metadata (EXIF, GPS, TIFF, maker notes).
    /// Returns nil if the input is not a decodable image.
    public static func stripMetadata(_ data: Data, asJPEGQuality quality: CGFloat = 0.9) -> Data? {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil),
              let image = CGImageSourceCreateImageAtIndex(src, 0, nil) else { return nil }
        return encode(image, quality: quality)
    }

    /// Produces a downscaled thumbnail (max edge `maxDimension`) with no metadata.
    public static func thumbnail(_ data: Data, maxDimension: Int = 320, quality: CGFloat = 0.7) -> Data? {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        let opts: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: maxDimension,
        ]
        guard let thumb = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return nil }
        return encode(thumb, quality: quality)
    }

    /// Pixel dimensions of an image without decoding the whole bitmap.
    public static func pixelSize(_ data: Data) -> (width: Int, height: Int)? {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil),
              let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [CFString: Any],
              let w = props[kCGImagePropertyPixelWidth] as? Int,
              let h = props[kCGImagePropertyPixelHeight] as? Int else { return nil }
        return (w, h)
    }

    /// Encodes a CGImage to JPEG with NO metadata dictionaries attached.
    private static func encode(_ image: CGImage, quality: CGFloat) -> Data? {
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil) else { return nil }
        // Only set the compression quality; do NOT copy source properties, so the
        // output carries no EXIF/GPS metadata.
        let props: [CFString: Any] = [kCGImageDestinationLossyCompressionQuality: quality]
        CGImageDestinationAddImage(dest, image, props as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return out as Data
    }
}
