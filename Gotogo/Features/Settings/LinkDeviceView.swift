//
//  LinkDeviceView.swift
//  Gotogo
//
//  PRIMARY-device side of device linking. Generates a new linked device on the
//  server and shows its credentials as a QR code + a copyable code for the new
//  device to scan or paste. The new device provisions its own keys on adoption.
//

import SwiftUI
import CoreImage.CIFilterBuiltins

struct LinkDeviceView: View {
    @Environment(AppState.self) private var appState

    @State private var deviceName: String = "New device"
    @State private var payload: DeviceLinkPayload?
    @State private var working = false
    @State private var errorMessage: String?
    @State private var copied = false

    var body: some View {
        List {
            if let payload {
                codeSection(payload)
                instructionsSection
            } else {
                generateSection
            }
        }
        .navigationTitle("Link a device")
        .navigationBarTitleDisplayMode(.inline)
        .alert("Couldn't create link", isPresented: errorBinding) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "")
        }
    }

    // MARK: Sections

    private var generateSection: some View {
        Section {
            TextField("Device name", text: $deviceName)
                .textInputAutocapitalization(.words)
                .disabled(working)
            Button {
                generate()
            } label: {
                if working {
                    ProgressView()
                } else {
                    Label("Generate link code", systemImage: "qrcode")
                }
            }
            .disabled(working || deviceName.trimmingCharacters(in: .whitespaces).isEmpty)
        } footer: {
            Text("Creates a new device on your account. Open Gotogo on the new device and choose “Link to an existing account”, then scan or paste this code.")
        }
    }

    private func codeSection(_ payload: DeviceLinkPayload) -> some View {
        Section("Scan on your new device") {
            VStack(spacing: Theme.Spacing.md) {
                if let qr = Self.makeQR(payload.encoded()) {
                    Image(uiImage: qr)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 240)
                        .padding(Theme.Spacing.sm)
                        .background(Color.white)
                        .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
                        .accessibilityLabel("Device link QR code")
                }
                Text(payload.encoded())
                    .font(.caption.monospaced())
                    .lineLimit(3)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    Clipboard.copySecret(payload.encoded())
                    copied = true
                    Task { try? await Task.sleep(nanoseconds: 2_000_000_000); copied = false }
                } label: {
                    Label(copied ? "Copied" : "Copy code", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                .buttonStyle(.bordered)
            }
            .padding(.vertical, Theme.Spacing.xs)
        }
    }

    private var instructionsSection: some View {
        Section {
            Label("This code grants one new device access to your account. Don't share it with anyone else.",
                  systemImage: "exclamationmark.shield")
                .font(.caption)
                .foregroundStyle(Theme.Palette.secondaryText)
        }
    }

    // MARK: Actions

    private func generate() {
        working = true
        Task {
            do {
                payload = try await appState.createDeviceLink(name: deviceName.trimmingCharacters(in: .whitespaces))
            } catch {
                errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            }
            working = false
        }
    }

    private var errorBinding: Binding<Bool> {
        Binding(get: { errorMessage != nil }, set: { if !$0 { errorMessage = nil } })
    }

    // MARK: QR rendering

    /// Renders a QR image for a string using CoreImage (no third-party dependency).
    static func makeQR(_ string: String) -> UIImage? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cg = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
}
