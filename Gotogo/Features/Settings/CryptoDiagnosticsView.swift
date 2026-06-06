//
//  CryptoDiagnosticsView.swift
//  Gotogo
//
//  A user-visible proof that the post-quantum crypto actually works IN THIS BUILD:
//  it runs the app's real primitives (X-Wing PQXDH, ML-KEM-1024, AES-256-GCM,
//  Ed25519) live and shows pass/fail.
//

import SwiftUI
import CryptoKit

struct CryptoDiagnosticsView: View {

    struct CheckResult: Identifiable {
        let id = UUID()
        let name: String
        let detail: String
        let passed: Bool
    }

    @State private var results: [CheckResult] = []
    @State private var running = true

    var body: some View {
        List {
            Section {
                ForEach(results) { r in
                    HStack(spacing: Theme.Spacing.md) {
                        Image(systemName: r.passed ? "checkmark.seal.fill" : "xmark.octagon.fill")
                            .foregroundStyle(r.passed ? Theme.Palette.success : Color.red)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(r.name).font(.subheadline.weight(.medium))
                            Text(r.detail).font(.caption).foregroundStyle(Theme.Palette.secondaryText)
                        }
                    }
                    .padding(.vertical, 2)
                }
                if running {
                    HStack(spacing: Theme.Spacing.md) {
                        ProgressView()
                        Text("Running self-tests…").foregroundStyle(Theme.Palette.secondaryText)
                    }
                }
            } header: {
                Text("Post-quantum primitives — live in this build")
            } footer: {
                Text("These run the app's actual CryptoKit crypto right now on this device, not a recording.")
            }

            Section {
                HStack(spacing: Theme.Spacing.md) {
                    Image(systemName: "info.circle.fill").foregroundStyle(Theme.Palette.accent)
                    Text("1:1 messages use Gotogo's native PQXDH bootstrap and Double Ratchet transport.")
                        .font(.caption)
                }
            } header: {
                Text("Messaging transport")
            } footer: {
                Text("The transport is implemented with the same CryptoKit-backed primitives checked above.")
            }
        }
        .navigationTitle("Crypto diagnostics")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            // Tiny yield so the spinner paints before the (fast) synchronous checks.
            results = [Self.checkPQXDH(), Self.checkMLKEM1024(), Self.checkAESGCM(), Self.checkEd25519()]
            running = false
        }
    }

    // MARK: - Checks (each runs the app's real crypto)

    /// The real session-bootstrap: X-Wing (ML-KEM-768 + X25519) hybrid PQ handshake
    /// via the app's CryptoEngine seal/open.
    static func checkPQXDH() -> CheckResult {
        let name = "X-Wing PQXDH (ML-KEM-768 + X25519)"
        let engine = CryptoKitEngine()
        do {
            let recipient = engine.generateIdentity()
            let pre = try engine.generatePreKeys(identity: recipient, signedPreKeyId: 1,
                                                 oneTimeCount: 1, firstOneTimeId: 1)
            let bundle = engine.publicBundle(identity: recipient, store: pre.store, oneTimePreKeyId: 1)
            let msg = Data("Gotogo PQXDH self-test".utf8)
            let env = try engine.seal(msg, to: bundle)
            let out = try engine.open(env, identity: recipient,
                                      signedPreKey: pre.store.signedPreKey,
                                      oneTimePreKeys: pre.store.oneTimePreKeys)
            let ok = (out == msg)
            return CheckResult(name: name, detail: ok ? "Hybrid post-quantum handshake round-trip OK" : "plaintext mismatch", passed: ok)
        } catch {
            return CheckResult(name: name, detail: "failed: \(error)", passed: false)
        }
    }

    /// ML-KEM-1024 (NIST FIPS 203 Level 5) seal/open + tamper rejection.
    static func checkMLKEM1024() -> CheckResult {
        let name = "ML-KEM-1024 (NIST L5) seal + tamper-reject"
        do {
            let kp = try MLKEM1024Seal.generate()
            let msg = Data("very sensitive payload".utf8)
            let sealed = try MLKEM1024Seal.seal(msg, toPublicKey: kp.publicKey)
            guard try MLKEM1024Seal.open(sealed, using: kp) == msg else {
                return CheckResult(name: name, detail: "round-trip mismatch", passed: false)
            }
            // Flip a byte of the AEAD box; opening MUST fail.
            var ct = sealed.ciphertext
            ct[ct.startIndex] = ct[ct.startIndex] ^ 0xFF
            let tampered = MLKEM1024Sealed(kem: sealed.kem, ciphertext: ct)
            do {
                _ = try MLKEM1024Seal.open(tampered, using: kp)
                return CheckResult(name: name, detail: "tamper NOT detected", passed: false)
            } catch {
                return CheckResult(name: name, detail: "Round-trip OK; tampered ciphertext rejected", passed: true)
            }
        } catch {
            return CheckResult(name: name, detail: "failed: \(error)", passed: false)
        }
    }

    /// AES-256-GCM authenticated encryption + tamper rejection (the message AEAD).
    static func checkAESGCM() -> CheckResult {
        let name = "AES-256-GCM AEAD + tamper-reject"
        do {
            let key = SymmetricKey(size: .bits256)
            let msg = Data("authenticated encryption".utf8)
            let box = try AES.GCM.seal(msg, using: key)
            guard try AES.GCM.open(box, using: key) == msg, var combined = box.combined else {
                return CheckResult(name: name, detail: "round-trip mismatch", passed: false)
            }
            combined[combined.index(before: combined.endIndex)] ^= 0xFF
            let badBox = try AES.GCM.SealedBox(combined: combined)
            do {
                _ = try AES.GCM.open(badBox, using: key)
                return CheckResult(name: name, detail: "tamper NOT detected", passed: false)
            } catch {
                return CheckResult(name: name, detail: "Round-trip OK; tampered tag rejected", passed: true)
            }
        } catch {
            return CheckResult(name: name, detail: "failed: \(error)", passed: false)
        }
    }

    /// Ed25519 identity signatures: a valid signature verifies and a wrong message
    /// is rejected.
    static func checkEd25519() -> CheckResult {
        let name = "Ed25519 identity signature"
        do {
            let sk = Curve25519.Signing.PrivateKey()
            let msg = Data("prekey to sign".utf8)
            let sig = try sk.signature(for: msg)
            let good = sk.publicKey.isValidSignature(sig, for: msg)
            let bad = sk.publicKey.isValidSignature(sig, for: Data("prekey to forge".utf8))
            let ok = good && !bad
            return CheckResult(name: name, detail: ok ? "Valid signature verifies; forgery rejected" : "verification anomaly", passed: ok)
        } catch {
            return CheckResult(name: name, detail: "failed: \(error)", passed: false)
        }
    }
}
