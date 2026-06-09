//
//  RegisterView.swift
//  Gotogo
//
//  First-launch screen: app name + "Create account". On success it presents the
//  recovery phrase; confirming there enters the app. Also offers Recover.
//

import SwiftUI

struct RegisterView: View {
    @Environment(AppState.self) private var appState
    @State private var model: RegisterViewModel?
    @State private var showRecovery = false
    @State private var showLink = false
    @State private var showServer = false

    var body: some View {
        NavigationStack {
            VStack(spacing: Theme.Spacing.xl) {
                Spacer()
                brand
                Spacer()
                if let model {
                    actions(model)
                } else {
                    ProgressView().frame(height: 44)
                }
                serverFooter
            }
            .padding(Theme.Spacing.xl)
            .modifier(RegisterFlowModifiers(model: model, homeDomain: appState.homeDomain,
                                            showRecovery: $showRecovery,
                                            onAdopt: { appState.adopt($0) }))
            .sheet(isPresented: $showLink) {
                LinkAdoptView { showLink = false }
            }
            .sheet(isPresented: $showServer) {
                ServerSelectView()
            }
        }
        .task {
            if model == nil { model = RegisterViewModel(auth: appState.auth) }
        }
    }

    /// Shows the chosen home server with a Change action (federation: pick where
    /// your account lives before creating it).
    private var serverFooter: some View {
        Button {
            showServer = true
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "server.rack")
                Text("Server: \(appState.homeDomain)")
                Text("·").foregroundStyle(Theme.Palette.secondaryText)
                Text("Change").fontWeight(.semibold)
            }
            .font(.footnote)
            .foregroundStyle(Theme.Palette.secondaryText)
        }
        .disabled(model?.isWorking ?? false)
    }

    private var brand: some View {
        VStack(spacing: Theme.Spacing.md) {
            Image(systemName: "lock.circle.fill")
                .font(.system(size: 72))
                .foregroundStyle(Theme.Palette.accent)
            Text("Gotogo")
                .font(.largeTitle.bold())
            Text("Private, end-to-end encrypted messaging.")
                .font(.subheadline)
                .foregroundStyle(Theme.Palette.secondaryText)
                .multilineTextAlignment(.center)
        }
    }

    private func actions(_ model: RegisterViewModel) -> some View {
        VStack(spacing: Theme.Spacing.md) {
            Button {
                Task { await model.createAccount() }
            } label: {
                if model.isWorking {
                    ProgressView().tint(.white).frame(maxWidth: .infinity).padding(.vertical, Theme.Spacing.md)
                        .background(Theme.Palette.accent)
                        .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.card, style: .continuous))
                } else {
                    Text("Create account").primaryButtonStyle()
                }
            }
            .disabled(model.isWorking)

            Button("I already have an account") { showRecovery = true }
                .font(.subheadline)
                .foregroundStyle(Theme.Palette.accent)
                .disabled(model.isWorking)

            Button("Link to an existing account") { showLink = true }
                .font(.subheadline)
                .foregroundStyle(Theme.Palette.accent)
                .disabled(model.isWorking)
        }
    }

}

/// Hosts the navigation/sheet/alert flow for `RegisterView`, tolerating a nil
/// model (during first-frame initialization).
private struct RegisterFlowModifiers: ViewModifier {
    let model: RegisterViewModel?
    let homeDomain: String
    @Binding var showRecovery: Bool
    let onAdopt: (Session) -> Void

    func body(content: Content) -> some View {
        content
            .navigationDestination(isPresented: registeredBinding) {
                if let model, model.phase == .registered {
                    PostCreateView(model: model, domain: homeDomain) {
                        if let session = model.pendingSession { onAdopt(session) }
                    }
                }
            }
            .sheet(isPresented: $showRecovery) {
                if let model {
                    RecoveryView(model: model) { session in
                        onAdopt(session)
                        showRecovery = false
                    }
                }
            }
            .alert("Couldn't create account", isPresented: failedBinding) {
                Button("OK") { model?.reset() }
            } message: {
                if let model, case .failed(let message) = model.phase { Text(message) }
            }
    }

    private var registeredBinding: Binding<Bool> {
        Binding(
            get: { if let model, model.phase == .registered { return true } else { return false } },
            set: { newValue in if !newValue { model?.reset() } }
        )
    }

    private var failedBinding: Binding<Bool> {
        Binding(
            get: { if let model, case .failed = model.phase { return true } else { return false } },
            set: { _ in }
        )
    }
}
