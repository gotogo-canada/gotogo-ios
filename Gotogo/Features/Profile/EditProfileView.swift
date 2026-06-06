//
//  EditProfileView.swift
//  Gotogo
//
//  The "Edit profile" screen reached from the Me tab: a display-name field, a
//  photo picker, a "Sensitive (ML-KEM-1024)" toggle, and Save. Saving seals the
//  profile key to every current mutual contact and publishes the encrypted blob.
//

import SwiftUI
import PhotosUI

struct EditProfileView: View {
    @Environment(AppState.self) private var appState
    @Environment(\.dismiss) private var dismiss

    @State private var model: EditProfileViewModel?
    @State private var photoItem: PhotosPickerItem?

    var body: some View {
        Group {
            if let model {
                form(model)
            } else {
                ProgressView()
            }
        }
        .navigationTitle("Edit profile")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) { saveButton }
        }
        .onAppear { if model == nil { model = EditProfileViewModel(appState: appState) } }
        .onChange(of: photoItem) { _, item in
            Task { await model?.loadPickedPhoto(item) }
        }
    }

    private func form(_ model: EditProfileViewModel) -> some View {
        @Bindable var model = model
        return Form {
            photoSection(model)
            nameSection(model)
            sensitiveSection(model)
        }
        .alert("Couldn't save", isPresented: errorBinding(model)) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
        .onChange(of: model.didSave) { _, saved in if saved { dismiss() } }
    }

    // MARK: Sections

    private func photoSection(_ model: EditProfileViewModel) -> some View {
        let hasPhoto = model.previewImage != nil
        return Section {
            HStack {
                Spacer()
                VStack(spacing: Theme.Spacing.md) {
                    avatarPreview(model)
                    PhotosPicker(selection: $photoItem, matching: .images, photoLibrary: .shared()) {
                        Label(hasPhoto ? "Change photo" : "Add photo", systemImage: "camera")
                    }
                    .disabled(model.saving)
                }
                Spacer()
            }
            .padding(.vertical, Theme.Spacing.sm)
        }
    }

    private func avatarPreview(_ model: EditProfileViewModel) -> some View {
        Group {
            if let image = model.previewImage {
                Image(uiImage: image).resizable().scaledToFill()
            } else {
                Circle()
                    .fill(Theme.Palette.accent.opacity(0.15))
                    .overlay(Image(systemName: "person.fill")
                        .font(.system(size: 36))
                        .foregroundStyle(Theme.Palette.accent))
            }
        }
        .frame(width: 96, height: 96)
        .clipShape(Circle())
    }

    private func nameSection(_ model: EditProfileViewModel) -> some View {
        Section {
            TextField("Your name", text: Binding(get: { model.displayName },
                                                  set: { model.displayName = $0 }))
                .textInputAutocapitalization(.words)
                .disabled(model.saving)
        } header: {
            Text("Display name")
        } footer: {
            Text("Shared end-to-end encrypted only with your mutual contacts.")
        }
    }

    private func sensitiveSection(_ model: EditProfileViewModel) -> some View {
        Section {
            Toggle("Sensitive (ML-KEM-1024)", isOn: Binding(get: { model.sensitive },
                                                            set: { model.sensitive = $0 }))
                .disabled(model.saving)
        } footer: {
            Text("Seals your profile to each contact with pure post-quantum ML-KEM-1024 (Level 5), for the highest sensitivity.")
        }
    }

    private var saveButton: some View {
        Button("Save") { Task { await model?.save() } }
            .disabled(!(model?.canSave ?? false))
            .overlay { if model?.saving == true { ProgressView() } }
    }

    private func errorBinding(_ model: EditProfileViewModel) -> Binding<Bool> {
        Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })
    }
}
