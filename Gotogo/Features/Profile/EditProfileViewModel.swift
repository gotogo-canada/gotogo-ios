//
//  EditProfileViewModel.swift
//  Gotogo
//
//  Backs the Edit-profile screen: holds the editable display name, picked photo,
//  and sensitive toggle, and saves through `AppState` (which seals the profile key
//  to every current mutual contact). UI-free logic kept out of the view.
//

import SwiftUI
import PhotosUI
import Observation

@MainActor
@Observable
final class EditProfileViewModel {

    var displayName: String = ""
    /// Newly picked photo bytes (nil = keep the existing photo).
    var pickedPhoto: Data?
    /// Decoded preview of the current/picked photo for display.
    var previewImage: UIImage?
    var sensitive: Bool = false

    var saving = false
    var errorMessage: String?
    var didSave = false

    private let appState: AppState

    init(appState: AppState) {
        self.appState = appState
        // Seed from the owner's existing profile, if any.
        if let id = appState.session?.publicId,
           let existing = appState.profileStore.profile(for: id) {
            displayName = existing.displayName
            previewImage = existing.image
        }
        sensitive = appState.profiles.ownProfileIsSensitive()
    }

    var canSave: Bool {
        !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !saving
    }

    /// Loads a freshly picked photo's bytes and updates the preview.
    func loadPickedPhoto(_ item: PhotosPickerItem?) async {
        guard let item else { return }
        guard let data = try? await item.loadTransferable(type: Data.self) else { return }
        pickedPhoto = data
        previewImage = UIImage(data: data)
    }

    /// Seals + publishes the profile to every current mutual contact.
    func save() async {
        let name = displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !saving else { return }
        saving = true
        errorMessage = nil
        do {
            try await appState.saveProfile(displayName: name,
                                           photo: pickedPhoto,
                                           sensitive: sensitive)
            didSave = true
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
        saving = false
    }
}
