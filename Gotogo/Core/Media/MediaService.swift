//
//  MediaService.swift
//  Gotogo
//
//  Orchestrates encrypted media: strip metadata -> thumbnail -> chunked encrypt
//  -> upload the opaque blob via a presigned URL -> return a MediaReference for
//  the E2EE message. And the reverse on download (fetch -> verify hash ->
//  decrypt). Self-contained networking so it stays decoupled. Foundation only.
//
import Foundation

/// Errors specific to media transfer.
public enum MediaServiceError: Error, Sendable {
    case http(Int)
    case integrityMismatch
    case notAnImage
}

/// Uploads/downloads end-to-end-encrypted media blobs.
public final class MediaService: @unchecked Sendable {
    private let baseURL: URL
    private let session: URLSession
    private let lock = NSLock()
    private var token: String?

    public init(baseURL: URL, token: String? = nil, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.token = token
        self.session = session
    }

    public func setToken(_ t: String?) { lock.lock(); token = t; lock.unlock() }
    private var bearer: String? { lock.lock(); defer { lock.unlock() }; return token }

    // MARK: - Outgoing

    /// Strips metadata, builds an encrypted thumbnail, encrypts the full image,
    /// uploads both, and returns the reference to embed in the message.
    public func uploadImage(_ imageData: Data) async throws -> MediaReference {
        guard let clean = MediaProcessing.stripMetadata(imageData) else { throw MediaServiceError.notAnImage }
        let size = MediaProcessing.pixelSize(clean)
        var ref = try await uploadBlob(clean, contentType: "image/jpeg")
        ref.width = size?.width
        ref.height = size?.height
        if let thumbData = MediaProcessing.thumbnail(imageData, maxDimension: 320) {
            let thumb = try await uploadBlob(thumbData, contentType: "image/jpeg")
            ref.thumbMediaId = thumb.mediaId
            ref.thumbKey = thumb.key
            ref.thumbSha256 = thumb.sha256
        }
        return ref
    }

    /// Encrypts and uploads arbitrary data (voice note, video, file).
    public func uploadData(_ data: Data, contentType: String) async throws -> MediaReference {
        try await uploadBlob(data, contentType: contentType)
    }

    private func uploadBlob(_ plaintext: Data, contentType: String) async throws -> MediaReference {
        let (key, ciphertext, sha) = try MediaCrypto.encrypt(plaintext)
        let create: UploadURLResponse = try await json("POST", "/v1/media/upload-url",
            UploadURLRequest(contentType: contentType, sizeBytes: ciphertext.count))
        try await putRaw(create.uploadUrl, ciphertext)
        let _: CompleteResponse = try await json("POST", "/v1/media/complete", CompleteRequest(mediaId: create.mediaId))
        return MediaReference(mediaId: create.mediaId, key: key, sha256: sha,
                              sizeBytes: plaintext.count, contentType: contentType)
    }

    // MARK: - Incoming

    /// Downloads the full blob, verifies its hash, and decrypts it.
    public func download(_ ref: MediaReference) async throws -> Data {
        try await fetchAndDecrypt(mediaId: ref.mediaId, key: ref.key, sha256: ref.sha256)
    }

    /// Downloads + decrypts the thumbnail, if any.
    public func downloadThumbnail(_ ref: MediaReference) async throws -> Data? {
        guard let id = ref.thumbMediaId, let key = ref.thumbKey, let sha = ref.thumbSha256 else { return nil }
        return try await fetchAndDecrypt(mediaId: id, key: key, sha256: sha)
    }

    private func fetchAndDecrypt(mediaId: String, key: Data, sha256: Data) async throws -> Data {
        let dl: DownloadURLResponse = try await json("GET", "/v1/media/\(mediaId)/download-url", Optional<Empty>.none)
        let blob = try await getRaw(dl.downloadUrl)
        guard MediaCrypto.sha256(blob) == sha256 else { throw MediaServiceError.integrityMismatch }
        return try MediaCrypto.decrypt(blob, key: key)
    }

    // MARK: - Networking

    private struct Empty: Codable {}
    private struct UploadURLRequest: Encodable { let contentType: String; let sizeBytes: Int }
    private struct UploadURLResponse: Decodable { let mediaId: String; let objectKey: String; let uploadUrl: String; let expiresInSeconds: Int }
    private struct CompleteRequest: Encodable { let mediaId: String }
    private struct CompleteResponse: Decodable { let state: String; let sizeBytes: Int }
    private struct DownloadURLResponse: Decodable { let downloadUrl: String; let expiresInSeconds: Int }

    private func json<B: Encodable, R: Decodable>(_ method: String, _ path: String, _ body: B?) async throws -> R {
        var req = URLRequest(url: URL(string: baseURL.absoluteString + path)!)
        req.httpMethod = method
        if let b = body { req.httpBody = try JSONEncoder().encode(b); req.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        if let t = bearer { req.setValue("Bearer \(t)", forHTTPHeaderField: "Authorization") }
        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else { throw MediaServiceError.http(code) }
        return try JSONDecoder().decode(R.self, from: data)
    }

    private func putRaw(_ urlString: String, _ data: Data) async throws {
        var req = URLRequest(url: URL(string: urlString)!)
        req.httpMethod = "PUT"; req.httpBody = data
        let (_, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else { throw MediaServiceError.http(code) }
    }

    private func getRaw(_ urlString: String) async throws -> Data {
        let (data, resp) = try await session.data(from: URL(string: urlString)!)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else { throw MediaServiceError.http(code) }
        return data
    }
}
