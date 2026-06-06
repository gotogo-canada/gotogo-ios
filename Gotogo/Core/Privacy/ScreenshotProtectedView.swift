//
//  ScreenshotProtectedView.swift
//  Gotogo
//
//  A SwiftUI wrapper that hosts arbitrary content inside the *secure* layer of a
//  `UITextField(isSecureTextEntry: true)`. iOS deliberately excludes that layer
//  from screenshots and screen recordings (it's the same mechanism that blanks a
//  password field in captures), so anything hosted there — here, the 24-word
//  recovery phrase — is omitted from any capture while still being visible live on
//  the device. The text field itself is never first responder and shows no text;
//  we only borrow its capture-excluded canvas.
//

import SwiftUI
import UIKit

/// Wraps `content` so it is rendered inside a secure text field's screenshot-
/// excluded layer. The content is fully visible on-device but absent from
/// screenshots / screen recordings.
struct ScreenshotProtectedView<Content: View>: UIViewRepresentable {
    private let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    func makeUIView(context: Context) -> UIView {
        let host = UIHostingController(rootView: content)
        host.view.backgroundColor = .clear
        return SecureCanvasView(hosting: host)
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        guard let secure = uiView as? SecureCanvasView else { return }
        secure.update(rootView: content)
    }

    @MainActor
    func sizeThatFits(_ proposal: ProposedViewSize, uiView: UIView, context: Context) -> CGSize? {
        guard let secure = uiView as? SecureCanvasView else { return nil }
        let target = CGSize(width: proposal.width ?? UIView.layoutFittingExpandedSize.width,
                            height: proposal.height ?? UIView.layoutFittingCompressedSize.height)
        return secure.fittingSize(for: target)
    }
}

/// A view whose only purpose is to expose the capture-excluded layer of a secure
/// `UITextField` and pin a SwiftUI hosting view inside it. The text field carries
/// no text and never becomes first responder; we use it purely as a canvas iOS
/// refuses to put into screenshots.
private final class SecureCanvasView: UIView {
    private let secureField = UITextField()
    private let hosting: UIHostingController<AnyView>

    init<Content: View>(hosting controller: UIHostingController<Content>) {
        self.hosting = UIHostingController(rootView: AnyView(controller.rootView))
        super.init(frame: .zero)

        secureField.isSecureTextEntry = true   // the bit that excludes from capture
        secureField.isUserInteractionEnabled = false
        secureField.backgroundColor = .clear
        secureField.translatesAutoresizingMaskIntoConstraints = false
        addSubview(secureField)
        NSLayoutConstraint.activate([
            secureField.topAnchor.constraint(equalTo: topAnchor),
            secureField.bottomAnchor.constraint(equalTo: bottomAnchor),
            secureField.leadingAnchor.constraint(equalTo: leadingAnchor),
            secureField.trailingAnchor.constraint(equalTo: trailingAnchor),
        ])

        // The secure text field's protected canvas is its first sublayer container;
        // on current iOS this is exposed via a private content view that is itself
        // excluded from capture. Hosting our SwiftUI content there inherits that
        // exclusion. Fall back to the field itself if the layout view isn't present.
        let canvas = secureField.subviews.first ?? secureField
        hosting.view.backgroundColor = .clear
        hosting.view.translatesAutoresizingMaskIntoConstraints = false
        canvas.addSubview(hosting.view)
        NSLayoutConstraint.activate([
            hosting.view.topAnchor.constraint(equalTo: canvas.topAnchor),
            hosting.view.bottomAnchor.constraint(equalTo: canvas.bottomAnchor),
            hosting.view.leadingAnchor.constraint(equalTo: canvas.leadingAnchor),
            hosting.view.trailingAnchor.constraint(equalTo: canvas.trailingAnchor),
        ])
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    /// Swaps in fresh SwiftUI content (driven by `updateUIView`).
    func update<Content: View>(rootView: Content) {
        hosting.rootView = AnyView(rootView)
        setNeedsLayout()
    }

    /// Asks the hosted SwiftUI content for its preferred size within `target`.
    func fittingSize(for target: CGSize) -> CGSize {
        hosting.sizeThatFits(in: target)
    }

    override var intrinsicContentSize: CGSize {
        hosting.sizeThatFits(in: CGSize(width: bounds.width > 0 ? bounds.width : UIView.layoutFittingExpandedSize.width,
                                        height: UIView.layoutFittingCompressedSize.height))
    }
}
