# Gotogo iOS

Gotogo iOS is the SwiftUI client for Gotogo, a privacy-focused messaging stack
where clients own the encryption keys and the backend stores opaque encrypted
data.

The app includes account registration and recovery, encrypted messaging,
contact gating, encrypted profiles, media attachments, group conversations,
device linking, safety verification, and local privacy protections.

## Repository Layout

```text
Gotogo.xcodeproj/          Xcode project and shared scheme
Gotogo/                    SwiftUI app, services, models, crypto, and UI
GotogoTests/               Unit and integration-style XCTest coverage
Info.plist                 App metadata and privacy usage descriptions
```

## Requirements

- Xcode 26.5 or newer
- iOS Simulator runtime matching the project deployment target
- A running Gotogo backend for end-to-end service tests

## Local Development

Open the project in Xcode:

```sh
open Gotogo.xcodeproj
```

The app defaults to the production Gotogo API. For local backend testing, set
these environment variables in your Xcode scheme:

```text
GOTOGO_ENV=local
GOTOGO_API=http://localhost:8080
GOTOGO_WS=ws://localhost:8080
```

When testing on a physical device, replace `localhost` with a private host or
LAN address reachable by the device. Do not commit personal network addresses
or private backend URLs.

## Build And Test

List schemes:

```sh
xcodebuild -list -project Gotogo.xcodeproj
```

Build for the simulator:

```sh
xcodebuild \
  -project Gotogo.xcodeproj \
  -scheme Gotogo \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

Some XCTest files exercise the live Gotogo backend. Set `GOTOGO_API` and
`GOTOGO_WS` before running those tests against a local stack.

## Local Safety Hooks

Enable the repository hooks after cloning:

```sh
git config core.hooksPath .githooks
```

The pre-commit hook runs `scripts/audit.sh --staged`. The pre-push hook runs
`scripts/audit.sh --full`, including secret scans, repository hygiene checks,
MIT license verification, Apple signing-account metadata checks, and a
simulator build when Xcode is available.

## Security

Please do not publish exploit details or sensitive material in public issues.
See [SECURITY.md](SECURITY.md) for the vulnerability reporting process.

## License

Gotogo iOS is released under the [MIT License](LICENSE).
