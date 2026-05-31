# Swift Style Guide

Project-specific Swift conventions for the CPoE macOS application (`apps/cpoe_macos/`).

## 1. File Structure

Organize each file in this order:

1. SPDX license header (if sensitive logic)
2. Imports (grouped, see below)
3. Type declaration with doc comment
4. `// MARK: - Properties / State`
5. `// MARK: - Init`
6. `// MARK: - Public API`
7. `// MARK: - Private Helpers`

Use `// MARK: -` sections extensively to organize code. Common sections:
- `// MARK: - State`
- `// MARK: - Derived Properties`
- `// MARK: - Notification Names`
- `// MARK: - Helper Methods`

## 2. Import Ordering

Group imports with blank lines between groups:

```swift
// 1. Foundation / system frameworks
import Foundation
import SwiftUI
import os.log

// 2. Third-party frameworks
import Supabase
import Auth

// 3. Apple service frameworks
import AuthenticationServices
import LocalAuthentication
import CryptoKit
```

## 3. Access Control

- `private` is the default for implementation details. Use it aggressively.
- `internal` (implicit) for types shared within the module.
- `public` used sparingly, mainly for API boundaries.
- `fileprivate` is rarely used; prefer `private`.
- `nonisolated(unsafe)` for actor-isolated classes when needed for FFI coordination.

```swift
private let logger = AppLogger.make(category: "auth")

@ObservationIgnored nonisolated(unsafe) private var screenLockObservers: [Any] = []
```

## 4. Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Classes, structs, enums | PascalCase | `AuthService`, `CloudProvider` |
| Type suffixes | Service, Controller, Manager, View | `EngineService`, `StatusBarController` |
| Properties | camelCase | `isAuthenticated`, `cloudSyncEnabled` |
| Methods | camelCase, descriptive verbs | `requestAndSetChallenge()`, `createSession()` |
| Static constants | camelCase or UPPER_SNAKE_CASE | `sessionCheckInterval`, `MAX_RETRIES` |
| Private cached state | underscore prefix | `_lastBiometricAuthDateCached` |
| Notification names | camelCase static properties | `Notification.Name.popoverNavigate` |

## 5. Error Handling

Define enum-based errors conforming to the shared `AppError` protocol:

```swift
protocol AppError: LocalizedError, Sendable {
    static var domain: String { get }
    var code: Int { get }
    var isRetryable: Bool { get }
    var recoverySuggestion: String? { get }
}

enum AuthError: AppError, Equatable {
    static let domain = "auth"

    case invalidEmail
    case weakPassword(String)
    case networkError
    case sessionExpired
    case rateLimited(TimeInterval)

    var errorDescription: String? { ... }
    var isRetryable: Bool { ... }
    var recoverySuggestion: String? { ... }
}
```

- Prefer `do/catch` over `Result` type.
- Catch specific error types when possible (`catch let decodeError as DecodingError`).
- Always log errors before discarding them.

## 6. Async / Concurrency

### Actors for Shared State

```swift
actor EngineService: EngineServiceProtocol {
    static let ffiQueue = DispatchQueue(label: "com.writerslogic.ffi", qos: .default)
}

actor ChallengeService { ... }
```

### @MainActor for UI

```swift
@MainActor
@Observable
final class AuthService { ... }

@MainActor
struct PaywallView: View { ... }
```

### Task Patterns

```swift
// Background work
Task.detached(priority: .utility) {
    let result = ffiDrainTextAttestationQueue()
    if result.success {
        logger.info("Text attestation queue: \(result.message ?? "done")")
    }
}
```

- `async void` only for event handlers and `@main` entry points.
- All other async methods return typed values.
- Use `CancellationToken` patterns where applicable.

## 7. SwiftUI & Observation

```swift
@MainActor
@Observable
final class AuthService {
    var isAuthenticated = false

    @ObservationIgnored nonisolated(unsafe) var authStateTask: Task<Void, Never>?
    @ObservationIgnored private var _lastBiometricAuthDateCached: Date?
}
```

- `@Observable` macro for SwiftUI observation (not `ObservableObject`).
- `@ObservationIgnored` for fields that should not trigger view updates.
- `@State` for view-local state; `@ScaledMetric` for responsive sizing.

## 8. Sendable Conformance

Mark value types as `Sendable` for thread safety:

```swift
struct CloudProvider: Identifiable, Hashable, Sendable { ... }
struct GitRepository: Identifiable, Hashable, Sendable { ... }
```

Error types must conform to `Sendable` (via `AppError: LocalizedError, Sendable`).

## 9. Extension Patterns

Use separate files for major extensions:

- `AuthService+ErrorHandling.swift`
- `AuthService+OAuth.swift`
- `AuthService+EmailAuth.swift`
- `AuthService+Session.swift`

Notification name extensions:

```swift
extension Notification.Name {
    private static let prefix = "com.writerslogic.witnessd."

    static let popoverNavigate = Notification.Name("\(prefix)popoverNavigate")
    static let deepLinkVerify = Notification.Name("\(prefix)deepLinkVerify")
}
```

## 10. Rust FFI Integration

- UniFFI generates `CPoEEngineFFI.swift` automatically; do not edit it.
- All FFI calls must go through actor isolation (the Rust engine is not thread-safe).
- Use a serial `DispatchQueue` as backup for FFI isolation.
- Circuit breaker pattern for FFI health monitoring:

```swift
var consecutiveFFIFailures: Int = 0
var engineHealthy: Bool = true

func recordFFISuccess(operationClass: FFIOperationClass = .general) { ... }
func recordFFIFailure(_ label: String, operationClass: FFIOperationClass = .general) { ... }
```

### Token Bridge (Rust FFI file)

When persisting tokens for the Rust layer, use TOCTOU-safe POSIX I/O:

```swift
let fd = open(cpath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0o600)
defer { close(fd) }
```

## 11. Documentation

Triple-slash `///` with multi-line explanations for complex types:

```swift
/// Manages WritersProof session lifecycle and 30-second timeline challenge nonces.
///
/// When the sentinel starts tracking a document, this service creates a WP session.
/// Before each checkpoint, it requests a challenge nonce and pushes it to the engine
/// via `ffiSentinelSetChallengeNonce`.
actor ChallengeService { ... }
```

Inline comments for complex logic. SPDX headers on files with sensitive/licensed logic.

## 12. Testing

- Test files in `WritersLogicTests/` directory, named `{Component}Tests.swift`.
- Test classes: `final class {Component}Tests: XCTestCase` with `@MainActor` when needed.
- Test method naming: `test_{scenario}_{expectedBehavior}()`.

```swift
@MainActor
final class AuthErrorTests: XCTestCase {
    func test_errorDescription_invalidEmail() {
        let error = AuthError.invalidEmail
        XCTAssertEqual(error.errorDescription, "Please enter a valid email address.")
    }
}
```

## 13. UserDefaults

Use typed computed properties:

```swift
var includePersonalDetailsInReports: Bool {
    get { UserDefaults.standard.object(forKey: "includePersonalDetailsInReports") as? Bool ?? false }
    set { UserDefaults.standard.set(newValue, forKey: "includePersonalDetailsInReports") }
}
```

## 14. Security Patterns

- Rate limiters for auth operations (`SignInRateLimiter`, `PerAccountRateLimiter`).
- Deep link replay prevention with session-scoped processed hashes and time windows.
- Keychain access via `KeychainHelper` with typed search queries.
- Validate JWT structure before persisting.
- POSIX `O_NOFOLLOW` on file writes to prevent symlink attacks.
