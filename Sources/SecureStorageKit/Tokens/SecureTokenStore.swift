import Foundation

/// OAuth-style access and refresh tokens with expiry metadata.
///
/// `description`, `debugDescription` and reflection never show token values,
/// so a `TokenSet` is safe to `print` or log by accident.
public struct TokenSet: Codable, Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var accessToken: String
    public var refreshToken: String?
    public var expiresAt: Date?
    public var tokenType: String
    public var scope: String?
    public var issuedAt: Date

    public init(accessToken: String, refreshToken: String? = nil, expiresAt: Date? = nil,
                tokenType: String = "Bearer", scope: String? = nil, issuedAt: Date = Date()) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
        self.tokenType = tokenType
        self.scope = scope
        self.issuedAt = issuedAt
    }

    /// Convenience for an `expires_in` value in seconds.
    public init(accessToken: String, refreshToken: String? = nil, expiresIn: TimeInterval,
                tokenType: String = "Bearer", scope: String? = nil, now: Date = Date()) {
        self.init(accessToken: accessToken, refreshToken: refreshToken, expiresAt: now.addingTimeInterval(expiresIn),
                  tokenType: tokenType, scope: scope, issuedAt: now)
    }

    /// True if the access token expires within `leeway` seconds. Tokens without
    /// an expiry never expire.
    public func isExpired(leeway: TimeInterval = 30, now: Date = Date()) -> Bool {
        guard let expiresAt else { return false }
        return expiresAt.timeIntervalSince(now) <= leeway
    }

    public var description: String {
        "TokenSet(accessToken: <redacted>, refreshToken: \(refreshToken == nil ? "nil" : "<redacted>"), expiresAt: \(expiresAt.map { "\($0)" } ?? "nil"), tokenType: \(tokenType))"
    }

    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: ["expiresAt": expiresAt as Any, "tokenType": tokenType]) }
}

/// Supplied by the host app to exchange a refresh token for new tokens.
public protocol TokenRefresher: Sendable {
    func refreshTokens(using refreshToken: String, account: String) async throws -> TokenSet
}

/// Stores tokens per account, refreshes them on demand and cleans up on logout.
///
/// Each account has its own namespace, so accounts or tenants never see each
/// other's credentials. Concurrent `validAccessToken` calls for the same account
/// share a single refresh request.
public actor SecureTokenStore {
    private let base: SecureStorage
    private let refresher: (any TokenRefresher)?
    private var refreshes: [String: Task<TokenSet, Error>] = [:]

    private static let tokensKey = "tokens"
    private static let indexKey = "accounts"

    /// - Parameters:
    ///   - configuration: Defaults to `afterFirstUnlockThisDeviceOnly` so background
    ///     refreshes work while the device is locked.
    ///   - refresher: Called when a token is expired. Without one, expired tokens throw `.tokenExpired`.
    public init(configuration: StorageConfiguration, backend: any KeychainBackend = SystemKeychain(),
                refresher: (any TokenRefresher)? = nil) {
        self.base = SecureStorage(configuration: configuration, backend: backend)
        self.refresher = refresher
    }

    public init(service: String, refresher: (any TokenRefresher)? = nil) {
        self.init(configuration: StorageConfiguration(service: service, namespace: "tokens",
                                                      accessibility: .afterFirstUnlockThisDeviceOnly),
                  refresher: refresher)
    }

    // MARK: Tokens

    public func save(_ tokens: TokenSet, for account: String = "default") async throws {
        try await storage(account).save(tokens, forKey: Self.tokensKey)
        try await addToIndex(account)
    }

    /// The stored tokens, possibly expired.
    public func tokens(for account: String = "default") async throws -> TokenSet? {
        try await storage(account).retrieve(Self.tokensKey, as: TokenSet.self)
    }

    /// A non-expired access token, refreshing first if needed.
    ///
    /// Throws `.itemNotFound` when there are no tokens, `.noRefreshToken` or
    /// `.tokenExpired` when the token can't be refreshed, or the refresher's error.
    public func validAccessToken(for account: String = "default", leeway: TimeInterval = 30) async throws -> String {
        guard let tokens = try await tokens(for: account) else { throw StorageError.itemNotFound }
        guard tokens.isExpired(leeway: leeway) else { return tokens.accessToken }
        return try await refresh(account: account, current: tokens).accessToken
    }

    /// Forces a refresh now, sharing any refresh already in progress.
    @discardableResult
    public func refresh(account: String = "default") async throws -> TokenSet {
        guard let tokens = try await tokens(for: account) else { throw StorageError.itemNotFound }
        return try await refresh(account: account, current: tokens)
    }

    public func deleteTokens(for account: String = "default") async throws {
        try await storage(account).delete(Self.tokensKey)
    }

    // MARK: Sessions

    /// Storage for other secrets tied to this account's session. It is wiped on logout.
    public func sessionStorage(for account: String = "default") throws -> SecureStorage {
        base.namespaced("\(base.configuration.namespace).session.\(NamespaceEncoding.encode(account))")
    }

    /// Removes the account's tokens and every session-owned secret.
    public func logout(account: String = "default") async throws {
        refreshes[account]?.cancel()
        refreshes[account] = nil
        try await storage(account).clearAll()
        try await sessionStorage(for: account).clearAll()
        var accounts = try await self.accounts()
        accounts.removeAll { $0 == account }
        try await base.save(accounts, forKey: Self.indexKey)
        base.configuration.eventHandler?(StorageEvent(operation: .logout, namespace: base.configuration.namespace, key: account, outcome: .success))
    }

    /// Logs every account out.
    public func logoutAll() async throws {
        for account in try await accounts() { try await logout(account: account) }
        try await base.delete(Self.indexKey)
    }

    /// Accounts that currently have stored tokens.
    public func accounts() async throws -> [String] {
        try await base.retrieve(Self.indexKey, as: [String].self) ?? []
    }

    // MARK: Internals

    private func storage(_ account: String) throws -> SecureStorage {
        guard !account.isEmpty else { throw StorageError.invalidConfiguration("account must not be empty") }
        return base.namespaced("\(base.configuration.namespace).\(NamespaceEncoding.encode(account))")
    }

    private func addToIndex(_ account: String) async throws {
        var accounts = try await self.accounts()
        guard !accounts.contains(account) else { return }
        accounts.append(account)
        try await base.save(accounts, forKey: Self.indexKey)
    }

    private func refresh(account: String, current: TokenSet) async throws -> TokenSet {
        if let running = refreshes[account] { return try await running.value }
        guard let refresher else { throw StorageError.tokenExpired }
        guard let refreshToken = current.refreshToken else { throw StorageError.noRefreshToken }

        let task = Task { try await refresher.refreshTokens(using: refreshToken, account: account) }
        refreshes[account] = task
        defer { refreshes[account] = nil }
        do {
            var fresh = try await task.value
            // Servers that don't rotate refresh tokens omit them; keep the old one.
            if fresh.refreshToken == nil { fresh.refreshToken = refreshToken }
            try await storage(account).save(fresh, forKey: Self.tokensKey)
            emit(.success, account)
            return fresh
        } catch {
            emit(.failure(error as? StorageError ?? .authenticationFailed), account)
            throw error
        }
    }

    private func emit(_ outcome: StorageEvent.Outcome, _ account: String) {
        base.configuration.eventHandler?(StorageEvent(operation: .tokenRefresh, namespace: base.configuration.namespace, key: account, outcome: outcome))
    }
}
