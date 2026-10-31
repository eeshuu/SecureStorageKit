import Foundation
import Testing
@testable import SecureStorageKit

actor MockRefresher: TokenRefresher {
    private(set) var calls = 0
    var failure: StorageError?
    var rotatesRefreshToken = true

    func setFailure(_ error: StorageError?) { failure = error }

    func refreshTokens(using refreshToken: String, account: String) async throws -> TokenSet {
        calls += 1
        try await Task.sleep(nanoseconds: 50_000_000)
        if let failure { throw failure }
        return TokenSet(accessToken: "access-\(calls)", refreshToken: rotatesRefreshToken ? "refresh-\(calls)" : nil, expiresIn: 3600)
    }
}

@Suite("Token store")
struct TokenStoreTests {
    func makeStore(_ refresher: (any TokenRefresher)? = nil, backend: InMemoryKeychain = InMemoryKeychain()) -> SecureTokenStore {
        SecureTokenStore(configuration: .init(service: "test-service", namespace: "tokens", accessibility: .afterFirstUnlockThisDeviceOnly),
                         backend: backend, refresher: refresher)
    }

    @Test func savesAndReturnsValidToken() async throws {
        let store = makeStore()
        try await store.save(TokenSet(accessToken: "abc", refreshToken: "r", expiresIn: 3600))
        #expect(try await store.validAccessToken() == "abc")
        #expect(try await store.tokens()?.refreshToken == "r")
    }

    @Test func refreshesExpiredTokenOnce() async throws {
        let refresher = MockRefresher()
        let store = makeStore(refresher)
        try await store.save(TokenSet(accessToken: "old", refreshToken: "r0", expiresIn: -10))

        let tokens = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<10 { group.addTask { try await store.validAccessToken() } }
            return try await group.reduce(into: [String]()) { $0.append($1) }
        }
        #expect(Set(tokens) == ["access-1"])
        #expect(await refresher.calls == 1)
        #expect(try await store.tokens()?.refreshToken == "refresh-1")
    }

    @Test func keepsRefreshTokenWhenServerDoesNotRotate() async throws {
        let refresher = MockRefresher()
        await refresher.setRotates(false)
        let store = makeStore(refresher)
        try await store.save(TokenSet(accessToken: "old", refreshToken: "keep-me", expiresIn: -10))
        _ = try await store.validAccessToken()
        #expect(try await store.tokens()?.refreshToken == "keep-me")
    }

    @Test func expiredWithoutRefresherOrRefreshToken() async throws {
        let noRefresher = makeStore()
        try await noRefresher.save(TokenSet(accessToken: "old", refreshToken: "r", expiresIn: -10))
        #expect(await expectError(.tokenExpired) { try await noRefresher.validAccessToken() })

        let noRefreshToken = makeStore(MockRefresher())
        try await noRefreshToken.save(TokenSet(accessToken: "old", expiresIn: -10))
        #expect(await expectError(.noRefreshToken) { try await noRefreshToken.validAccessToken() })

        #expect(await expectError(.itemNotFound) { try await makeStore().validAccessToken(for: "nobody") })
    }

    @Test func refreshFailureLeavesTokensInPlace() async throws {
        let refresher = MockRefresher()
        await refresher.setFailure(.authenticationFailed)
        let store = makeStore(refresher)
        try await store.save(TokenSet(accessToken: "old", refreshToken: "r", expiresIn: -10))
        #expect(await expectError(.authenticationFailed) { try await store.validAccessToken() })
        #expect(try await store.tokens()?.accessToken == "old")
    }

    @Test func accountsAreIsolatedAndLogoutCleansUp() async throws {
        let backend = InMemoryKeychain()
        let store = makeStore(backend: backend)
        try await store.save(TokenSet(accessToken: "a"), for: "alice")
        try await store.save(TokenSet(accessToken: "b"), for: "bob/tenant-2")
        try await store.sessionStorage(for: "alice").save("pin", forKey: "pin")
        try await store.sessionStorage(for: "bob/tenant-2").save("pin", forKey: "pin")
        #expect(try await store.accounts() == ["alice", "bob/tenant-2"])

        try await store.logout(account: "alice")

        #expect(try await store.tokens(for: "alice") == nil)
        #expect(try await store.sessionStorage(for: "alice").allKeys().isEmpty)
        #expect(try await store.tokens(for: "bob/tenant-2")?.accessToken == "b")
        #expect(try await store.sessionStorage(for: "bob/tenant-2").retrieve("pin", as: String.self) == "pin")
        #expect(try await store.accounts() == ["bob/tenant-2"])

        try await store.logoutAll()
        #expect(backend.count == 0)
    }

    @Test func tokenDescriptionsAreRedacted() {
        let tokens = TokenSet(accessToken: "eyJhbGciOi.secret", refreshToken: "refresh-secret", expiresIn: 60)
        for text in [String(describing: tokens), String(reflecting: tokens), "\(tokens)", dumped(tokens)] {
            #expect(!text.contains("secret"))
        }
        #expect(String(describing: Redacted("password123")) == "<redacted>")
        #expect(!dumped(Redacted("password123")).contains("password123"))
    }

    @Test func expiryUsesLeeway() {
        let now = Date()
        let tokens = TokenSet(accessToken: "a", expiresAt: now.addingTimeInterval(20))
        #expect(tokens.isExpired(leeway: 30, now: now))
        #expect(tokens.isExpired(leeway: 10, now: now) == false)
        #expect(TokenSet(accessToken: "a").isExpired() == false)
    }

    func dumped<T>(_ value: T) -> String {
        var output = ""
        dump(value, to: &output)
        return output
    }
}

extension MockRefresher {
    func setRotates(_ value: Bool) { rotatesRefreshToken = value }
}
