import SwiftUI

@main
struct SecureStorageDemoApp: App {
    var body: some Scene {
        WindowGroup {
            TabView {
                KeychainDemoView()
                    .tabItem { Label("Keychain", systemImage: "key.fill") }
                BiometricDemoView()
                    .tabItem { Label("Biometrics", systemImage: "faceid") }
                CryptoDemoView()
                    .tabItem { Label("Encryption", systemImage: "lock.doc.fill") }
                TokenDemoView()
                    .tabItem { Label("Tokens", systemImage: "person.badge.key.fill") }
            }
        }
    }
}
