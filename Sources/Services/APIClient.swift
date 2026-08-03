import Foundation
import Security

struct UsageAPIResponse: Codable {
    let fiveHour: WindowData?
    let sevenDay: WindowData?
    let sevenDayOpus: WindowData?
    let sevenDaySonnet: WindowData?
    let sevenDayClaudeDesign: WindowData?

    enum CodingKeys: String, CodingKey {
        case fiveHour = "five_hour"
        case sevenDay = "seven_day"
        case sevenDayOpus = "seven_day_opus"
        case sevenDaySonnet = "seven_day_sonnet"
        // Claude Design is named "omelette" in the API for historical reasons.
        case sevenDayClaudeDesign = "seven_day_omelette"
    }

    struct WindowData: Codable {
        let utilization: Double // 0-100
        let resetsAt: String? // ISO 8601

        enum CodingKeys: String, CodingKey {
            case utilization
            case resetsAt = "resets_at"
        }

        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.utilization = try container.decodeIfPresent(Double.self, forKey: .utilization) ?? 0
            self.resetsAt = try container.decodeIfPresent(String.self, forKey: .resetsAt)
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(utilization, forKey: .utilization)
            try container.encodeIfPresent(resetsAt, forKey: .resetsAt)
        }
    }
}

final class APIClient {
    private let usageURL = URL(string: "https://api.anthropic.com/api/oauth/usage")!
    private let refreshURL = URL(string: "https://platform.claude.com/v1/oauth/token")!
    private let clientId = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    private let keychainService = "Claude Code-credentials"

    struct OAuthCredentials: Codable {
        var claudeAiOauth: OAuthToken

        struct OAuthToken: Codable {
            var accessToken: String
            var refreshToken: String
            var expiresAt: Int64
            var scopes: [String]
        }
    }

    private struct TokenRefreshResponse: Decodable {
        let accessToken: String
        let refreshToken: String?
        let expiresIn: Int

        enum CodingKeys: String, CodingKey {
            case accessToken = "access_token"
            case refreshToken = "refresh_token"
            case expiresIn = "expires_in"
        }
    }

    func fetchUsage() async throws -> UsageAPIResponse {
        let token = try await getAccessToken()
        do {
            return try await performUsageRequest(token: token)
        } catch let error as APIError {
            // Server may invalidate a token before our local expiry check fires
            // (e.g. revoked from another device). Try one transparent refresh.
            if case .httpError(let code) = error, code == 401 || code == 403 {
                let refreshed = try await refreshAndPersist()
                return try await performUsageRequest(token: refreshed.claudeAiOauth.accessToken)
            }
            throw error
        }
    }

    private func performUsageRequest(token: String) async throws -> UsageAPIResponse {
        var request = URLRequest(url: usageURL, cachePolicy: .reloadIgnoringLocalCacheData)
        request.httpMethod = "GET"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }

        if httpResponse.statusCode == 429 {
            let retryAfter = httpResponse.value(forHTTPHeaderField: "retry-after")
                .flatMap { TimeInterval($0) }
            throw APIError.rateLimited(retryAfter: retryAfter)
        }

        guard httpResponse.statusCode == 200 else {
            throw APIError.httpError(httpResponse.statusCode)
        }

        guard !data.isEmpty else {
            throw APIError.emptyResponse
        }

        do {
            return try JSONDecoder().decode(UsageAPIResponse.self, from: data)
        } catch {
            if let rawString = String(data: data, encoding: .utf8) {
                print("⚠️ Failed to decode API response. Raw data: \(rawString)")
            }
            throw error
        }
    }

    private func getAccessToken() async throws -> String {
        let credentials = try readCredentials()

        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let bufferMs: Int64 = 60_000
        if credentials.claudeAiOauth.expiresAt - bufferMs <= nowMs {
            // Refresh transparently using the stored refresh_token so the user
            // doesn't have to keep `claude` running in a terminal just to keep
            // the access token alive when they use Claude Desktop instead.
            let refreshed = try await refreshAndPersist()
            return refreshed.claudeAiOauth.accessToken
        }

        return credentials.claudeAiOauth.accessToken
    }

    // MARK: - Keychain

    private struct KeychainItem {
        let credentials: OAuthCredentials
        /// Account name reported by the Keychain, when it reported one. Only
        /// needed if the item has to be recreated from scratch — updates match
        /// on service alone, so a missing account is not worth guessing at.
        let account: String?
    }

    /// Query identifying the Claude Code credential item. No
    /// `kSecUseDataProtectionKeychain` — the CLI writes to the file-based login
    /// keychain, and setting it would look in the wrong place.
    private var keychainQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
        ]
    }

    private func readKeychainItem() throws -> KeychainItem {
        var query = keychainQuery
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            break
        case errSecItemNotFound:
            throw APIError.noCredentials
        default:
            // errSecUserCanceled / errSecAuthFailed / errSecInteractionNotAllowed:
            // the item is there, we just weren't allowed to read it. Telling the
            // user to re-run `claude` would send them down the wrong path.
            throw APIError.keychainAccessDenied(status)
        }

        guard let item = result as? [String: Any],
              let data = item[kSecValueData as String] as? Data,
              !data.isEmpty else {
            throw APIError.noCredentials
        }

        let account = item[kSecAttrAccount as String] as? String

        do {
            return KeychainItem(
                credentials: try JSONDecoder().decode(OAuthCredentials.self, from: data),
                account: account
            )
        } catch {
            // Log the shape of the failure, never the payload — it holds the
            // access and refresh tokens in plaintext.
            print("⚠️ Failed to decode credentials from Keychain (\(data.count) bytes): \(Self.describeDecodingFailure(error))")
            throw APIError.corruptedCredentials
        }
    }

    private func readCredentials() throws -> OAuthCredentials {
        try readKeychainItem().credentials
    }

    private func saveCredentials(_ credentials: OAuthCredentials, account: String?) throws {
        let data = try JSONEncoder().encode(credentials)

        // Match on service alone. The CLI stores one item under this service,
        // and narrowing the query with a guessed account name would miss it and
        // silently add a duplicate next to it instead of updating it.
        //
        // SecItemUpdate rewrites the value in place, preserving the existing
        // item and its ACL. There is no window where the item is missing, so
        // the Claude Code CLI never sees the entry vanish mid-rotation (which
        // is what caused the earlier "logout" regression).
        let status = SecItemUpdate(
            keychainQuery as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )

        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var addQuery = keychainQuery
            addQuery[kSecAttrAccount as String] = account ?? NSUserName()
            addQuery[kSecValueData as String] = data
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                print("⚠️ Keychain SecItemAdd failed (OSStatus \(addStatus))")
                throw APIError.keychainWriteFailed
            }
        default:
            print("⚠️ Keychain SecItemUpdate failed (OSStatus \(status))")
            throw APIError.keychainWriteFailed
        }
    }

    private static func describeDecodingFailure(_ error: Error) -> String {
        guard let error = error as? DecodingError else { return "not valid JSON" }
        switch error {
        case .keyNotFound(let key, _):
            return "missing key '\(key.stringValue)'"
        case .typeMismatch(_, let context), .valueNotFound(_, let context):
            return "unexpected type at '\(context.codingPath.map(\.stringValue).joined(separator: "."))'"
        case .dataCorrupted(let context):
            return "corrupted at '\(context.codingPath.map(\.stringValue).joined(separator: "."))'"
        @unknown default:
            return "unrecognized decoding error"
        }
    }

    // MARK: - Token refresh

    private func refreshAndPersist() async throws -> OAuthCredentials {
        let item = try readKeychainItem()
        let refreshed = try await refreshAccessToken(item.credentials)
        do {
            try saveCredentials(refreshed, account: item.account)
        } catch {
            // The server has already rotated the pair, so the copy still in the
            // Keychain is dead regardless. Throwing here would discard the only
            // live credentials we have and strand the user (and the CLI, which
            // shares this item). Use them for this session and retry next time.
            print("⚠️ Refreshed credentials could not be persisted; using them in-memory for this session.")
        }
        return refreshed
    }

    private func refreshAccessToken(_ credentials: OAuthCredentials) async throws -> OAuthCredentials {
        var request = URLRequest(url: refreshURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body: [String: String] = [
            "grant_type": "refresh_token",
            "refresh_token": credentials.claudeAiOauth.refreshToken,
            "client_id": clientId,
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            if let raw = String(data: data, encoding: .utf8), !raw.isEmpty {
                print("⚠️ Token refresh failed: \(raw)")
            }
            throw APIError.tokenRefreshFailed
        }

        let tokenResponse: TokenRefreshResponse
        do {
            tokenResponse = try JSONDecoder().decode(TokenRefreshResponse.self, from: data)
        } catch {
            throw APIError.tokenRefreshFailed
        }

        var updated = credentials
        updated.claudeAiOauth.accessToken = tokenResponse.accessToken
        updated.claudeAiOauth.expiresAt =
            Int64(Date().timeIntervalSince1970 * 1000) + Int64(tokenResponse.expiresIn) * 1000
        if let newRefresh = tokenResponse.refreshToken {
            updated.claudeAiOauth.refreshToken = newRefresh
        }
        return updated
    }

    enum APIError: LocalizedError {
        case noCredentials
        case corruptedCredentials
        case invalidResponse
        case emptyResponse
        case httpError(Int)
        case rateLimited(retryAfter: TimeInterval?)
        case tokenRefreshFailed
        case keychainWriteFailed
        case keychainAccessDenied(OSStatus)

        var errorDescription: String? {
            switch self {
            case .noCredentials:
                return "No Claude Code credentials found in Keychain. Run 'claude' in terminal first."
            case .corruptedCredentials:
                return "Claude Code credentials are corrupted. Run 'claude' in terminal to re-authenticate."
            case .invalidResponse:
                return "Invalid response from API."
            case .emptyResponse:
                return "API returned empty response. Please try again later."
            case .httpError(401), .httpError(403):
                return "Authentication failed. Sign in to Claude Code (terminal or Desktop) to refresh."
            case .httpError(429):
                return "Rate limited. Try again in a moment."
            case .httpError(let code):
                return "HTTP error \(code). Please try again later."
            case .rateLimited(let retryAfter):
                if let seconds = retryAfter, seconds > 0 {
                    return "Rate limited. Retrying in \(Int(seconds))s."
                }
                return "Rate limited. Try again in a moment."
            case .tokenRefreshFailed:
                return "Couldn't refresh credentials. Sign in to Claude Code to re-authenticate."
            case .keychainWriteFailed:
                return "Failed to update credentials in Keychain."
            case .keychainAccessDenied:
                return "Keychain access denied. Allow Claude Usage Monitor to read the 'Claude Code-credentials' item."
            }
        }
    }
}
