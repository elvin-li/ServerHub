import AppKit
import Darwin
import Foundation

private enum MenuLanguage: String {
    case simplifiedChinese = "zh-Hans"
    case english = "en"
}

private enum L10n {
    static let language: MenuLanguage = {
        let override = ProcessInfo.processInfo.environment["SERVERHUB_LANGUAGE"]?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let requested: String
        if let override, !override.isEmpty {
            requested = override
        } else {
            requested = Locale.preferredLanguages.first ?? "en"
        }
        return requested.lowercased().hasPrefix("zh") ? .simplifiedChinese : .english
    }()

    static func text(_ simplifiedChinese: String, _ english: String) -> String {
        language == .simplifiedChinese ? simplifiedChinese : english
    }
}

private func localized(_ simplifiedChinese: String, _ english: String) -> String {
    L10n.text(simplifiedChinese, english)
}

private enum Labels {
    static let panel = "local.serverhub"
    static let launcher = "local.serverhub-launcher"
}

private struct CommandResult {
    let status: Int32
    let output: String
}

private struct ServiceCounts: Decodable {
    let ok: Int?
    let warn: Int?
    let down: Int?
    let stopped: Int?
    let unknown: Int?
}

private struct ServiceLink: Decodable {
    let name: String?
    let url: String?
}

private struct PanelService: Decodable {
    let id: String?
    let name: String?
    let state: String?
    let url: String?
    let port: Int?
    let actions: [String]?
    let links: [ServiceLink]?
    let detail: String?
}

private struct ServiceGroup: Decodable {
    let group: String?
    let services: [PanelService]?
}

private struct PanelStatus: Decodable {
    let counts: ServiceCounts?
    let groups: [ServiceGroup]?
    let problems: [PanelService]?
    let links: [ServiceLink]?
}

private struct ServiceActionRequest: Encodable {
    let target: String
    let action: String
}

private struct ServiceActionResponse: Decodable {
    let ok: Bool?
    let message: String?
}

private final class ResultBox<Value>: @unchecked Sendable {
    var value: Value?
}

private func safeWebURL(_ rawURL: String?) -> URL? {
    guard let rawURL,
          let url = URL(string: rawURL),
          let scheme = url.scheme?.lowercased(),
          scheme == "http" || scheme == "https",
          url.host != nil else { return nil }
    return url
}

private func inferredPort(_ rawURL: String?) -> Int? {
    guard let url = safeWebURL(rawURL) else { return nil }
    if let port = url.port { return port }
    return url.scheme?.lowercased() == "http" ? 80 : 443
}

private func stateDot(_ state: String?) -> String {
    switch state ?? "unknown" {
    case "ok": return "🟢"
    case "stopped": return "⚪️"
    case "down": return "🔴"
    default: return "🟡"
    }
}

private func serviceTitle(_ service: PanelService) -> String {
    let fallback = localized("服务", "Service")
    var title = "\(stateDot(service.state)) \(service.name ?? service.id ?? fallback)"
    if let port = service.port ?? inferredPort(service.url) {
        title += "  :\(port)"
    }
    return title
}

private func groupTitle(_ group: ServiceGroup) -> String {
    let services = group.services ?? []
    let active = services.filter { ($0.state ?? "unknown") != "stopped" }
    let stopped = services.count - active.count
    let healthy = active.filter { ($0.state ?? "unknown") == "ok" }.count
    let problemStates = active.map { $0.state ?? "unknown" }.filter { $0 != "ok" }
    let dot = problemStates.contains("down") ? "🔴"
        : (!problemStates.isEmpty ? "🟡" : (active.isEmpty ? "⚪️" : "🟢"))
    let name = group.group ?? localized("服务", "Services")
    if active.isEmpty {
        return localized(
            "\(dot) \(name)（\(stopped) 已停止）",
            "\(dot) \(name) (\(stopped) stopped)"
        )
    }
    let stoppedSuffix = stopped > 0
        ? localized(" · \(stopped) 已停止", " · \(stopped) stopped")
        : ""
    return localized(
        "\(dot) \(name)（\(healthy)/\(active.count) 运行\(stoppedSuffix)）",
        "\(dot) \(name) (\(healthy)/\(active.count) running\(stoppedSuffix))"
    )
}

private func statusSummary(_ status: PanelStatus) -> String {
    let counts = status.counts
    let warnings = (counts?.warn ?? 0) + (counts?.unknown ?? 0)
    return localized(
        "\(counts?.ok ?? 0) 正常 · \(warnings) 警告 · \(counts?.down ?? 0) 故障 · \(counts?.stopped ?? 0) 已停止",
        "\(counts?.ok ?? 0) OK · \(warnings) warnings · \(counts?.down ?? 0) down · \(counts?.stopped ?? 0) stopped"
    )
}

private var serviceActionLabels: [String: String] {
    [
        "restart": localized("🔄 重启", "🔄 Restart"),
        "stop": localized("⏹ 停止", "⏹ Stop"),
        "start": localized("▶️ 启动", "▶️ Start"),
        "run": localized("⚡ 立即运行", "⚡ Run Now"),
        "pause": localized("⏸ 暂停", "⏸ Pause"),
        "unpause": localized("▶️ 继续", "▶️ Resume"),
        "resume": localized("▶️ 继续", "▶️ Resume"),
        "suspend": localized("💤 挂起", "💤 Suspend"),
    ]
}

private func visibleActions(_ service: PanelService) -> [(id: String, title: String)] {
    var actions: [(id: String, title: String)] = []
    for action in service.actions ?? [] {
        if action == "logs" {
            actions.append((id: action, title: localized("📄 查看日志", "📄 View Logs")))
        } else if let title = serviceActionLabels[action] {
            actions.append((id: action, title: title))
        }
    }
    return actions
}

private func dumpMenuSnapshot() -> Int32 {
    let manager = ServiceManager()
    let result = ResultBox<Result<PanelStatus, Error>>()
    let completed = DispatchSemaphore(value: 0)
    manager.fetchStatus {
        result.value = $0
        completed.signal()
    }
    guard completed.wait(timeout: .now() + 8) == .success else {
        FileHandle.standardError.write(Data("ServerHub menu snapshot timed out\n".utf8))
        return 1
    }
    guard let fetched = result.value else {
        FileHandle.standardError.write(Data("ServerHub menu snapshot returned no result\n".utf8))
        return 1
    }
    switch fetched {
    case let .failure(error):
        FileHandle.standardError.write(Data("ServerHub menu snapshot failed: \(error.localizedDescription)\n".utf8))
        return 1
    case let .success(status):
        print("SUMMARY\t\(statusSummary(status))")
        let problems = status.problems ?? []
        print("ATTENTION\t\(problems.count)")
        for service in problems.prefix(12) {
            print("PROBLEM\t\(serviceTitle(service))")
        }
        for group in status.groups ?? [] {
            let services = group.services ?? []
            guard !services.isEmpty else { continue }
            print("GROUP\t\(groupTitle(group))")
            for service in services {
                print("SERVICE\t\(serviceTitle(service))")
                if let url = safeWebURL(service.url) {
                    print("LINK\tservice\t\(url.absoluteString)")
                }
                for link in service.links ?? [] {
                    if let url = safeWebURL(link.url) {
                        print("LINK\tservice-extra\t\(url.absoluteString)")
                    }
                }
                for action in visibleActions(service) {
                    print("ACTION\t\(service.id ?? "")\t\(action.id)\t\(action.title)")
                }
            }
        }
        for link in status.links ?? [] {
            if let url = safeWebURL(link.url) {
                print("LINK\tquick\t\(url.absoluteString)")
            }
        }
        return 0
    }
}

private enum APIRequestError: LocalizedError {
    case invalidResponse
    case http(Int, String)

    var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "The ServerHub API returned an invalid response."
        case let .http(status, message):
            return message.isEmpty ? "ServerHub API request failed (HTTP \(status))." : message
        }
    }
}

private final class ServiceActionPayload: NSObject {
    let target: String
    let action: String
    let name: String

    init(target: String, action: String, name: String) {
        self.target = target
        self.action = action
        self.name = name
    }
}

private final class ServiceManager: @unchecked Sendable {
    let uid = getuid()
    let home = FileManager.default.homeDirectoryForCurrentUser
    let appURL = Bundle.main.bundleURL
    let root: URL
    let stateRoot: URL
    let pythonURL: URL
    let isBundledRuntime: Bool
    let port: String

    init() {
        let resources = Bundle.main.resourceURL
        let packagedRoot = resources?.appendingPathComponent("ServerHubRuntime", isDirectory: true)
        let packagedApp = packagedRoot?.appendingPathComponent("app.py")
        let hasPackagedRuntime = packagedApp.map {
            FileManager.default.fileExists(atPath: $0.path)
        } ?? false
        let supportRoot = home.appendingPathComponent(
            "Library/Application Support/ServerHub",
            isDirectory: true
        )

        if hasPackagedRuntime, let packagedRoot {
            root = packagedRoot
            stateRoot = supportRoot
            pythonURL = packagedRoot.appendingPathComponent("python/bin/python3")
            isBundledRuntime = true
        } else {
            let savedRoot = UserDefaults.standard.string(forKey: "ServerHubInstallRoot").map {
                URL(fileURLWithPath: $0, isDirectory: true)
            }
            let rootFile = resources?.appendingPathComponent("install-root.txt")
            let recordedRoot = rootFile.flatMap { try? String(contentsOf: $0, encoding: .utf8) }
                .map {
                    URL(
                        fileURLWithPath: $0.trimmingCharacters(in: .whitespacesAndNewlines),
                        isDirectory: true
                    )
                }
            let fallback = supportRoot.appendingPathComponent("runtime", isDirectory: true)
            let candidates = [savedRoot, recordedRoot, fallback].compactMap { $0 }
            root = candidates.first(where: {
                FileManager.default.fileExists(atPath: $0.appendingPathComponent("app.py").path)
            }) ?? fallback
            stateRoot = root
            pythonURL = root.appendingPathComponent(".venv/bin/python")
            isBundledRuntime = false
        }
        port = Self.validatedPort(ProcessInfo.processInfo.environment["SERVERHUB_PORT"])
        UserDefaults.standard.set(root.path, forKey: "ServerHubInstallRoot")
    }

    /// A TCP port, or the default, matching `app.py:_port()`.
    ///
    /// The raw environment value used to be interpolated into `panelURL` as-is,
    /// which was wrong in two ways.  A non-numeric value ("abc", "-1", "80 90")
    /// made `URL(string:)` return nil and the force-unwrap below crash the
    /// menu-bar app.  Worse, a value containing a slash was not a port at all:
    /// `SERVERHUB_PORT=8086/../x` produced `http://127.0.0.1:8086/../x`, and
    /// since every API call is built by appending a path to `panelURL`, that
    /// redirected requests which carry the local-client token in a header.
    ///
    /// `launchctl setenv` is available to any process running as this user, so
    /// the value is not self-supplied just because the LaunchAgent normally sets
    /// it.  Validating here also keeps the app and `app.py` agreeing on which
    /// port they mean, instead of silently talking past each other.
    static func validatedPort(_ raw: String?) -> String {
        guard let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty,
              let parsed = Int(trimmed),
              (1...65535).contains(parsed)
        else { return "8086" }
        return String(parsed)
    }

    /// Never force-unwrapped: `port` is validated, and the fallback keeps a bad
    /// value from being fatal even if that ever changes.
    var panelURL: URL {
        URL(string: "http://127.0.0.1:\(port)")
            ?? URL(string: "http://127.0.0.1:8086")!
    }
    var setupURL: URL { panelURL.appendingPathComponent("settings") }
    var errorLogURL: URL { logsURL.appendingPathComponent("serverhub.err.log") }
    private var agentsURL: URL { home.appendingPathComponent("Library/LaunchAgents", isDirectory: true) }
    private var logsURL: URL { home.appendingPathComponent("Library/Logs", isDirectory: true) }
    private var panelPlist: URL { agentsURL.appendingPathComponent("\(Labels.panel).plist") }
    private var launcherPlist: URL { agentsURL.appendingPathComponent("\(Labels.launcher).plist") }
    private var domain: String { "gui/\(uid)" }
    private var localTokenURL: URL { stateRoot.appendingPathComponent("data/.local-client-token") }
    private var setupTokenURL: URL { stateRoot.appendingPathComponent("data/.setup-token") }
    private var runtimeEnvironment: [String: String] {
        [
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "SERVERHUB_PORT": port,
            "SERVERHUB_RUNTIME_DIR": root.path,
            "SERVERHUB_STATE_DIR": stateRoot.path,
        ]
    }

    @discardableResult
    func run(
        _ executable: String,
        _ arguments: [String],
        environment: [String: String] = [:]
    ) -> CommandResult {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, new in new }
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return CommandResult(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
        } catch {
            return CommandResult(status: 127, output: error.localizedDescription)
        }
    }

    private func xmlEscaped(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }

    private func bootstrapState() -> CommandResult {
        let script = """
        import sys
        sys.path.insert(0, \(String(reflecting: root.path)))
        from hub import auth
        from hub.config import cfg
        cfg()
        auth.local_client_token()
        if auth.setup_required():
            auth.setup_token()
        """
        return run(pythonURL.path, ["-I", "-B", "-c", script], environment: runtimeEnvironment)
    }

    func setupToken() -> String? {
        guard let token = try? String(contentsOf: setupTokenURL, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines), !token.isEmpty else { return nil }
        return token
    }

    func waitUntilHealthy(timeout: TimeInterval = 20) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var request = localRequest(path: "api/health")
            request.timeoutInterval = 1
            let completed = DispatchSemaphore(value: 0)
            let healthy = ResultBox<Bool>()
            URLSession.shared.dataTask(with: request) { _, response, _ in
                healthy.value = (response as? HTTPURLResponse)?.statusCode == 200
                completed.signal()
            }.resume()
            if completed.wait(timeout: .now() + 2) == .success, healthy.value == true {
                return true
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        return false
    }

    func ensurePanelDefinition() throws {
        let app = root.appendingPathComponent("app.py")
        guard FileManager.default.isExecutableFile(atPath: pythonURL.path), FileManager.default.fileExists(atPath: app.path) else {
            throw NSError(domain: "ServerHub", code: 1, userInfo: [NSLocalizedDescriptionKey: "ServerHub runtime is incomplete at \(root.path)"])
        }
        try FileManager.default.createDirectory(
            at: stateRoot,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.createDirectory(
            at: stateRoot.appendingPathComponent("data", isDirectory: true),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let initialized = bootstrapState()
        guard initialized.status == 0 else {
            throw NSError(domain: "ServerHub", code: 2, userInfo: [NSLocalizedDescriptionKey: initialized.output])
        }
        try FileManager.default.createDirectory(at: agentsURL, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: logsURL, withIntermediateDirectories: true)
        let environmentXML = runtimeEnvironment.sorted(by: { $0.key < $1.key }).map {
            "<key>\(xmlEscaped($0.key))</key><string>\(xmlEscaped($0.value))</string>"
        }.joined()
        let launchScript = "import runpy, sys; sys.path.insert(0, \(String(reflecting: root.path))); runpy.run_path(\(String(reflecting: app.path)), run_name='__main__')"
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Label</key><string>\(Labels.panel)</string>
          <key>ProgramArguments</key><array><string>\(xmlEscaped(pythonURL.path))</string><string>-I</string><string>-B</string><string>-c</string><string>\(xmlEscaped(launchScript))</string></array>
          <key>WorkingDirectory</key><string>\(xmlEscaped(root.path))</string>
          <key>EnvironmentVariables</key><dict>\(environmentXML)</dict>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><true/>
          <!-- Interactive, not Background: launchd throttles Background jobs on
               both CPU and disk I/O, and this one serves the HTTP panel a user
               is sitting in front of.  Under a loaded machine the throttle
               turned an 8.5s start into well over a minute, which reads as
               "the panel did not come back".  The menu-bar helper below has
               always been Interactive; the service it fronts should not be
               starved harder than its own launcher. -->
          <key>ProcessType</key><string>Interactive</string>
          <key>StandardOutPath</key><string>\(xmlEscaped(logsURL.appendingPathComponent("serverhub.out.log").path))</string>
          <key>StandardErrorPath</key><string>\(xmlEscaped(logsURL.appendingPathComponent("serverhub.err.log").path))</string>
        </dict></plist>
        """
        try plist.write(to: panelPlist, atomically: true, encoding: .utf8)
    }

    func removeLegacyMenuBar() {
        let target = "\(domain)/local.serverhub-menubar"
        _ = run("/bin/launchctl", ["bootout", target])
        _ = run("/bin/launchctl", ["disable", target])
        try? FileManager.default.removeItem(
            at: agentsURL.appendingPathComponent("local.serverhub-menubar.plist")
        )
    }

    /// Labels this host has used for the Python panel, preferred first.
    private var panelLabelCandidates: [String] {
        ["com.elvin.serverhub", Labels.panel, "local.serverhub.panel"]
    }

    func loadedPanelLabel() -> String? {
        for label in panelLabelCandidates {
            if run("/bin/launchctl", ["print", "\(domain)/\(label)"]).status == 0 {
                return label
            }
        }
        return nil
    }

    func isPanelJobLoaded() -> Bool {
        loadedPanelLabel() != nil
    }

    func startPanel() -> CommandResult {
        if let existing = loadedPanelLabel(), existing != Labels.panel {
            // Another lineage already owns :8086. Writing local.serverhub on
            // top of com.elvin.serverhub is what produced EADDRINUSE loops
            // and the settings.auth wipe.
            return CommandResult(status: 0, output: "using existing \(existing)")
        }
        do { try ensurePanelDefinition() } catch { return CommandResult(status: 1, output: error.localizedDescription) }
        _ = run("/bin/launchctl", ["enable", "\(domain)/\(Labels.panel)"])
        if !isPanelJobLoaded() {
            let loaded = run("/bin/launchctl", ["bootstrap", domain, panelPlist.path])
            if loaded.status != 0 && !isPanelJobLoaded() { return loaded }
        }
        return run("/bin/launchctl", ["kickstart", "\(domain)/\(Labels.panel)"])
    }

    func stopPanel() -> CommandResult {
        guard let label = loadedPanelLabel() else {
            return CommandResult(status: 0, output: "")
        }
        let result = run("/bin/launchctl", ["bootout", "\(domain)/\(label)"])
        if result.status == 0 || !isPanelJobLoaded() { return CommandResult(status: 0, output: result.output) }
        return result
    }

    func restartPanel() -> CommandResult {
        if let existing = loadedPanelLabel(), existing != Labels.panel {
            return run("/bin/launchctl", ["kickstart", "-k", "\(domain)/\(existing)"])
        }
        do { try ensurePanelDefinition() } catch { return CommandResult(status: 1, output: error.localizedDescription) }
        if !isPanelJobLoaded() { return startPanel() }
        return run("/bin/launchctl", ["kickstart", "-k", "\(domain)/\(Labels.panel)"])
    }

    func isLoginEnabled() -> Bool {
        FileManager.default.fileExists(atPath: launcherPlist.path)
    }

    func setLoginEnabled(_ enabled: Bool) -> CommandResult {
        if enabled {
            do {
                try FileManager.default.createDirectory(at: agentsURL, withIntermediateDirectories: true)
                try FileManager.default.createDirectory(at: logsURL, withIntermediateDirectories: true)
                let plist = """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0"><dict>
                  <key>Label</key><string>\(Labels.launcher)</string>
                  <key>ProgramArguments</key><array>
                    <string>/usr/bin/open</string><string>-gj</string><string>\(xmlEscaped(appURL.path))</string>
                  </array>
                  <key>RunAtLoad</key><true/>
                  <key>ProcessType</key><string>Interactive</string>
                  <key>LimitLoadToSessionType</key><string>Aqua</string>
                  <key>StandardOutPath</key><string>\(xmlEscaped(logsURL.appendingPathComponent("serverhub-launcher.out.log").path))</string>
                  <key>StandardErrorPath</key><string>\(xmlEscaped(logsURL.appendingPathComponent("serverhub-launcher.err.log").path))</string>
                </dict></plist>
                """
                let target = "\(domain)/\(Labels.launcher)"
                let loaded = run("/bin/launchctl", ["print", target])
                let ownsCurrentProcess = loaded.output.contains("pid = \(getpid())")
                try plist.write(to: launcherPlist, atomically: true, encoding: .utf8)
                if ownsCurrentProcess {
                    return CommandResult(status: 0, output: "updated for next login")
                }
                _ = run("/bin/launchctl", ["bootout", target])
                _ = run("/bin/launchctl", ["enable", target])
                let result = run("/bin/launchctl", ["bootstrap", domain, launcherPlist.path])
                if result.status != 0 && run("/bin/launchctl", ["print", "\(domain)/\(Labels.launcher)"]).status != 0 {
                    return result
                }
                return CommandResult(status: 0, output: "enabled")
            } catch {
                return CommandResult(status: 1, output: error.localizedDescription)
            }
        }
        _ = run("/bin/launchctl", ["bootout", "\(domain)/\(Labels.launcher)"])
        _ = run("/bin/launchctl", ["disable", "\(domain)/\(Labels.launcher)"])
        do {
            try FileManager.default.removeItem(at: launcherPlist)
            return CommandResult(status: 0, output: "disabled")
        } catch CocoaError.fileNoSuchFile {
            return CommandResult(status: 0, output: "disabled")
        } catch {
            return CommandResult(status: 1, output: error.localizedDescription)
        }
    }

    private func localRequest(path: String, method: String = "GET", body: Data? = nil) -> URLRequest {
        var request = URLRequest(url: panelURL.appendingPathComponent(path))
        request.httpMethod = method
        request.httpBody = body
        request.timeoutInterval = method == "GET" ? 6 : 120
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if let token = try? String(contentsOf: localTokenURL, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines), !token.isEmpty {
            request.setValue(token, forHTTPHeaderField: "X-ServerHub-Local-Token")
        }
        return request
    }

    func fetchStatus(_ completion: @escaping (Result<PanelStatus, Error>) -> Void) {
        let request = localRequest(path: "api/status")
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error {
                completion(.failure(error))
                return
            }
            guard let http = response as? HTTPURLResponse, let data else {
                completion(.failure(APIRequestError.invalidResponse))
                return
            }
            guard http.statusCode == 200 else {
                let message = (try? JSONSerialization.jsonObject(with: data) as? [String: Any])
                    .flatMap { $0["message"] as? String } ?? ""
                completion(.failure(APIRequestError.http(http.statusCode, message)))
                return
            }
            do {
                completion(.success(try JSONDecoder().decode(PanelStatus.self, from: data)))
            } catch {
                completion(.failure(error))
            }
        }.resume()
    }

    func serviceAction(target: String, action: String, completion: @escaping (Result<ServiceActionResponse, Error>) -> Void) {
        do {
            let body = try JSONEncoder().encode(ServiceActionRequest(target: target, action: action))
            let request = localRequest(path: "api/action", method: "POST", body: body)
            URLSession.shared.dataTask(with: request) { data, response, error in
                if let error {
                    completion(.failure(error))
                    return
                }
                guard let http = response as? HTTPURLResponse, let data else {
                    completion(.failure(APIRequestError.invalidResponse))
                    return
                }
                let decoded = try? JSONDecoder().decode(ServiceActionResponse.self, from: data)
                guard (200..<300).contains(http.statusCode) else {
                    completion(.failure(APIRequestError.http(http.statusCode, decoded?.message ?? "")))
                    return
                }
                guard let decoded, let ok = decoded.ok else {
                    completion(.failure(APIRequestError.invalidResponse))
                    return
                }
                guard ok else {
                    completion(.failure(APIRequestError.http(http.statusCode, decoded.message ?? "")))
                    return
                }
                completion(.success(decoded))
            }.resume()
        } catch {
            completion(.failure(error))
        }
    }
}

@MainActor
private final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private let manager = ServiceManager()
    private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
    private let menu = NSMenu()
    private let statusRow = NSMenuItem(title: localized("正在启动…", "Starting…"), action: nil, keyEquivalent: "")
    private let loginItem = NSMenuItem(title: localized("登录时启动", "Start at Login"), action: #selector(toggleLogin), keyEquivalent: "")
    private var timer: Timer?
    private var menuSignature = ""
    private var refreshInFlight = false
    private var forceRefreshPending = false
    private var serviceActionsInFlight = Set<String>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        statusItem.button?.image = makeStatusImage(warning: false)
        statusItem.button?.toolTip = "ServerHub"
        // AppKit's automatic menu validation can disable every targeted leaf item
        // while an asynchronous service action is running. We manage the only
        // transient disabled state explicitly so links, logs and Quit stay usable.
        menu.autoenablesItems = false
        menu.delegate = self
        rebuildMenu(status: nil)
        statusItem.menu = menu
        manager.removeLegacyMenuBar()

        let firstLaunch = !UserDefaults.standard.bool(forKey: "ServerHubFirstLaunchCompleted")
        if firstLaunch || manager.isLoginEnabled() {
            let login = manager.setLoginEnabled(true)
            if firstLaunch && login.status == 0 {
                UserDefaults.standard.set(true, forKey: "ServerHubFirstLaunchCompleted")
            }
        }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let started = self.manager.startPanel()
            guard started.status == 0 else {
                DispatchQueue.main.async { self.showLaunchFailure(started) }
                return
            }
            guard self.manager.waitUntilHealthy() else {
                DispatchQueue.main.async {
                    self.showLaunchFailure(CommandResult(
                        status: 1,
                        output: localized(
                            "后台未能在 20 秒内响应。",
                            "The backend did not respond within 20 seconds."
                        )
                    ))
                }
                return
            }
            let setupToken = self.manager.setupToken()
            DispatchQueue.main.async {
                self.finishLaunch(setupToken: setupToken)
            }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshStatus() }
        }
        refreshStatus()
    }

    private func item(_ title: String, action: Selector, key: String = "") -> NSMenuItem {
        let result = NSMenuItem(title: title, action: action, keyEquivalent: key)
        result.target = self
        return result
    }

    private func managedSubmenu() -> NSMenu {
        let result = NSMenu()
        result.autoenablesItems = false
        result.delegate = self
        return result
    }

    private func updateMenuAvailability(_ currentMenu: NSMenu) {
        currentMenu.autoenablesItems = false
        currentMenu.delegate = self
        for menuItem in currentMenu.items {
            if menuItem.isSeparatorItem { continue }
            if menuItem === statusRow {
                menuItem.isEnabled = false
            } else if let payload = menuItem.representedObject as? ServiceActionPayload {
                let actionKey = serviceActionKey(target: payload.target, action: payload.action)
                menuItem.isEnabled = !serviceActionsInFlight.contains(actionKey)
            } else if let submenu = menuItem.submenu {
                updateMenuAvailability(submenu)
                menuItem.isEnabled = !submenu.items.isEmpty
            } else {
                menuItem.isEnabled = menuItem.action != nil
            }
        }
    }

    func menuWillOpen(_ menu: NSMenu) {
        updateMenuAvailability(menu)
    }

    private func rebuildMenu(status: PanelStatus?) {
        menu.removeAllItems()
        statusRow.isEnabled = false
        menu.addItem(statusRow)
        menu.addItem(.separator())
        menu.addItem(item(localized("打开 ServerHub 面板", "Open ServerHub Panel"), action: #selector(openPanel), key: "o"))

        if let status {
            let problems = status.problems ?? []
            if !problems.isEmpty {
                menu.addItem(.separator())
                let attention = NSMenuItem(
                    title: localized("⚠️ 需处理（\(problems.count)）", "⚠️ Needs Attention (\(problems.count))"),
                    action: nil,
                    keyEquivalent: ""
                )
                let submenu = managedSubmenu()
                for service in problems.prefix(12) {
                    submenu.addItem(serviceItem(service))
                }
                attention.submenu = submenu
                menu.addItem(attention)
            }

            if !(status.groups ?? []).isEmpty {
                menu.addItem(.separator())
            }
            for group in status.groups ?? [] {
                let services = group.services ?? []
                guard !services.isEmpty else { continue }
                if services.count == 1 {
                    menu.addItem(serviceItem(services[0]))
                    continue
                }
                let groupItem = NSMenuItem(title: groupTitle(group), action: nil, keyEquivalent: "")
                let submenu = managedSubmenu()
                for service in services {
                    submenu.addItem(serviceItem(service))
                }
                groupItem.submenu = submenu
                menu.addItem(groupItem)
            }

            let links = (status.links ?? []).filter { $0.url != nil }
            if !links.isEmpty {
                menu.addItem(.separator())
                for link in links.prefix(8) {
                    menu.addItem(linkItem("🔗 \(link.name ?? localized("链接", "Link"))", url: link.url))
                }
            }
        }

        menu.addItem(.separator())
        menu.addItem(item(localized("启动 ServerHub", "Start ServerHub"), action: #selector(startPanel)))
        menu.addItem(item(localized("停止 ServerHub", "Stop ServerHub"), action: #selector(stopPanel)))
        menu.addItem(item(localized("重启 ServerHub", "Restart ServerHub"), action: #selector(restartPanel)))
        menu.addItem(.separator())
        loginItem.title = localized("登录时启动", "Start at Login")
        loginItem.target = self
        loginItem.action = #selector(toggleLogin)
        loginItem.state = manager.isLoginEnabled() ? .on : .off
        menu.addItem(loginItem)
        menu.addItem(item(localized("打开日志文件夹", "Open Logs Folder"), action: #selector(openLogs)))
        menu.addItem(.separator())
        menu.addItem(item(localized("退出菜单栏应用", "Quit Menu Bar App"), action: #selector(quitApp), key: "q"))
    }

    private func serviceItem(_ service: PanelService) -> NSMenuItem {
        let result = NSMenuItem(title: serviceTitle(service), action: nil, keyEquivalent: "")
        let submenu = managedSubmenu()

        if let url = service.url {
            submenu.addItem(linkItem(localized("🌐 打开 \(url)", "🌐 Open \(url)"), url: url))
        }
        for link in service.links ?? [] {
            if let url = link.url {
                submenu.addItem(linkItem("🌐 \(link.name ?? localized("打开", "Open"))", url: url))
            }
        }
        for action in visibleActions(service) {
            if action.id == "logs" {
                submenu.addItem(item(action.title, action: #selector(openPanelLogs)))
                continue
            }
            guard let target = service.id else { continue }
            let actionItem = item(action.title, action: #selector(runServiceAction(_:)))
            actionItem.representedObject = ServiceActionPayload(
                target: target,
                action: action.id,
                name: service.name ?? target
            )
            actionItem.isEnabled = !serviceActionsInFlight.contains(
                serviceActionKey(target: target, action: action.id)
            )
            submenu.addItem(actionItem)
        }
        if submenu.items.isEmpty {
            result.isEnabled = false
        } else {
            result.submenu = submenu
        }
        return result
    }

    private func linkItem(_ title: String, url: String?) -> NSMenuItem {
        guard let safeURL = safeWebURL(url) else {
            let result = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            result.isEnabled = false
            return result
        }
        let result = item(title, action: #selector(openRepresentedURL(_:)))
        result.representedObject = safeURL.absoluteString as NSString
        return result
    }

    private func signature(_ status: PanelStatus) -> String {
        var parts = [
            String(status.counts?.ok ?? 0),
            String(status.counts?.warn ?? 0),
            String(status.counts?.down ?? 0),
            String(status.counts?.stopped ?? 0),
            String(status.counts?.unknown ?? 0),
        ]
        for group in status.groups ?? [] {
            parts.append(group.group ?? "")
            for service in group.services ?? [] {
                let links = (service.links ?? []).map {
                    "\($0.name ?? "")=\($0.url ?? "")"
                }.joined(separator: ",")
                parts.append([
                    service.id ?? "",
                    service.name ?? "",
                    service.state ?? "",
                    service.url ?? "",
                    service.port.map(String.init) ?? "",
                    (service.actions ?? []).joined(separator: ","),
                    links,
                ].joined(separator: "|"))
            }
        }
        parts.append(contentsOf: (status.problems ?? []).compactMap(\.id))
        parts.append(contentsOf: (status.links ?? []).map {
            "quick:\($0.name ?? "")=\($0.url ?? "")"
        })
        return parts.joined(separator: "\u{1f}")
    }

    private func summary(_ status: PanelStatus) -> String {
        statusSummary(status)
    }

    private func makeStatusImage(warning: Bool) -> NSImage {
        let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { _ in
            let color = warning ? NSColor.systemOrange : NSColor.labelColor
            color.setFill()
            for (index, width) in [14.0, 14.0, 14.0].enumerated() {
                let y = 13.0 - CGFloat(index) * 5.0
                NSBezierPath(roundedRect: NSRect(x: 2, y: y, width: width, height: 3.2), xRadius: 1.2, yRadius: 1.2).fill()
            }
            return true
        }
        image.isTemplate = !warning
        return image
    }

    private func finishLaunch(setupToken: String?) {
        refreshStatus(forceMenu: true)
        guard let setupToken else {
            NSWorkspace.shared.open(manager.panelURL)
            return
        }

        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(setupToken, forType: .string)

        let tokenField = NSTextField(string: setupToken)
        tokenField.isEditable = false
        tokenField.isSelectable = true
        tokenField.isBordered = true
        tokenField.drawsBackground = true
        tokenField.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        tokenField.frame = NSRect(x: 0, y: 0, width: 430, height: 24)

        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = localized("完成 ServerHub 首次设置", "Finish Setting Up ServerHub")
        alert.informativeText = localized(
            "一次性设置令牌已复制到剪贴板。请在即将打开的本机设置页面中粘贴；完成设置后令牌会自动删除。",
            "The one-time setup token has been copied to the clipboard. Paste it into the local setup page that opens next; the token is deleted after setup."
        )
        alert.alertStyle = .informational
        alert.accessoryView = tokenField
        alert.addButton(withTitle: localized("打开设置", "Open Setup"))
        alert.addButton(withTitle: localized("再次复制", "Copy Again"))
        if alert.runModal() == .alertSecondButtonReturn {
            pasteboard.clearContents()
            pasteboard.setString(setupToken, forType: .string)
        }
        NSWorkspace.shared.open(manager.panelURL.appendingPathComponent("settings"))
    }

    private func showLaunchFailure(_ result: CommandResult) {
        let unavailable = localized("⚠️ ServerHub 启动失败", "⚠️ ServerHub Failed to Start")
        statusRow.title = unavailable
        statusItem.button?.image = makeStatusImage(warning: true)
        statusItem.button?.toolTip = unavailable
        rebuildMenu(status: nil)
        statusRow.title = unavailable

        let detail = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        let reason = detail.isEmpty
            ? localized("后台进程未能启动。", "The backend process could not start.")
            : String(detail.prefix(2_000))
        let alert = NSAlert()
        alert.messageText = localized("无法启动 ServerHub", "Unable to Start ServerHub")
        alert.informativeText = reason + "\n\n" + localized(
            "请查看日志后，从菜单栏选择“启动 ServerHub”重试。",
            "Check the logs, then choose “Start ServerHub” from the menu bar to retry."
        )
        alert.alertStyle = .warning
        alert.addButton(withTitle: localized("打开日志", "Open Logs"))
        alert.addButton(withTitle: localized("关闭", "Close"))
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            NSWorkspace.shared.open(manager.home.appendingPathComponent("Library/Logs"))
        }
    }

    private func notify(_ title: String, message: String, failure: Bool) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = failure ? .warning : .informational
        alert.runModal()
    }

    private func notify(_ title: String, _ result: CommandResult) {
        notify(
            title,
            message: result.status == 0
                ? localized("已完成", "Completed")
                : (result.output.isEmpty ? localized("操作失败", "Operation failed") : result.output),
            failure: result.status != 0
        )
    }

    private func perform(_ title: String, action: @escaping () -> CommandResult) {
        statusRow.title = "\(title)…"
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = action()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                self?.refreshStatus(forceMenu: true)
                if result.status != 0 { self?.notify(title, result) }
            }
        }
    }

    private func refreshStatus(forceMenu: Bool = false) {
        if refreshInFlight {
            if forceMenu { forceRefreshPending = true }
            return
        }
        refreshInFlight = true
        loginItem.state = manager.isLoginEnabled() ? .on : .off
        manager.fetchStatus { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case let .success(status):
                    let counts = status.counts
                    let warning = (counts?.warn ?? 0) > 0 || (counts?.down ?? 0) > 0 || (counts?.unknown ?? 0) > 0
                    self.statusRow.title = self.summary(status)
                    self.statusItem.button?.image = self.makeStatusImage(warning: warning)
                    self.statusItem.button?.toolTip = warning
                        ? localized("ServerHub — 需要处理", "ServerHub — Needs Attention")
                        : localized("ServerHub — 正常", "ServerHub — Healthy")
                    let signature = self.signature(status)
                    if forceMenu || signature != self.menuSignature {
                        self.menuSignature = signature
                        self.rebuildMenu(status: status)
                        self.statusRow.title = self.summary(status)
                    }
                case .failure:
                    let unavailable = localized("⚠️ ServerHub 后台无响应", "⚠️ ServerHub Backend Unavailable")
                    self.menuSignature = ""
                    self.statusRow.title = unavailable
                    self.statusItem.button?.image = self.makeStatusImage(warning: true)
                    self.statusItem.button?.toolTip = localized(
                        "ServerHub — 后台无响应",
                        "ServerHub — Backend Unavailable"
                    )
                    self.rebuildMenu(status: nil)
                    self.statusRow.title = unavailable
                }
                let rerunForced = self.forceRefreshPending
                self.forceRefreshPending = false
                self.refreshInFlight = false
                if rerunForced {
                    self.refreshStatus(forceMenu: true)
                }
            }
        }
    }

    private func confirmAction(_ title: String, message: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .warning
        alert.addButton(withTitle: localized("继续", "Continue"))
        alert.addButton(withTitle: localized("取消", "Cancel"))
        return alert.runModal() == .alertFirstButtonReturn
    }

    @objc private func openRepresentedURL(_ sender: NSMenuItem) {
        guard let raw = sender.representedObject as? String,
              let url = safeWebURL(raw) else { return }
        NSWorkspace.shared.open(url)
    }

    @objc private func openPanelLogs() {
        NSWorkspace.shared.open(manager.panelURL.appendingPathComponent("logs"))
    }

    private func serviceActionKey(target: String, action: String) -> String {
        "\(target)\u{1f}\(action)"
    }

    @objc private func runServiceAction(_ sender: NSMenuItem) {
        guard let payload = sender.representedObject as? ServiceActionPayload else { return }
        let actionKey = serviceActionKey(target: payload.target, action: payload.action)
        guard !serviceActionsInFlight.contains(actionKey) else { return }
        if let message = serviceConfirmation(action: payload.action, name: payload.name),
           !confirmAction(localized("确认操作", "Confirm Action"), message: message) {
            return
        }
        serviceActionsInFlight.insert(actionKey)
        sender.isEnabled = false
        statusRow.title = localized(
            "正在\(sender.title.replacingOccurrences(of: " ", with: "")) \(payload.name)…",
            "Running \(sender.title.replacingOccurrences(of: " ", with: "")) for \(payload.name)…"
        )
        manager.serviceAction(target: payload.target, action: payload.action) { [weak self] result in
            DispatchQueue.main.async {
                guard let self else { return }
                self.serviceActionsInFlight.remove(actionKey)
                switch result {
                case let .success(response):
                    if response.ok == false {
                        self.notify(
                            payload.name,
                            message: response.message ?? localized("操作失败", "Operation failed"),
                            failure: true
                        )
                    }
                case let .failure(error):
                    self.notify(payload.name, message: error.localizedDescription, failure: true)
                }
                self.refreshStatus(forceMenu: true)
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
                    self?.refreshStatus(forceMenu: true)
                }
            }
        }
    }

    @objc private func openPanel() { NSWorkspace.shared.open(manager.panelURL) }
    @objc private func startPanel() {
        perform(localized("正在启动 ServerHub", "Starting ServerHub")) { self.manager.startPanel() }
    }
    @objc private func stopPanel() {
        guard confirmAction(
            localized("停止 ServerHub？", "Stop ServerHub?"),
            message: localized(
                "管理面板和菜单栏服务数据将暂时不可用。",
                "The admin panel and menu bar service data will be temporarily unavailable."
            )
        ) else { return }
        perform(localized("正在停止 ServerHub", "Stopping ServerHub")) { self.manager.stopPanel() }
    }
    @objc private func restartPanel() {
        guard confirmAction(
            localized("重启 ServerHub？", "Restart ServerHub?"),
            message: localized("管理面板会短暂中断。", "The admin panel will be briefly unavailable.")
        ) else { return }
        perform(localized("正在重启 ServerHub", "Restarting ServerHub")) { self.manager.restartPanel() }
    }
    @objc private func toggleLogin() {
        let enabled = !manager.isLoginEnabled()
        perform(
            enabled
                ? localized("正在启用登录自启", "Enabling Start at Login")
                : localized("正在关闭登录自启", "Disabling Start at Login")
        ) {
            self.manager.setLoginEnabled(enabled)
        }
    }
    @objc private func openLogs() { NSWorkspace.shared.open(manager.home.appendingPathComponent("Library/Logs")) }
    @objc private func quitApp() { NSApp.terminate(nil) }
}

private func serviceConfirmation(action: String, name: String) -> String? {
    switch action {
    case "stop":
        return localized(
            "停止 \(name)？服务将不可用，直到再次启动。",
            "Stop \(name)? The service will be unavailable until it is started again."
        )
    case "restart":
        return localized(
            "重启 \(name)？服务会短暂中断。",
            "Restart \(name)? The service will be briefly unavailable."
        )
    case "pause":
        return localized(
            "暂停 \(name)？服务在继续前将不可用。",
            "Pause \(name)? The service will be unavailable until it is resumed."
        )
    case "suspend":
        return localized(
            "挂起 \(name)？虚拟机会暂停运行。",
            "Suspend \(name)? The virtual machine will pause."
        )
    default:
        return nil
    }
}

private func dumpLocalizationSnapshot() {
    let status = PanelStatus(
        counts: ServiceCounts(ok: 2, warn: 1, down: 1, stopped: 1, unknown: 0),
        groups: nil,
        problems: nil,
        links: nil
    )
    let group = ServiceGroup(
        group: localized("样例服务", "Sample Services"),
        services: [
            PanelService(
                id: "sample",
                name: localized("样例", "Sample"),
                state: "stopped",
                url: nil,
                port: nil,
                actions: ["start", "restart", "stop", "logs"],
                links: nil,
                detail: nil
            ),
        ]
    )
    print("LANG\t\(L10n.language.rawValue)")
    print("SUMMARY\t\(statusSummary(status))")
    print("GROUP\t\(groupTitle(group))")
    for action in visibleActions(group.services?[0] ?? PanelService(
        id: nil, name: nil, state: nil, url: nil, port: nil, actions: nil, links: nil, detail: nil
    )) {
        print("ACTION\t\(action.id)\t\(action.title)")
    }
    print("MENU\t\(localized("打开 ServerHub 面板", "Open ServerHub Panel"))")
    print("CONFIRM\t\(serviceConfirmation(action: "restart", name: "Sample") ?? "")")
}

@main
private struct ServerHubLauncher {
    @MainActor static func main() {
        let arguments = CommandLine.arguments.dropFirst()
        if arguments.contains("--dump-localization") {
            dumpLocalizationSnapshot()
            return
        }
        if arguments.contains("--dump-menu") {
            exit(dumpMenuSnapshot())
        }
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
