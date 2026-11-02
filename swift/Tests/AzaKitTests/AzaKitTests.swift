// The Swift API end to end: a real aza node, the aza app's device, and Heavier as a client.
import Foundation
import Testing
@testable import AzaKit

/// Starts `aza-node` (built by `cargo build --release -p aza-node`) on a free port.
func startNode() async throws -> (url: String, process: Process) {
    let root = URL(filePath: #filePath).deletingLastPathComponent().appending(path: "../../..").standardized
    let port = Int.random(in: 20000..<40000)
    let url = "http://127.0.0.1:\(port)"
    let p = Process()
    p.executableURL = root.appending(path: "target/release/aza-node")
    p.arguments = ["--url", url, "--listen", "127.0.0.1:\(port)", "--db", NSTemporaryDirectory() + "aza-\(port).db"]
    p.standardError = FileHandle.nullDevice
    try p.run()
    for _ in 0..<50 {
        if (try? await URLSession.shared.data(from: URL(string: "\(url)/aza/v1/pairing/x")!)) != nil { break }
        try await Task.sleep(for: .milliseconds(100))
    }
    return (url, p)
}

@Test func heavierSignsInSyncsAndSurvivesARestart() async throws {
    let (node, process) = try await startNode()
    defer { process.terminate() }

    // The aza app creates an identity and names it.
    let phone = try await AzaDevice.create(node: node, label: "iPhone")
    try await phone.setName(name: "aiden")
    let picture = Data("not really a png".utf8)
    try await phone.setPicture(image: picture, imageType: "image/png")
    #expect(try await phone.picture() == picture)

    // Heavier asks for sign-in, read and write; the aza app shows what it asks and approves.
    let heavier = try AzaClient(app: "heavier.aza.network", scopes: ["sign-in", "read", "write"],
                                returnUrl: "https://heavier.aza.network/aza")
    let request = try #require(heavier.approveUrl())
    #expect(request.hasPrefix("aza:approve#req="))
    let asked = try phone.describeRequest(url: request)
    #expect(asked.app == "heavier.aza.network")
    #expect(asked.scopes == ["sign-in", "read", "write"])
    let returned = try await phone.approveUrl(url: request)
    #expect(returned.hasPrefix("https://heavier.aza.network/aza#aza="))
    try await heavier.receive(url: returned)
    #expect(await heavier.identity() == (await phone.identity()))
    #expect(try await heavier.profile().name == "aiden")

    // Sync: write, conflict on a stale version, read back.
    try await heavier.write(name: "workouts/2026-11-02", version: 1, data: Data("bench 3x5".utf8))
    await #expect(throws: AzaError.self) {
        try await heavier.write(name: "workouts/2026-11-02", version: 1, data: Data("rows".utf8))
    }
    let items = try await heavier.readAll()
    #expect(items.map(\.name) == ["workouts/2026-11-02"])
    #expect(String(decoding: items[0].data, as: UTF8.self) == "bench 3x5")

    // Restart: both come back from their saved bytes (the Keychain, in the apps).
    let heavierAgain = try AzaClient.load(saved: await heavier.save())
    let phoneAgain = try AzaDevice.load(saved: await phone.save())
    #expect(heavierAgain.approveUrl() == nil)
    try await heavierAgain.write(name: "workouts/2026-11-02", version: 2, data: Data("bench 3x5, rows 3x8".utf8))
    #expect(try await phoneAgain.approvals().map(\.app) == ["heavier.aza.network"])

    // Signing in to an app's server: a proof over its challenge.
    let signIn = try await heavierAgain.signIn(challenge: Data(repeating: 7, count: 32))
    #expect(!signIn.certificate.isEmpty && !signIn.proof.isEmpty)
}
