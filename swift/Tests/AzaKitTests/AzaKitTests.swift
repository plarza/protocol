// The Swift API end to end: a real aza node, the aza app's device, and Coach as a client.
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

@Test func coachSignsInSyncsAndSurvivesARestart() async throws {
    let (node, process) = try await startNode()
    defer { process.terminate() }

    // The aza app creates an identity and names it.
    let phone = try await AzaDevice.create(node: node, label: "iPhone")
    try await phone.setName(name: "aiden")
    let picture = Data("not really a png".utf8)
    try await phone.setPicture(image: picture, imageType: "image/png")
    #expect(try await phone.picture() == picture)

    // Coach asks for sign-in, read and write; the aza app shows what it asks and approves.
    let coach = try AzaClient(app: "coach.aza.network", scopes: ["sign-in", "read", "write"],
                                returnUrl: "https://coach.aza.network/aza")
    let request = try #require(coach.approveUrl())
    #expect(request.hasPrefix("aza:approve#req="))
    let asked = try phone.describeRequest(url: request)
    #expect(asked.app == "coach.aza.network")
    #expect(asked.scopes == ["sign-in", "read", "write"])
    let returned = try await phone.approveUrl(url: request)
    #expect(returned.hasPrefix("https://coach.aza.network/aza#aza="))
    try await coach.receive(url: returned)
    #expect(await coach.identity() == (await phone.identity()))
    #expect(try await coach.profile().name == "aiden")

    // Sync: write, conflict on a stale version, read back.
    try await coach.write(name: "workouts/2026-11-02", version: 1, data: Data("bench 3x5".utf8))
    await #expect(throws: AzaError.self) {
        try await coach.write(name: "workouts/2026-11-02", version: 1, data: Data("rows".utf8))
    }
    let items = try await coach.readAll()
    #expect(items.map(\.name) == ["workouts/2026-11-02"])
    #expect(String(decoding: items[0].data, as: UTF8.self) == "bench 3x5")

    // Restart: both come back from their saved bytes (the Keychain, in the apps).
    let coachAgain = try AzaClient.load(saved: await coach.save())
    let phoneAgain = try AzaDevice.load(saved: await phone.save())
    #expect(coachAgain.approveUrl() == nil)
    try await coachAgain.write(name: "workouts/2026-11-02", version: 2, data: Data("bench 3x5, rows 3x8".utf8))
    #expect(try await phoneAgain.approvals().map(\.app) == ["coach.aza.network"])

    // Signing in to an app's server: a proof over its challenge.
    let signIn = try await coachAgain.signIn(challenge: Data(repeating: 7, count: 32))
    #expect(!signIn.certificate.isEmpty && !signIn.proof.isEmpty)
}
