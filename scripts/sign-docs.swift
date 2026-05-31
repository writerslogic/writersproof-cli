#!/usr/bin/env swift
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
//
// sign-docs.swift
//
// Generates a C2PA-compliant content provenance manifest covering all
// documentation assets: man pages, CDDL/JSON schemas, user docs, and
// spec files. Produces a signed manifest at docs/manifest.c2pa.json.
//
// Usage: swift scripts/sign-docs.swift

import Foundation
import CryptoKit

let docsDir = "docs"
let outputPath = "\(docsDir)/manifest.c2pa.json"

struct FileAssertion: Codable {
    let path: String
    let algorithm: String
    let hash: String
    let size: Int
}

func hashFile(at path: String) throws -> (hash: String, size: Int) {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    let digest = SHA256.hash(data: data)
    let hex = digest.map { String(format: "%02x", $0) }.joined()
    return (hex, data.count)
}

func collectFiles(in directory: String) throws -> [String] {
    let fm = FileManager.default
    guard let enumerator = fm.enumerator(atPath: directory) else {
        throw NSError(domain: "sign-docs", code: 1, userInfo: [NSLocalizedDescriptionKey: "Cannot enumerate \(directory)"])
    }
    let allowedExtensions: Set<String> = [
        "1", "5", "7", "8",        // man pages
        "cddl", "json",            // schemas
        "md",                       // documentation
    ]
    var files: [String] = []
    while let path = enumerator.nextObject() as? String {
        let fullPath = "\(directory)/\(path)"
        var isDir: ObjCBool = false
        if fm.fileExists(atPath: fullPath, isDirectory: &isDir), !isDir.boolValue {
            if path.hasSuffix("manifest.c2pa.json") || path.hasSuffix(".DS_Store") { continue }
            let ext = (path as NSString).pathExtension
            if allowedExtensions.contains(ext) {
                files.append(path)
            }
        }
    }
    return files.sorted()
}

struct C2PAManifest: Codable {
    let manifestVersion: String
    let claimGenerator: String
    let claimGeneratorVersion: String
    let instanceId: String
    let format: String
    let title: String
    let assertions: [C2PAAssertion]
    let signatureInfo: SignatureInfo
    let signature: String
    let publicKey: String

    enum CodingKeys: String, CodingKey {
        case manifestVersion = "c2pa.manifest.version"
        case claimGenerator = "claim_generator"
        case claimGeneratorVersion = "claim_generator_version"
        case instanceId = "instance_id"
        case format, title, assertions
        case signatureInfo = "signature_info"
        case signature
        case publicKey = "public_key"
    }
}

struct C2PAAssertion: Codable {
    let label: String
    let data: C2PAAssertionData
}

struct C2PAAssertionData: Codable {
    let exclusions: [String]?
    let hashMethod: String?
    let files: [FileAssertion]?
    let name: String?
    let value: String?

    enum CodingKeys: String, CodingKey {
        case exclusions, hashMethod = "hash_method", files, name, value
    }
}

struct SignatureInfo: Codable {
    let algorithm: String
    let issuer: String
    let time: String
}

do {
    print("Scanning documentation: \(docsDir)")
    let files = try collectFiles(in: docsDir)
    print("Found \(files.count) files to hash")

    var assertions: [FileAssertion] = []
    for relPath in files {
        let fullPath = "\(docsDir)/\(relPath)"
        let (hash, size) = try hashFile(at: fullPath)
        assertions.append(FileAssertion(path: relPath, algorithm: "SHA-256", hash: hash, size: size))
        print("  \(relPath) (\(size) bytes)")
    }

    let signingKey = Curve25519.Signing.PrivateKey()
    let publicKeyData = signingKey.publicKey.rawRepresentation
    let publicKeyHex = publicKeyData.map { String(format: "%02x", $0) }.joined()

    let claimData = C2PAAssertionData(
        exclusions: ["manifest.c2pa.json", ".DS_Store"],
        hashMethod: "SHA-256",
        files: assertions,
        name: nil,
        value: nil
    )

    let creativeWork = C2PAAssertionData(
        exclusions: nil,
        hashMethod: nil,
        files: nil,
        name: "WritersProof Documentation Suite",
        value: "com.writerslogic.writersproof.docs"
    )

    let now = ISO8601DateFormatter().string(from: Date())

    let c2paAssertions = [
        C2PAAssertion(label: "c2pa.hash.data", data: claimData),
        C2PAAssertion(label: "stds.schema-org.CreativeWork", data: creativeWork),
    ]

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let payloadData = try encoder.encode(c2paAssertions)
    let payloadHash = Data(SHA256.hash(data: payloadData))

    let signatureData = try signingKey.signature(for: payloadHash)
    let signatureHex = signatureData.map { String(format: "%02x", $0) }.joined()

    let manifest = C2PAManifest(
        manifestVersion: "2.0",
        claimGenerator: "WritersProof/sign-docs",
        claimGeneratorVersion: "1.0.0",
        instanceId: UUID().uuidString.lowercased(),
        format: "application/x-documentation-bundle",
        title: "WritersProof Documentation Suite",
        assertions: c2paAssertions,
        signatureInfo: SignatureInfo(
            algorithm: "Ed25519",
            issuer: "WritersLogic, Inc.",
            time: now
        ),
        signature: signatureHex,
        publicKey: publicKeyHex
    )

    let outputEncoder = JSONEncoder()
    outputEncoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let manifestData = try outputEncoder.encode(manifest)
    try manifestData.write(to: URL(fileURLWithPath: outputPath))

    print("Manifest written to: \(outputPath)")
    print("Files signed: \(assertions.count)")
    print("Timestamp: \(now)")
} catch {
    fputs("Error: \(error.localizedDescription)\n", stderr)
    exit(1)
}
