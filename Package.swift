// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PhishGuard",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "PhishGuardCore",
            targets: ["PhishGuardCore"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/scinfu/SwiftSoup.git", from: "2.7.0"),
        .package(url: "https://github.com/stephencelis/SQLite.swift.git", from: "0.15.0"),
    ],
    targets: [
        .target(
            name: "PhishGuardCore",
            dependencies: [
                "SwiftSoup",
                .product(name: "SQLite", package: "SQLite.swift"),
            ],
            path: "Sources/PhishGuardCore"
        ),
        .testTarget(
            name: "PhishGuardCoreTests",
            dependencies: ["PhishGuardCore"],
            path: "Tests/PhishGuardCoreTests"
        ),
    ]
)
