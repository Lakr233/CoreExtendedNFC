// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build the package.

import PackageDescription

let package = Package(
    name: "CoreExtendedNFC",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v15),
    ],
    products: [
        .library(
            name: "CoreExtendedNFC",
            targets: ["CoreExtendedNFC"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/Lakr233/openssl-spm.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "CoreExtendedNFC",
            dependencies: [
                .product(name: "OpenSSL", package: "openssl-spm"),
            ],
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "CoreExtendedNFCTests",
            dependencies: [
                "CoreExtendedNFC",
                .product(name: "OpenSSL", package: "openssl-spm"),
            ]
        ),
    ]
)
