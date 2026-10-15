// swift-tools-version: 6.2

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
        .package(url: "https://github.com/Lakr233/openssl-spm.git", from: "3.6.1"),
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
