// SOD fixtures for passive authentication trust-chain tests.
//
// Generated once with the OpenSSL 4.0 command line (P-256 keys, 100-year validity):
//   CSCA   self-signed CA "C=UT, CN=Test CSCA"
//   DSC    "C=UT, CN=Test DSC", issued by the CSCA
//   Rogue  self-signed "C=UT, CN=Rogue Signer"
//   LDS security object: version 0, SHA-256, one hash for `dg1` below.
//   genuine: `openssl cms -sign -signer dsc.pem -econtent_type 2.23.136.1.1.1 -nodetach -md sha256`
//   forged:  same content signed by Rogue, with `-certfile dsc.pem`, so the certificates
//            SET holds [DSC, Rogue] with the genuine DSC first (RFC 5652 §5.1, ICAO 9303-10 §4.6.2).
import Foundation

enum SODFixtures {
    private static func decode(_ lines: [String]) -> Data {
        Data(base64Encoded: lines.joined())!
    }

    static let cscaDER = decode(
        [
            "MIIBiDCCAS6gAwIBAgIUHDjJ+oXE864rILDVOw3UbRBLO3cwCgYIKoZIzj0EAwIwITELMAkGA1UEBhMCVVQxEjAQBgNVBAMM",
            "CVRlc3QgQ1NDQTAgFw0yNjEwMTYwNTU4MTFaGA8yMTI2MDkyMjA1NTgxMVowITELMAkGA1UEBhMCVVQxEjAQBgNVBAMMCVRl",
            "c3QgQ1NDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMfHXCa6Oi5GoyFtSpoeYJbRnu8gpf5a6PZteSS1AGnBco2YaZiJ",
            "DfD29PENUk3d3hdgJw9fhm6IahgfU/Oqw6qjQjBAMB0GA1UdDgQWBBQK9pgz/V1hH9VSKOo2zQv2ZDlURDAPBgNVHRMBAf8E",
            "BTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiAGXVBlr2l3pjaNrQUKg0Mzs9pNDgZ4BcEyecYkeE94",
            "ogIhAOdThom/mKI9frfCgRyitwltr3OQMjnrzGwaVWF+qo68",
        ]
    )

    static let dscDER = decode(
        [
            "MIIBVjCB/aADAgECAhRnJWuhKLzpZI34DUA6QOq81TVHLjAKBggqhkjOPQQDAjAhMQswCQYDVQQGEwJVVDESMBAGA1UEAwwJ",
            "VGVzdCBDU0NBMCAXDTI2MTAxNjA1NTgxMVoYDzIxMjYwOTIyMDU1ODExWjAgMQswCQYDVQQGEwJVVDERMA8GA1UEAwwIVGVz",
            "dCBEU0MwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARo2GkfzptAiX4gGwIyYI/BvUnZDGjFyyFQI7hv6pb+V1my5MBQSAxy",
            "vX7//kByimH89bCBKvA0J53KNEtVC0yIoxIwEDAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSAAwRQIhAJU7Nds+w5VA",
            "Adxq8OM/LEQcchuiCxZTwdP3JqBdJ3xqAiAlS++V9vh9fJPDEpDZw+LHZC/7PrI0verapL/dYvRhFA==",
        ]
    )

    static let rogueDER = decode(
        [
            "MIIBjTCCATSgAwIBAgIULqeQpHMjkjtUN/eNOTsTRl9U7xcwCgYIKoZIzj0EAwIwJDELMAkGA1UEBhMCVVQxFTATBgNVBAMM",
            "DFJvZ3VlIFNpZ25lcjAgFw0yNjEwMTYwNTU4MTFaGA8yMTI2MDkyMjA1NTgxMVowJDELMAkGA1UEBhMCVVQxFTATBgNVBAMM",
            "DFJvZ3VlIFNpZ25lcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKwVbq1dMO6Zjq16/DisS76sRG5OLon6ggFo1lPcM5nw",
            "UjwOWXth3RohiCKIV4koGWs68QhRrM8DPr/c9ifem1GjQjBAMB0GA1UdDgQWBBR8HUwjMA5s0myxmxZmriUah5KWxzAPBgNV",
            "HRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAgNHADBEAiBFXc91vaWFGkI3SBj1qFYYd7aZKepjxCT7",
            "UVnBPhU9wwIgD0TiT2ag5ziGBjrySKfmIVtoLimYAds1z/UOe9hfpuE=",
        ]
    )

    static let dg1 = decode(
        [
            "YVtfH1hQPFVUT0VSSUtTU09OPDxBTk5BPE1BUklBPDw8PDw8PDw8PDw8PDw8PDw8PEw4OTg5MDJDMzZVVE83NDA4MTIyRjEy",
            "MDQxNTlaRTE4NDIyNkI8PDw8PDEw",
        ]
    )

    static let genuineSOD = decode(
        [
            "MIIDWQYJKoZIhvcNAQcCoIIDSjCCA0YCAQMxDTALBglghkgBZQMEAgEwRwYGZ4EIAQEBoD0EOzA5AgEAMAsGCWCGSAFlAwQC",
            "ATAnMCUCAQEEIEMrwH0cY3eT9Nd+C3VoZfeuw3VvmNbsbrdn7aNxkEZRoIIBWjCCAVYwgf2gAwIBAgIUZyVroSi86WSN+A1A",
            "OkDqvNU1Ry4wCgYIKoZIzj0EAwIwITELMAkGA1UEBhMCVVQxEjAQBgNVBAMMCVRlc3QgQ1NDQTAgFw0yNjEwMTYwNTU4MTFa",
            "GA8yMTI2MDkyMjA1NTgxMVowIDELMAkGA1UEBhMCVVQxETAPBgNVBAMMCFRlc3QgRFNDMFkwEwYHKoZIzj0CAQYIKoZIzj0D",
            "AQcDQgAEaNhpH86bQIl+IBsCMmCPwb1J2QxoxcshUCO4b+qW/ldZsuTAUEgMcr1+//5Acoph/PWwgSrwNCedyjRLVQtMiKMS",
            "MBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIQCVOzXbPsOVQAHcavDjPyxEHHIbogsWU8HT9yagXSd8agIg",
            "JUvvlfb4fXyTwxKQ2cPix2Qv+z6yNL3q2qS/3WL0YRQxggGJMIIBhQIBATA5MCExCzAJBgNVBAYTAlVUMRIwEAYDVQQDDAlU",
            "ZXN0IENTQ0ECFGcla6EovOlkjfgNQDpA6rzVNUcuMAsGCWCGSAFlAwQCAaCB4TAVBgkqhkiG9w0BCQMxCAYGZ4EIAQEBMBwG",
            "CSqGSIb3DQEJBTEPFw0yNjEwMTYwNTU4MTFaMC8GCSqGSIb3DQEJBDEiBCCYpfttzf+L7PaCXi8h5aD+poWYNH+Iwbx7ojy4",
            "kTdJzzB5BgkqhkiG9w0BCQ8xbDBqMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJYIZIAWUDBAECMAoGCCqGSIb3DQMH",
            "MA4GCCqGSIb3DQMCAgIAgDANBggqhkiG9w0DAgIBQDAHBgUrDgMCBzANBggqhkiG9w0DAgIBKDAKBggqhkjOPQQDAgRIMEYC",
            "IQDfDh3BVG5jI6HmJHXxViGQ5TILx/dxkzO8HFJCnpwpxAIhALI6pN9SDkoY0NLnSaXhQHb3+tUyIeyexvWn6PsCFX99",
        ]
    )

    static let forgedSOD = decode(
        [
            "MIIE7AYJKoZIhvcNAQcCoIIE3TCCBNkCAQMxDTALBglghkgBZQMEAgEwRwYGZ4EIAQEBoD0EOzA5AgEAMAsGCWCGSAFlAwQC",
            "ATAnMCUCAQEEIEMrwH0cY3eT9Nd+C3VoZfeuw3VvmNbsbrdn7aNxkEZRoIIC6zCCAVYwgf2gAwIBAgIUZyVroSi86WSN+A1A",
            "OkDqvNU1Ry4wCgYIKoZIzj0EAwIwITELMAkGA1UEBhMCVVQxEjAQBgNVBAMMCVRlc3QgQ1NDQTAgFw0yNjEwMTYwNTU4MTFa",
            "GA8yMTI2MDkyMjA1NTgxMVowIDELMAkGA1UEBhMCVVQxETAPBgNVBAMMCFRlc3QgRFNDMFkwEwYHKoZIzj0CAQYIKoZIzj0D",
            "AQcDQgAEaNhpH86bQIl+IBsCMmCPwb1J2QxoxcshUCO4b+qW/ldZsuTAUEgMcr1+//5Acoph/PWwgSrwNCedyjRLVQtMiKMS",
            "MBAwDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMCA0gAMEUCIQCVOzXbPsOVQAHcavDjPyxEHHIbogsWU8HT9yagXSd8agIg",
            "JUvvlfb4fXyTwxKQ2cPix2Qv+z6yNL3q2qS/3WL0YRQwggGNMIIBNKADAgECAhQup5CkcyOSO1Q39405OxNGX1TvFzAKBggq",
            "hkjOPQQDAjAkMQswCQYDVQQGEwJVVDEVMBMGA1UEAwwMUm9ndWUgU2lnbmVyMCAXDTI2MTAxNjA1NTgxMVoYDzIxMjYwOTIy",
            "MDU1ODExWjAkMQswCQYDVQQGEwJVVDEVMBMGA1UEAwwMUm9ndWUgU2lnbmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE",
            "rBVurV0w7pmOrXr8OKxLvqxEbk4uifqCAWjWU9wzmfBSPA5Ze2HdGiGIIohXiSgZazrxCFGszwM+v9z2J96bUaNCMEAwHQYD",
            "VR0OBBYEFHwdTCMwDmzSbLGbFmauJRqHkpbHMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgeAMAoGCCqGSM49BAMC",
            "A0cAMEQCIEVdz3W9pYUaQjdIGPWoVhh3tpkp6mPEJPtRWcE+FT3DAiAPROJPZqDnOIYGOvJIp+YhW2guKZgB2zXP9Q572F+m",
            "4TGCAYswggGHAgEBMDwwJDELMAkGA1UEBhMCVVQxFTATBgNVBAMMDFJvZ3VlIFNpZ25lcgIULqeQpHMjkjtUN/eNOTsTRl9U",
            "7xcwCwYJYIZIAWUDBAIBoIHhMBUGCSqGSIb3DQEJAzEIBgZngQgBAQEwHAYJKoZIhvcNAQkFMQ8XDTI2MTAxNjA1NTgxMVow",
            "LwYJKoZIhvcNAQkEMSIEIJil+23N/4vs9oJeLyHloP6mhZg0f4jBvHuiPLiRN0nPMHkGCSqGSIb3DQEJDzFsMGowCwYJYIZI",
            "AWUDBAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwDgYIKoZIhvcNAwICAgCAMA0GCCqGSIb3DQMC",
            "AgFAMAcGBSsOAwIHMA0GCCqGSIb3DQMCAgEoMAoGCCqGSM49BAMCBEcwRQIgAa3cQrjWdauiVr10DWddKD+9Uf67JHmYzp27",
            "KZWDftQCIQCIv2HQsxZnr5tHJCygMDekdqg8TTVtQcQZH6bzRYHvag==",
        ]
    )
}
