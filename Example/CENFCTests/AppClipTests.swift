@testable import CENFC
import Foundation
import Testing

struct AppClipTests {
    @Test
    func `The default link keeps the app's own parameters and drops p`() throws {
        let url = try #require(URL(string: "https://appclip.apple.com/id?p=wiki.qaq.nfc.app.Clip&source=poster&source=again&flag"))
        let invocation = try #require(ClipInvocation(url))

        #expect(invocation.parameters == ["source": "poster", "flag": ""])
    }

    @Test
    func `The bare default link has no parameters`() throws {
        let url = try #require(URL(string: "https://appclip.apple.com/id?p=wiki.qaq.nfc.app.Clip"))

        #expect(try #require(ClipInvocation(url)).parameters.isEmpty)
    }

    @Test
    func `Only web links are invocations`() throws {
        #expect(ClipInvocation(URL(fileURLWithPath: "/tmp/card.cenfc")) == nil)
        #expect(try ClipInvocation(#require(URL(string: "https://example.com/id?p=wiki.qaq.nfc.app.Clip"))) == nil)

        let other = NSUserActivity(activityType: "wiki.qaq.nfc.app.other")
        other.webpageURL = URL(string: "https://appclip.apple.com/id?p=wiki.qaq.nfc.app.Clip")
        #expect(ClipInvocation(userActivity: other) == nil)

        let web = NSUserActivity(activityType: NSUserActivityTypeBrowsingWeb)
        web.webpageURL = URL(string: "https://appclip.apple.com/id?p=wiki.qaq.nfc.app.Clip&a=1")
        #expect(ClipInvocation(userActivity: web)?.parameters == ["a": "1"])
    }

    /// App Store Connect rejects an App Clip whose version or build differs from
    /// its app's, and the App Clip scans with its own copy of the NFC identifiers.
    @Test
    func `The embedded App Clip matches the app's version and NFC identifiers`() throws {
        let clip = try #require(Bundle(url: Bundle.main.bundleURL.appendingPathComponent("AppClips/CENFCClip.app")))

        for key in [
            "CFBundleShortVersionString",
            "CFBundleVersion",
        ] {
            let appValue = try #require(Bundle.main.object(forInfoDictionaryKey: key) as? String)
            #expect(clip.object(forInfoDictionaryKey: key) as? String == appValue, "\(key)")
        }
        for key in [
            "com.apple.developer.nfc.readersession.felica.systemcodes",
            "com.apple.developer.nfc.readersession.iso7816.select-identifiers",
        ] {
            let appValue = try #require(Bundle.main.object(forInfoDictionaryKey: key) as? [String])
            #expect(clip.object(forInfoDictionaryKey: key) as? [String] == appValue, "\(key)")
        }
    }
}
