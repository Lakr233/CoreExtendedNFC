import Foundation

/// The link that opened the App Clip, or the full app in its place.
///
/// The App Clip is opened by Apple's default link,
/// `https://appclip.apple.com/id?p=wiki.qaq.nfc.app.Clip`, optionally followed
/// by `&key=value` parameters. Once the full app is installed it replaces the
/// App Clip and receives the same link, so both targets parse it with this type.
///
/// Neither target acts on a parameter today: the link only opens the scan
/// screen. Parameters are kept so one can be given a meaning later; unknown
/// ones are ignored by whoever reads ``parameters``.
nonisolated struct ClipInvocation: Equatable, Sendable {
    /// The link's query parameters without `p`, which only names the App Clip.
    /// The first value wins when a name is repeated.
    let parameters: [String: String]

    /// `nil` when `url` is not Apple's App Clip link.
    init?(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let scheme = components.scheme?.lowercased(),
              scheme == "https" || scheme == "http",
              components.host?.lowercased() == "appclip.apple.com"
        else { return nil }
        let items = (components.queryItems ?? []).filter { $0.name != "p" }
        parameters = Dictionary(
            items.map { ($0.name, $0.value ?? "") },
            uniquingKeysWith: { first, _ in first }
        )
    }

    /// `nil` unless `userActivity` is a web link handed over by the system.
    init?(userActivity: NSUserActivity) {
        guard userActivity.activityType == NSUserActivityTypeBrowsingWeb,
              let url = userActivity.webpageURL
        else { return nil }
        self.init(url)
    }
}
