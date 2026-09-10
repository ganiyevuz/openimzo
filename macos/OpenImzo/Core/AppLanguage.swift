import Foundation

/// The app's own chrome language — the menu bar, the window, Settings, and the five request
/// panels. Deliberately a different type from the core's own `Settings.lang`
/// (`eimzo_rpc::i18n::Lang`, `Ru`/`Uz` only): this one has three cases, because the person using
/// the app and the websites it talks to are not the same audience — see
/// `CoreEngine.setAppLanguage(_:)`, which keeps the two from ever disagreeing about what "Uzbek"
/// or "Russian" means, without ever handing the core a language it doesn't have.
enum AppLanguage: String, CaseIterable, Identifiable {
    case ru, uz, en

    var id: String { rawValue }

    /// Each language's own name for itself, in its own script — never re-expressed in whatever
    /// language is currently selected, the way a language picker never translates "Русский" to
    /// "Russian" just because English is active. `ru`/`uz` are the two languages the core
    /// itself carries, spelled here exactly as it spells them — «Русский» / «O'zbekcha»,
    /// matching `crates/eimzo-rpc/resources/messages_ru.properties`'s `russian`/`uzbek`
    /// keys — so the same two words appear in both halves of this app. English is the app's
    /// own: the core has no counterpart for it, which is why `AppLanguage` and the core's
    /// own two-case `Lang` are separate types.
    var displayName: String {
        switch self {
        case .ru: "Русский"
        case .uz: "Oʻzbekcha"
        case .en: "English"
        }
    }

    /// Forces SwiftUI's own localization lookups (`.environment(\.locale, _:)`) to this
    /// language rather than following the system's — the original itself defaults to Russian
    /// regardless of the machine's language (its own preference default is `"ru"`), and this
    /// app matches that default rather than guessing from the Mac's own language setting.
    var locale: Locale { Locale(identifier: rawValue) }

    /// What this chrome language tells the core through `Settings.lang`, via
    /// `Engine.updateSettings(_:)`. The core's `eimzo_rpc::i18n::Lang` parses only `"ru"`/`"uz"`
    /// — task 6's controller addendum is explicit that adding English there would change what a
    /// website sees, which this task must not do — so English chrome leaves the core on its own
    /// Russian default rather than being given a language it has no third option for.
    var coreLangCode: String {
        self == .uz ? "uz" : "ru"
    }
}

extension Locale {
    /// Resolves `key` (with any `%@` arguments substituted in) from `Localizable.xcstrings` for
    /// this locale — the imperative-code equivalent of what `Text`/`Label` do automatically via
    /// SwiftUI's environment, for the handful of call sites that build a plain `String` instead
    /// of a view (`CoreEngine`'s error messages, `MainWindow`'s window title, `MenuBarContent`'s
    /// key-validity word).
    ///
    /// Deliberately not `String(localized:locale:)`: running the app and reading these exact
    /// strings in each language (task 6's own verification requirement) showed that API silently
    /// returns the English source text regardless of the `locale` argument on this SDK, while
    /// loading the matching `.lproj` bundle directly and calling `Bundle
    /// .localizedString(forKey:value:table:)` on it resolves correctly — confirmed by checking
    /// that the same bundle, opened the same way, does contain the translation.
    func localizedAppString(_ key: String, _ arguments: CVarArg...) -> String {
        let code = language.languageCode?.identifier ?? "en"
        let bundle = Bundle.main.path(forResource: code, ofType: "lproj").flatMap(Bundle.init(path:)) ?? .main
        let template = bundle.localizedString(forKey: key, value: nil, table: "Localizable")
        guard !arguments.isEmpty else { return template }
        return String(format: template, arguments: arguments)
    }
}
