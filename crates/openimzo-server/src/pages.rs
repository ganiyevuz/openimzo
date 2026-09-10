//! The words our own two pages are written in, in the three languages the
//! app's menu bar offers.
//!
//! Deliberately NOT in `openimzo-rpc`'s message bundle. That bundle is a
//! byte-for-byte copy of the app we replace, websites match on the strings
//! in it, and it has no English at all — the original only ever shipped
//! Russian and Uzbek. These are our own words on our own pages, so they
//! live here, where adding English costs nothing and changing one cannot
//! alter anything a website reads.
//!
//! One `struct` of fields rather than a map of keys, so a language missing
//! a string is a compile error rather than a page that silently falls back
//! to another language. The Swift side needs a whole script
//! (`scripts/check-localization.py`) to get the same guarantee; here the
//! type system does it.

use openimzo_rpc::UiLang;

/// Every string either page shows that is not a plugin's own documentation.
///
/// A handful carry inline markup (`<code>`, `<strong>`) and one carries a
/// `%s` for the version. They are template fragments authored in this file,
/// not data from anywhere else, and they are substituted into the page as
/// written — which is what lets a translation put the emphasis where its
/// own grammar wants it.
pub struct PageText {
    /// `<html lang>` and the browser's own idea of the page's language.
    pub code: &'static str,
    /// index.html: the line under the product name.
    pub tagline: &'static str,
    /// index.html: what the app is doing right now. `%s` is the version.
    pub status: &'static str,
    /// index.html: the link to apidoc.html, and apidoc.html's own heading.
    pub api_docs: &'static str,
    /// index.html: the link to the repository.
    pub source_code: &'static str,
    /// apidoc.html: the compatibility note's opening claim, shown bold.
    pub compat_lead: &'static str,
    /// apidoc.html: the compatibility note itself.
    pub compat_body: &'static str,
    /// apidoc.html: the smaller print under it.
    pub compat_note: &'static str,
    /// apidoc.html: the sidebar's heading.
    pub toc_title: &'static str,
    /// apidoc.html: the sidebar before the document arrives.
    pub loading: &'static str,
    /// apidoc.html: the body before the document arrives.
    pub loading_doc: &'static str,
    /// apidoc.html: the button on every example.
    pub copy: &'static str,
    /// apidoc.html: what that button says for a moment afterwards.
    pub copied: &'static str,
    /// apidoc.html: marks an argument a call may leave out. Shown in
    /// parentheses, which the page adds.
    pub optional: &'static str,
    /// apidoc.html: shown when the document cannot be fetched. The reason
    /// follows after a colon, which the page adds.
    pub load_failed: &'static str,
}

/// Russian, which is also what an unrecognized language falls back to — the
/// original defaults to Russian regardless of the machine's own language,
/// and this project matches that rather than guessing.
const RU: PageText = PageText {
    code: "ru",
    tagline: "Локальный сервис электронной подписи. Открытый исходный код — проверьте сами.",
    status: "OpenImzo работает на этом компьютере и отвечает сайтам как E-IMZO-v%s.",
    api_docs: "API-документация для разработчиков",
    source_code: "Исходный код",
    compat_lead: "Тот же API, что и у E-IMZO.",
    compat_body: "Все функции, имена плагинов, аргументы и коды статусов совпадают, а клиентская \
                  библиотека <code>e-imzo.js</code> — та же самая и по тому же адресу. Сайт, уже \
                  работающий с E-IMZO, работает с OpenImzo без единой правки в коде: меняется \
                  приложение на компьютере пользователя, а не интеграция.",
    compat_note: "Отличается лишь текст некоторых сообщений, которые видит человек, — сами коды \
                  ответов те же, поэтому проверки на стороне сайта остаются рабочими.",
    toc_title: "Содержание",
    loading: "Загрузка…",
    loading_doc: "Загрузка документации…",
    copy: "Копировать",
    copied: "Скопировано",
    optional: "необязательный",
    load_failed: "Не удалось загрузить документацию",
};

const UZ: PageText = PageText {
    code: "uz",
    tagline: "Elektron imzo uchun lokal xizmat. Ochiq kodli — oʻzingiz tekshirib koʻrishingiz mumkin.",
    status: "OpenImzo shu kompyuterda ishlamoqda va saytlarga E-IMZO-v%s sifatida javob beradi.",
    api_docs: "Dasturchilar uchun API hujjatlari",
    source_code: "Manba kodi",
    compat_lead: "E-IMZO bilan bir xil API.",
    compat_body: "Barcha funksiyalar, plagin nomlari, argumentlar va holat kodlari bir xil, \
                  <code>e-imzo.js</code> mijoz kutubxonasi ham oʻsha manzildagi oʻsha faylning \
                  oʻzi. E-IMZO bilan allaqachon ishlayotgan sayt OpenImzo bilan kodiga bitta ham \
                  oʻzgartirish kiritmasdan ishlaydi: foydalanuvchi kompyuteridagi dastur \
                  almashadi, integratsiya emas.",
    compat_note: "Faqat odam oʻqiydigan ayrim xabarlar matni farq qiladi — javob kodlari \
                  oʻzgarmagan, shuning uchun sayt tomonidagi tekshiruvlar ishlayveradi.",
    toc_title: "Mundarija",
    loading: "Yuklanmoqda…",
    loading_doc: "Hujjatlar yuklanmoqda…",
    copy: "Nusxalash",
    copied: "Nusxalandi",
    optional: "ixtiyoriy",
    load_failed: "Hujjatlarni yuklab boʻlmadi",
};

const EN: PageText = PageText {
    code: "en",
    tagline: "Local signing service for Uzbek e-signature. Open source, and yours to check.",
    status: "OpenImzo is running on this computer and answers websites as E-IMZO-v%s.",
    api_docs: "API documentation for developers",
    source_code: "Source code",
    compat_lead: "The same API as E-IMZO.",
    compat_body: "Every function, plugin name, argument and status code is identical, and the \
                  client library <code>e-imzo.js</code> is the same file at the same address. A \
                  site that already works with E-IMZO works with OpenImzo without a single change \
                  to its code: what changes is the app on the person's computer, not the \
                  integration.",
    compat_note: "Only the wording of some human-readable messages differs — the response codes \
                  themselves are unchanged, so checks on the site's own side keep working.",
    toc_title: "Contents",
    loading: "Loading…",
    loading_doc: "Loading the documentation…",
    copy: "Copy",
    copied: "Copied",
    optional: "optional",
    load_failed: "The documentation could not be loaded",
};

pub fn text(lang: UiLang) -> &'static PageText {
    match lang {
        UiLang::Ru => &RU,
        UiLang::Uz => &UZ,
        UiLang::En => &EN,
    }
}
