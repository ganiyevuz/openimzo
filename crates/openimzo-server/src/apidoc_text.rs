//! Uzbek and English for the descriptions in the API reference.
//!
//! The `apidoc` RPC reply is a wire contract. Every plugin, function and argument description in
//! it is the text the original returns, in the language the original returns it in, and websites
//! receive it unchanged — this module never touches that reply. What it does is give *our own*
//! page a table to look those strings up in, so the reference a person opens on `127.0.0.1` reads
//! in the language the menu bar is set to instead of being half translated.
//!
//! Keyed by the Russian source string rather than by a message id, which is the one decision here
//! worth explaining. Adding ids would mean editing all thirteen plugin modules and changing what
//! `FunctionSpec.description` holds, and the value of that field is exactly what goes out on the
//! wire. Keying by the source instead means the Russian a website receives is the same literal it
//! always was, by construction, and a string this table has no entry for simply falls through to
//! the original — a missing translation degrades to the original's own text, never to an empty
//! label or a raw key.
//!
//! The original's own typos are preserved in the keys, because a key that does not match the
//! literal byte for byte translates nothing. They are not reproduced in the translations.

use openimzo_rpc::UiLang;
use std::collections::BTreeMap;

/// `(Russian as the original writes it, Uzbek, English)`.
const TABLE: &[(&str, &str, &str)] = &[
    // --- plugin descriptions -------------------------------------------------
    // The Uzbek here is the original's own, copied from its message bundle rather than written
    // fresh: these eleven are the only descriptions the original itself translates, and where it
    // has already chosen the words, this uses them. The English is ours, since it has none.
    ("Плагин для работы с настройками приложения E-IMZO",
     "E-IMZO ilova sozlamalari bilan ishlash uchun plagin",
     "Plugin for working with E-IMZO's application settings"),
    ("Плагин для работы с файлами хранилища ключей формата PFX",
     "PFX formatidagi kalitlar ombori fayllari bilan ishlash uchun plagin",
     "Plugin for working with PFX key store files"),
    ("Плагин для работы с файлами хранилища ключей формата YTKS",
     "YTKS formatidagi kalitlar ombori fayllari bilan ishlash uchun plagin",
     "Plugin for working with YTKS key store files"),
    ("Плагин для работы с форматом PKCS#7/CMS",
     "PKCS#7/CMS formati bilan ishlash uchun plagin",
     "Plugin for working with the PKCS#7/CMS format"),
    ("Плагин для генерации ключевой пары и формирования запроса на сертификат формата PKCS#10",
     "Kalit juftligini yaratish va PKCS#10 formatidagi sertifikat so‘rovini shakllantirish uchun plagin",
     "Plugin for generating a key pair and building a PKCS#10 certificate request"),
    ("Плагин для работы с сертификатами X.509",
     "X.509 sertifikatlari bilan ishlash uchun plagin",
     "Plugin for working with X.509 certificates"),
    // The original's own abbreviation, ИОК / OKI: the national public key infrastructure.
    ("Плагин для взаимодейтвия с ИОК",
     "OKI bilan o‘zaro ishlash uchun plagin",
     "Plugin for interacting with the public key infrastructure"),
    ("Плагин для работы с Крипто Контейнерами Ключа",
     "Kripto kalit konteynerlari bilan ishlash uchun plagin",
     "Plugin for working with crypto key containers"),
    ("Плагин для работы с BAIK-Token",
     "BAIK-token bilan ishlash uchun plagin",
     "Plugin for working with the BAIK token"),
    ("Плагин для работы с ID-card E-IMZO",
     "E-IMZO ID-karta bilan ishlash uchun plagin",
     "Plugin for working with the E-IMZO ID card"),
    ("Плагин для работы с UZGUARD-Token",
     "UZGUARD-token bilan ishlash uchun plagin",
     "Plugin for working with the UZGUARD token"),

    ("Отобразить окно с меню E-IMZO",
     "E-IMZO menyusi oynasini koʻrsatish",
     "Show the E-IMZO menu window"),
    ("Изменить язык интерфейса (не сохраняя в настройках)",
     "Interfeys tilini oʻzgartirish (sozlamalarga saqlamasdan)",
     "Change the interface language without saving it to settings"),
    ("Информацио о версии JVM",
     "JVM versiyasi haqida ma'lumot",
     "Information about the JVM version"),

    // --- keys and key stores -------------------------------------------------
    ("Получить список дисков",
     "Disklar roʻyxatini olish",
     "List the disks"),
    ("Получить список сертификатов пользователя",
     "Foydalanuvchi sertifikatlari roʻyxatini olish",
     "List the user's certificates"),
    ("Получить список всех сертификатов пользователя",
     "Foydalanuvchining barcha sertifikatlari roʻyxatini olish",
     "List all of the user's certificates"),
    ("Загрузить ключ и получить идентификатор ключа. Ключ будет доступен определенное время",
     "Kalitni yuklash va kalit identifikatorini olish. Kalit ma'lum vaqt davomida ochiq boʻladi",
     "Load a key and get its identifier. The key stays available for a limited time"),
    ("Удалить загруженные ключи по идентификатору",
     "Yuklangan kalitlarni identifikator boʻyicha oʻchirish",
     "Unload the keys with this identifier"),
    ("Изменить пароль хранилища ключей",
     "Kalitlar ombori parolini oʻzgartirish",
     "Change the key store's password"),
    ("Получить список Крипто Контейнеров Ключа",
     "Kripto kalit konteynerlari roʻyxatini olish",
     "List the crypto key containers"),
    ("Стереть сохраненые PIN-коды",
     "Saqlangan PIN-kodlarni oʻchirish",
     "Erase the saved PIN codes"),

    // --- certificates and chains ---------------------------------------------
    ("Получить цепочку сертификатов в кодировке BASE64 по идентификатору ключа",
     "Kalit identifikatori boʻyicha BASE64 kodidagi sertifikatlar zanjirini olish",
     "Get the BASE64-encoded certificate chain for a key identifier"),
    ("Верификация подписи сертификата субъектка сертификатом издателя",
     "Subyekt sertifikati imzosini chiqaruvchi sertifikati bilan tekshirish",
     "Verify a subject certificate's signature against its issuer's certificate"),
    ("Получить информацию о запросе PKCS#10",
     "PKCS#10 soʻrovi haqida ma'lumot olish",
     "Get information about a PKCS#10 request"),
    ("Формировать запрос на сертификат формата PKCS#10",
     "PKCS#10 formatidagi sertifikat soʻrovini shakllantirish",
     "Build a PKCS#10 certificate request"),
    ("Формировать запрос на сертификат формата PKCS#10 из существующего ключа",
     "Mavjud kalitdan PKCS#10 formatidagi sertifikat soʻrovini shakllantirish",
     "Build a PKCS#10 certificate request from an existing key"),

    // --- signing --------------------------------------------------------------
    ("Создать PKCS#7/CMS документ подписав ключем задаваемым идентификатором",
     "Identifikator bilan koʻrsatilgan kalit yordamida imzolab PKCS#7/CMS hujjatini yaratish",
     "Create a PKCS#7/CMS document, signed with the key named by the identifier"),

    // --- enrolment ------------------------------------------------------------
    ("Шаг №1 для получения ключа PFX",
     "PFX kalitini olish uchun 1-qadam",
     "Step 1 of obtaining a PFX key"),
    ("Шаг №2 для получения ключа PFX",
     "PFX kalitini olish uchun 2-qadam",
     "Step 2 of obtaining a PFX key"),
    ("Сохранить ключевую пару или существующий ключ и новые сертификаты в новый файл формата PFX",
     "Kalitlar juftini yoki mavjud kalitni va yangi sertifikatlarni yangi PFX faylga saqlash",
     "Save a key pair, or an existing key, and new certificates into a new PFX file"),
    ("Сохранить ключевую пару или существующий ключ и новые сертификаты в новый файл формата YTKS",
     "Kalitlar juftini yoki mavjud kalitni va yangi sertifikatlarni yangi YTKS faylga saqlash",
     "Save a key pair, or an existing key, and new certificates into a new YTKS file"),
    ("Сохранить ключевую пару и самоподписанный сертификат во временный файл формата PFX",
     "Kalitlar jufti va oʻz-oʻzini imzolagan sertifikatni vaqtinchalik PFX faylga saqlash",
     "Save a key pair and a self-signed certificate into a temporary PFX file"),

    // --- tokens ---------------------------------------------------------------
    ("Получить список считывателей",
     "Oʻquvchilar roʻyxatini olish",
     "List the card readers"),
    ("Получить список BAIK-Token ов",
     "BAIK-Token'lar roʻyxatini olish",
     "List the BAIK tokens"),
    ("Получить список UZGUARD-Token ов",
     "UZGUARD-Token'lar roʻyxatini olish",
     "List the UZGUARD tokens"),
    ("Получить зашифрованный и подписанный заводской номер USB-токена",
     "USB-tokenning shifrlangan va imzolangan zavod raqamini olish",
     "Get the USB token's encrypted and signed factory serial number"),
    ("Персонализировать BAIK-Token записав новые сертификаты и установив PIN-код",
     "Yangi sertifikatlarni yozib va PIN-kod oʻrnatib BAIK-Token'ni shaxsiylashtirish",
     "Personalise a BAIK token by writing new certificates and setting a PIN code"),
    ("Персонализировать ID-карту записав новые сертификаты и установив PIN-код",
     "Yangi sertifikatlarni yozib va PIN-kod oʻrnatib ID-kartani shaxsiylashtirish",
     "Personalise an ID card by writing new certificates and setting a PIN code"),
    ("Персонализировать UZGUARD-Token записав новые сертификаты и установив PIN-код",
     "Yangi sertifikatlarni yozib va PIN-kod oʻrnatib UZGUARD-Token'ni shaxsiylashtirish",
     "Personalise a UZGUARD token by writing new certificates and setting a PIN code"),

    ("Сгенерировать ключевую пару",
     "Kalitlar juftini yaratish",
     "Generate a key pair"),
    ("Проверить пароль хранилища ключей",
     "Kalitlar ombori parolini tekshirish",
     "Check the key store's password"),
    ("Получить информацию о сертификате",
     "Sertifikat haqida ma'lumot olish",
     "Get information about a certificate"),
    ("Получить список типов поддерживаемых Крипто Контейнеров Ключа",
     "Qoʻllab-quvvatlanadigan kripto kalit konteynerlari turlari roʻyxatini olish",
     "List the supported crypto key container types"),

    // --- argument descriptions ------------------------------------------------
    ("Название алгоритма", "Algoritm nomi", "Algorithm name"),
    ("Корневой сертификат в кодировке BASE64",
     "BASE64 kodidagi ildiz sertifikati",
     "BASE64-encoded root certificate"),
    ("Сертификат издателя в кодировке BASE64",
     "BASE64 kodidagi chiqaruvchi sertifikati",
     "BASE64-encoded issuer certificate"),
    ("Диск", "Disk", "Disk"),
    ("Путь (должна быть пустой или 'DSKEYS')",
     "Yoʻl (boʻsh yoki 'DSKEYS' boʻlishi kerak)",
     "Path; must be empty or 'DSKEYS'"),
    ("Имя файла без расширения", "Kengaytmasiz fayl nomi", "File name without its extension"),
    ("Имя файла без расширения (если тип носителя ключа - файл)",
     "Kengaytmasiz fayl nomi (agar kalit tashuvchisi fayl boʻlsa)",
     "File name without its extension, when the key medium is a file"),
    ("Алиас ключа", "Kalit taxallusi", "Key alias"),
    ("Идентификатор ключа", "Kalit identifikatori", "Key identifier"),
    // The original is missing a letter here; the key has to match it exactly to find anything.
    ("Идентификато ключа", "Kalit identifikatori", "Key identifier"),
    ("Идентификатор ключевой пары", "Kalitlar jufti identifikatori", "Key pair identifier"),
    ("Идентификатор новой ключевой пары", "Yangi kalitlar jufti identifikatori", "New key pair identifier"),
    ("Идентификатор новой ключевой пары или существующего хранилища ключей (для обновления сертификатов)",
     "Yangi kalitlar jufti yoki mavjud kalitlar ombori identifikatori (sertifikatlarni yangilash uchun)",
     "Identifier of the new key pair, or of an existing key store when renewing certificates"),
    ("Идентификатор ключа подписывающего лица (полученный из фукнции других плагинов)",
     "Imzolovchi shaxs kalitining identifikatori (boshqa plaginlar funksiyasidan olingan)",
     "The signer's key identifier, as returned by another plugin's function"),
    ("Идентификатор процесса GUID", "Jarayon identifikatori GUID", "Process identifier (GUID)"),
    ("Идентификатор процесса GUID (полученный из Шага №1)",
     "Jarayon identifikatori GUID (1-qadamdan olingan)",
     "Process identifier (GUID), as returned by step 1"),
    ("Пароль для нового ключа", "Yangi kalit uchun parol", "Password for the new key"),
    ("Пароль для временного ключа", "Vaqtinchalik kalit uchun parol", "Password for the temporary key"),
    ("PIN-код", "PIN-kod", "PIN code"),
    ("Значение NONCE", "NONCE qiymati", "NONCE value"),
    ("Код языка (uz,ru)", "Til kodi (uz, ru)", "Language code (uz, ru)"),
    ("Серийный номер сертификата (HEX)", "Sertifikat seriya raqami (HEX)", "Certificate serial number (HEX)"),
    ("Сертификат в кодировке BASE64", "BASE64 kodidagi sertifikat", "BASE64-encoded certificate"),
    ("Сертификат в кодировке BASE64 или PEM",
     "BASE64 yoki PEM kodidagi sertifikat",
     "Certificate, BASE64- or PEM-encoded"),
    ("Сертификат субъекта в кодировке BASE64",
     "BASE64 kodidagi subyekt sertifikati",
     "BASE64-encoded subject certificate"),
    ("Сертификат Центра Регистрации в кодировке BASE64",
     "BASE64 kodidagi Roʻyxatga olish markazi sertifikati",
     "BASE64-encoded Registration Authority certificate"),
    ("Имя субъекта в формате X.500", "X.500 formatidagi subyekt nomi", "Subject name in X.500 format"),
    ("Имя субъекта в формате X.500 или '' если нужно получить имя из сертификата по идентификатору ключа",
     "X.500 formatidagi subyekt nomi, yoki kalit identifikatori boʻyicha sertifikatdan nom olinishi kerak boʻlsa ''",
     "Subject name in X.500 format, or '' to take the name from the certificate for the given key identifier"),
    ("OIDы политик применения сертификатов разделенных запятой",
     "Vergul bilan ajratilgan sertifikatlardan foydalanish siyosati OID'lari",
     "Comma-separated OIDs of the certificate policies"),
    ("Случайные данные для инициализации генератора случайных чисел",
     "Tasodifiy sonlar generatorini ishga tushirish uchun tasodifiy ma'lumotlar",
     "Random data used to seed the random number generator"),
    ("Данные в кодировке BASE64 (будут предваритьльно декодированы, подписаны и вложены в документ)",
     "BASE64 kodidagi ma'lumotlar (avval dekodlanadi, imzolanadi va hujjat ichiga joylanadi)",
     "BASE64-encoded data; it is decoded first, then signed and embedded in the document"),
    ("Возможные значения: 'yes' - будет создан PKCS#7/CMS документ без вложения исходных данных, 'no' или '' - будет создан PKCS#7/CMS документ с вложением исходных данных",
     "Mumkin boʻlgan qiymatlar: 'yes' — asl ma'lumotlar joylanmagan PKCS#7/CMS hujjati yaratiladi; 'no' yoki '' — asl ma'lumotlar joylangan PKCS#7/CMS hujjati yaratiladi",
     "Possible values: 'yes' creates a PKCS#7/CMS document without the original data embedded; 'no' or '' creates one with it embedded"),
];

/// The lookup table the API reference page carries, as JSON, for one language.
///
/// Empty for Russian: the descriptions already arrive in Russian, so there is nothing to swap and
/// the page ships no table at all rather than one mapping every string to itself.
pub fn translations_json(lang: UiLang) -> String {
    if lang == UiLang::Ru {
        return "{}".to_string();
    }
    let map: BTreeMap<&str, &str> = TABLE
        .iter()
        .map(|(ru, uz, en)| (*ru, if lang == UiLang::Uz { *uz } else { *en }))
        .collect();
    // A table of fixed literals cannot fail to serialize; if it somehow did, an empty table
    // leaves every description as the original wrote it, which is the same thing a missing entry
    // already does.
    serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
}
