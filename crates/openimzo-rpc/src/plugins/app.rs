//! Settings and window control. The original's `app` plugin.

use crate::dispatch::{Ctx, FunctionSpec};
use crate::error::{Result, RpcError};
use crate::function;
use crate::i18n::Lang;
use crate::model::{Request, Response};
use crate::origin::Origin;
use crate::plugins::arg;

pub fn functions() -> Vec<FunctionSpec> {
    vec![
        function!("app", "get_jvm_version", "Информацио о версии JVM", [], get_runtime_version),
        function!(
            "app",
            "change_ui_lang",
            "Изменить язык интерфейса (не сохраняя в настройках)",
            [arg("lang", "Код языка (uz,ru)")],
            change_ui_lang
        ),
        function!("app", "show_menu", "Отобразить окно с меню E-IMZO", [], show_menu),
    ]
}

async fn show_menu(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    // Phase 3 routes this to the app's main window. Answering success keeps
    // sites that call it working meanwhile.
    tracing::info!("site asked to show the app window");
    Ok(Response::success())
}

async fn get_runtime_version(_ctx: &Ctx, _origin: &Origin, _request: &Request) -> Result<Response> {
    Ok(Response::message(env!("CARGO_PKG_VERSION")))
}

async fn change_ui_lang(ctx: &Ctx, origin: &Origin, request: &Request) -> Result<Response> {
    let lang = Lang::from_code(request.arg(0)).ok_or(RpcError::InvalidLangCode)?;
    // Scoped to this caller (`Ctx::set_lang_for`), not written process-wide,
    // so one site's language change never colors every other connection's
    // reply text.
    ctx.set_lang_for(origin, lang);
    Ok(Response::message(match lang {
        Lang::Ru => "ru_RU",
        Lang::Uz => "uz_UZ",
    }))
}
