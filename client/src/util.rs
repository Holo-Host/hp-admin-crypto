use failure::*;
use wasm_bindgen::prelude::*;

pub type Fallible<T> = Result<T, JsValue>;

pub fn into_js_error(err: impl Fail) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}
