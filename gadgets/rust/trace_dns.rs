use wapc_guest as wapc;

#[no_mangle]
pub fn wapc_init() {
    wapc::register_function("column_name", column_name);
}

fn column_name(payload: &[u8]) -> wapc::CallResult {
    let mut str = String::new();
    let mut i = 0;
    while i < payload.len() {
        let length = payload[i] as usize;
        if length == 0 {
            break;
        }
        if i + 1 + length <= payload.len() {
            str.push_str(std::str::from_utf8(&payload[i + 1..i + 1 + length]).unwrap());
            str.push('.');
        } else {
            panic!("invalid payload");
        }
        i += 1 + length;
    }

    if str == "wikipedia.org." {
        wapc::console_log(&format!(
            "In WASM implemented in Rust: thank you for visiting {}",
            str
        ));
    }

    Ok(str.into_bytes())
}

