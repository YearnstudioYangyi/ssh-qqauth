use std::ffi::{CStr, CString, c_char, c_int, c_void};
use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

// PAM参数枚举 - pam_get_item
const PAM_RHOST: c_int = 4;
const PAM_SERVICE: c_int = 1;

// PAM状态枚举
const PAM_SUCCESS: c_int = 0;

const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_TEXT_INFO: c_int = 4;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *const c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;

    fn pam_get_item(pamh: *const c_void, item_type: c_int, item: *mut *const c_void) -> c_int;

    fn pam_prompt(
        pamh: *mut c_void,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;
}

unsafe extern "C" {
    fn free(ptr: *mut c_void);
}

// IPC请求体
#[derive(Serialize)]
struct AuthRequest {
    version: u64,
    #[serde(rename = "type")]
    kind: String,
    service: String,
    #[serde(rename = "user")]
    username: String,
    remote_host: String,
    pin: String,
}

// IPC响应结果
#[derive(serde::Deserialize)]
struct AuthResponse {
    version: u32,

    #[serde(rename = "type")]
    kind: String,

    approved: bool,
}

// IPC返回的本次请求数据
#[derive(serde::Deserialize)]
struct AuthRequestInfo {
    version: u32,

    #[serde(rename = "type")]
    kind: String,

    id: String,
}

// IPC相关常量
// const AUTH_SOCKET_PATH: &str = "/run/qqauthd/auth.sock";
const AUTH_SOCKET_PATH: &str = "/tmp/qqauth-dev.sock"; // 调试模式
const AUTH_TIMEOUT: Duration = Duration::from_secs(65);

// 读取用户名
fn get_user(pamh: *const c_void) -> Result<String, String> {
    let mut user: *const c_char = std::ptr::null();

    let status = unsafe { pam_get_user(pamh, &mut user, std::ptr::null()) };

    if status != 0 {
        return Err("get failed".to_owned());
    }

    if user.is_null() {
        return Err("4".to_owned()); // PAM_SYSTEM_ERR
    }

    // 转换为Rust的String
    let username = unsafe { CStr::from_ptr(user).to_string_lossy().into_owned() };

    Ok(username)
}

// 读取远程主机名
fn get_remote_host(pamh: *const c_void) -> Result<String, String> {
    let mut item: *const c_void = std::ptr::null();

    let status = unsafe { pam_get_item(pamh, PAM_RHOST, &mut item) };

    if status != 0 {
        return Err("get failed".to_owned());
    }

    let remote_host = if item.is_null() {
        String::new()
    } else {
        unsafe {
            CStr::from_ptr(item.cast::<c_char>())
                .to_string_lossy()
                .into_owned()
        }
    };

    Ok(remote_host)
}

// 读取服务名
fn get_service(pamh: *const c_void) -> Result<String, String> {
    let mut item: *const c_void = std::ptr::null();

    let status = unsafe { pam_get_item(pamh, PAM_SERVICE, &mut item) };

    if status != 0 {
        return Err("get failed".to_owned());
    }

    let remote_host = if item.is_null() {
        String::new()
    } else {
        unsafe {
            CStr::from_ptr(item.cast::<c_char>())
                .to_string_lossy()
                .into_owned()
        }
    };

    Ok(remote_host)
}

// 向会话推送信息
fn push_message(pamh: *mut c_void ,msg: String) -> Result<(),String> {
    let message = CString::new(msg).unwrap();
    let status = unsafe {
        pam_prompt(
            pamh,
            PAM_TEXT_INFO,
            std::ptr::null_mut(),
            c"%s".as_ptr(),
            message.as_ptr(),
        )
    };
    if status == PAM_SUCCESS {
        return Ok(());
    } else {
        return Err(format!("failed push message with code: {status}"));
    }
}

// 发送并等待认证请求返回
fn request_auth(pamh: *mut c_void, socket_path: &str, req: AuthRequest) -> Result<AuthResponse, String> {
    // 建立连接
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("connect auth socket {socket_path}: {e}"))?;

    // 设置超时
    stream
        .set_read_timeout(Some(AUTH_TIMEOUT))
        .map_err(|e| format!("set read timeout: {e}"))?;

    stream
        .set_write_timeout(Some(AUTH_TIMEOUT))
        .map_err(|e| format!("set write timeout: {e}"))?;

    // 序列化为JSON
    let mut req_json = serde_json::to_vec(&req)
        .map_err(|e| format!("serialize auth request: {e}"))?;

    // 添加换行符
    req_json.push(b'\n');

    // 发送请求
    stream 
        .write_all(&req_json)
        .map_err(|e| format!("write auth request: {e}"))?;

    stream
        .flush()
        .map_err(|e| format!("flush auth request: {e}"))?;

    // 读取响应
    let mut reader = BufReader::new(stream);
    let mut resp_json = Vec::new();

    reader
        .read_until(b'\n', &mut resp_json)
        .map_err(|e| format!("read auth response: {e}"))?;

    if resp_json.is_empty() || resp_json.last() != Some(&b'\n') {
        return Err("incomplete auth request".to_owned());
    }

    // 解析本次请求的信息
    let info: AuthRequestInfo = serde_json::from_slice(&resp_json)
        .map_err(|e|format!("deserialize auth info : {e}"))?;

    if info.version != 1 {
        return Err(format!(
            "unsupported auth protocol version: {}",
            info.version
        ));
    }

    if info.kind != "request_info" {
        return Err(format!(
            "unexpected auth response type: {}",
            info.kind
        ));
    }

    // 向PAM推送信息
    let _ = push_message(pamh, format!("Please confirm request with id: {}", info.id));

    // 等待结果
    resp_json.clear();
    reader
        .read_until(b'\n', &mut resp_json)
        .map_err(|e| format!("read auth response: {e}"))?;

    if resp_json.is_empty() || resp_json.last() != Some(&b'\n') {
        return Err("incomplete auth request".to_owned());
    }

    // 反序列化结果
    let response: AuthResponse = serde_json::from_slice(&resp_json)
        .map_err(|e| format!("deserialize auth response: {e}"))?;

    if response.version != 1 {
        return Err(format!(
            "unsupported auth protocol version: {}",
            response.version
        ));
    }

    if response.kind != "auth_result" {
        return Err(format!(
            "unexpected auth response type: {}",
            response.kind
        ));
    }

    Ok(response)
}

// 提示输入约定 PIN 码（隐藏回显）
fn prompt_pin(pamh: *mut c_void, prompt_text: &str) -> Result<String, String> {
    let mut resp_ptr: *mut c_char = std::ptr::null_mut();
    let prompt = CString::new(prompt_text).map_err(|e| e.to_string())?;

    let status = unsafe {
        pam_prompt(
            pamh,
            PAM_PROMPT_ECHO_OFF,
            &mut resp_ptr,
            c"%s".as_ptr(),
            prompt.as_ptr(),
        )
    };

    if status != PAM_SUCCESS {
        return Err(format!("pam_prompt failed with code: {status}"));
    }

    if resp_ptr.is_null() {
        return Err("empty pin entered".to_owned());
    }

    let pin = unsafe { CStr::from_ptr(resp_ptr).to_string_lossy().into_owned() };
    unsafe { free(resp_ptr.cast()) };

    Ok(pin)
}

struct PamArgs {
    nopin: bool,
    socket_path: Option<String>,
}

fn parse_pam_args(argc: i32, argv: *const *const i8) -> PamArgs {
    let mut args = PamArgs {
        nopin: false,
        socket_path: None,
    };
    if argc <= 0 || argv.is_null() {
        return args;
    }
    for i in 0..argc {
        let arg_ptr = unsafe { *argv.offset(i as isize) };
        if arg_ptr.is_null() {
            continue;
        }
        let arg = unsafe { CStr::from_ptr(arg_ptr).to_string_lossy() };
        if arg == "nopin" {
            args.nopin = true;
        } else if let Some(path) = arg.strip_prefix("socket=") {
            args.socket_path = Some(path.to_owned());
        }
    }
    args
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    _pamh: *mut c_void,
    _flags: i32,
    _argc: i32,
    _argv: *const *const i8,
) -> i32 {
    let pam_args = parse_pam_args(_argc, _argv);

    // 读取用户名
    let username = match get_user(_pamh) {
        Ok(username) => username,
        Err(_) => return 7,
    };

    // 读取主机名
    let hostname = match get_remote_host(_pamh) {
        Ok(hostname) => hostname,
        Err(_) => return 7,
    };

    // 读取服务名
    let service = match get_service(_pamh) {
        Ok(service) => service,
        Err(_) => return 7,
    };

    // 提示输入约定 PIN 码（若未设置 nopin）
    let pin = if pam_args.nopin {
        String::new()
    } else {
        match prompt_pin(_pamh, "Enter PIN: ") {
            Ok(pin) => pin,
            Err(_) => return 7,
        }
    };

    // 构造请求体
    let req = AuthRequest {
        remote_host: hostname,
        username,
        service,
        kind: "auth_request".to_owned(),
        version: 1,
        pin,
    };

    // 选择 socket 路径：参数优先 > 生产 /run/qqauthd/auth.sock > 调试 /tmp/qqauth-dev.sock
    let target_socket = if let Some(ref path) = pam_args.socket_path {
        path.as_str()
    } else if std::path::Path::new("/run/qqauthd/auth.sock").exists() {
        "/run/qqauthd/auth.sock"
    } else {
        AUTH_SOCKET_PATH
    };

    match request_auth(_pamh, target_socket, req) {
        Ok(response) if response.approved => 0,
        Ok(_) => 7,
        Err(_) => 7,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: i32,
    _argc: i32,
    _argv: *const *const i8,
) -> i32 {
    PAM_SUCCESS
}
