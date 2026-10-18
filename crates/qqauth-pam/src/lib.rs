use std::ffi::{CStr, c_char, c_int, c_void};
use serde::Serialize;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

// PAM参数枚举 - pam_get_item
const PAM_RHOST: c_int = 4;
const PAM_SERVICE: c_int = 1;

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_get_user(pamh: *const c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;

    fn pam_get_item(pamh: *const c_void, item_type: c_int, item: *mut *const c_void) -> c_int;
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
}

// IPC响应结果
#[derive(serde::Deserialize)]
struct AuthResponse {
    version: u32,

    #[serde(rename = "type")]
    kind: String,

    approved: bool,
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

// 发送并等待认证请求返回
fn request_auth(req: AuthRequest) -> Result<AuthResponse, String> {
    // 建立连接
    let mut stream = UnixStream::connect(AUTH_SOCKET_PATH)
        .map_err(|e| format!("connect auth socket: {e}"))?;

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

    // 反序列化
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    _pamh: *mut c_void,
    _flags: i32,
    _argc: i32,
    _argv: *const *const i8,
) -> i32 {
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

    // 构造请求体
    let req = AuthRequest{
        remote_host: hostname,
        username,
        service,
        kind: "auth_request".to_owned(),
        version: 1,
    };

    match request_auth(req) {
        Ok(response) if response.approved => 0,
        Ok(_) => 7,
        Err(_) => 7,
    }
}
