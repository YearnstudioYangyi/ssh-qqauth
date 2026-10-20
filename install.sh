#!/usr/bin/env bash
# ==============================================================================
# QQAuth 一键交互式安装与配置脚本
# 支持：
#   1. 是否启用 PIN 码保护及自定义 PIN 码
#   2. PAM & SSH 行为配置（默认：禁用系统密码，QQ授权与公钥登录二选一）
#   3. 一键编译、安装二进制、配置 systemd 服务与安全备份
# ==============================================================================

set -e

# 确保在 sudo 运行环境下继承常见 Go 与 Cargo 的安装路径
export PATH="/usr/local/go/bin:/usr/local/cargo/bin:${HOME}/.cargo/bin:${HOME}/go/bin:/home/${SUDO_USER:-root}/.cargo/bin:/home/${SUDO_USER:-root}/go/bin:${PATH}"
export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"

RED='\033[031m'
GREEN='\033[032m'
YELLOW='\033[033m'
BLUE='\033[034m'
CYAN='\033[036m'
BOLD='\033[1m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
# 如果脚本在 scripts 目录下，PROJECT_ROOT 向上跳一级
if [ -f "${SCRIPT_DIR}/../Cargo.toml" ]; then
    PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
fi

CONFIG_DIR="/etc/qqauth"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SYSTEMD_SERVICE="/etc/systemd/system/qqauthd.service"
PAM_INSTALL_PATH="/lib/security/pam_qqauth.so"
BIN_INSTALL_PATH="/usr/local/bin/qqauthd"
SSHD_CONFIG_DIR="/etc/ssh/sshd_config.d"
SSHD_CONFIG_FILE="/etc/ssh/sshd_config"
PAM_SSHD_FILE="/etc/pam.d/sshd"
BACKUP_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

info() {
    echo -e "${GREEN}[INFO]${RESET} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${RESET} $1"
}

error() {
    echo -e "${RED}[ERROR]${RESET} $1"
}

heading() {
    echo -e "\n${BOLD}${CYAN}=== $1 ===${RESET}"
}

# 1. 权限检查
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "此脚本必须以 root 权限运行，请使用 sudo $0"
        exit 1
    fi
}

# 2. 检查依赖
check_deps() {
    heading "检查编译与运行环境"
    local missing=()
    for cmd in cargo go pamtester; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        warn "检测到缺少以下依赖工具: ${missing[*]}"
        read -r -p "是否尝试通过 apt/yum 自动安装必要依赖？[Y/n]: " install_dep
        install_dep=${install_dep:-Y}
        if [[ "$install_dep" =~ ^[Yy]$ ]]; then
            if command -v apt-get >/dev/null 2>&1; then
                apt-get update && apt-get install -y libpam0g-dev pamtester build-essential
            elif command -v yum >/dev/null 2>&1; then
                yum install -y pam-devel pamtester gcc
            fi
        fi
    fi
    info "环境检查完毕。"
}

# 3. 编译二进制与 PAM 模块
build_targets() {
    heading "编译 Go 守护进程与 Rust PAM 模块"
    cd "${PROJECT_ROOT}"

    local run_as_user=""
    if [ -n "${SUDO_USER}" ] && [ "${SUDO_USER}" != "root" ]; then
        run_as_user="sudo -u ${SUDO_USER} PATH=${PATH} HOME=/home/${SUDO_USER}"
    fi

    info "正在编译 Go 守护进程 (qqauthd)..."
    if [ -n "$run_as_user" ]; then
        sudo -u "${SUDO_USER}" env "PATH=${PATH}" "HOME=/home/${SUDO_USER}" go build -ldflags="-s -w" -o "${PROJECT_ROOT}/target/qqauthd" ./cmd/qqauthd/main.go
    else
        go build -ldflags="-s -w" -o "${PROJECT_ROOT}/target/qqauthd" ./cmd/qqauthd/main.go
    fi
    info "Go 守护进程编译成功: ${PROJECT_ROOT}/target/qqauthd"

    info "正在编译 Rust PAM 模块 (libqqauth_pam.so)..."
    if [ -n "$run_as_user" ]; then
        sudo -u "${SUDO_USER}" env "PATH=${PATH}" "HOME=/home/${SUDO_USER}" "RUSTUP_HOME=${RUSTUP_HOME}" "CARGO_HOME=${CARGO_HOME}" cargo build --release -p qqauth-pam || sudo -u "${SUDO_USER}" env "PATH=${PATH}" "HOME=/home/${SUDO_USER}" "RUSTUP_HOME=${RUSTUP_HOME}" "CARGO_HOME=${CARGO_HOME}" cargo build -p qqauth-pam
    else
        cargo build --release -p qqauth-pam || cargo build -p qqauth-pam
    fi

    local pam_so="${PROJECT_ROOT}/target/release/libqqauth_pam.so"
    if [ ! -f "$pam_so" ]; then
        pam_so="${PROJECT_ROOT}/target/debug/libqqauth_pam.so"
    fi
    info "Rust PAM 模块编译成功: ${pam_so}"
}

# 4. 交互式配置问答
interactive_setup() {
    heading "配置选项交互设置"

    # --- PIN 码设置 ---
    echo -e "${BOLD}1. 约定 PIN 码保护配置：${RESET}"
    echo "   开启后，终端需先输入此 6 位 PIN 码才会发起 QQ 授权，能从源头彻底阻断扫描器与爆破消息轰炸。"
    read -r -p "是否开启 PIN 码防护？[Y/n (默认: Y)]: " opt_enable_pin
    opt_enable_pin=${opt_enable_pin:-Y}

    ENABLE_PIN="true"
    PIN_CODE="123456"

    if [[ "$opt_enable_pin" =~ ^[Nn]$ ]]; then
        ENABLE_PIN="false"
        info "已选择：关闭 PIN 码保护。"
    else
        read -r -p "请输入预设的 PIN 码 (默认: 123456): " input_pin
        PIN_CODE=${input_pin:-123456}
        info "已设置 PIN 码为: ${PIN_CODE}"
    fi

    # --- PAM / SSH 行为模式选择 ---
    echo -e "\n${BOLD}2. PAM 与 SSH 登录行为策略选择：${RESET}"
    echo "   [1] (默认推荐) 密钥与QQ二选一：有SSH密钥直接进，无密钥走QQ授权，禁用传统系统密码"
    echo "   [2] 双因子严格模式 (2FA)：无论密钥还是密码登录，均必须通过 QQ 授权二次确认"
    echo "   [3] 仅独立测试模式：不触动系统 SSH，仅安装服务并在 /etc/pam.d/qqauth-test 供测试"
    read -r -p "请选择模式编号 [1/2/3 (默认: 1)]: " opt_pam_mode
    PAM_MODE=${opt_pam_mode:-1}

    case "$PAM_MODE" in
        2) info "已选择：[2] 双因子严格模式 (2FA)" ;;
        3) info "已选择：[3] 仅独立测试模式" ;;
        *) PAM_MODE=1; info "已选择：[1] 密钥与QQ二选一（禁用密码，无密钥走QQ授权）" ;;
    esac
}

# 5. 安装核心文件
install_files() {
    heading "安装系统文件与目录"

    mkdir -p "${CONFIG_DIR}" "/run/qqauthd" "/lib/security" "/usr/local/bin"

    # 安装二进制
    cp -f "${PROJECT_ROOT}/target/qqauthd" "${BIN_INSTALL_PATH}"
    chmod 755 "${BIN_INSTALL_PATH}"
    info "已安装守护进程至: ${BIN_INSTALL_PATH}"

    # 安装 PAM 模块
    local src_pam="${PROJECT_ROOT}/target/release/libqqauth_pam.so"
    if [ ! -f "$src_pam" ]; then
        src_pam="${PROJECT_ROOT}/target/debug/libqqauth_pam.so"
    fi
    cp -f "$src_pam" "${PAM_INSTALL_PATH}"
    chmod 644 "${PAM_INSTALL_PATH}"
    info "已安装 PAM 模块至: ${PAM_INSTALL_PATH}"

    # 生成配置文件
    cat > "${CONFIG_FILE}" <<EOF
{
  "enable_pin": ${ENABLE_PIN},
  "pin": "${PIN_CODE}",
  "auth_socket": "/run/qqauthd/auth.sock",
  "bot_socket": "/run/qqauthd/botipc.sock",
  "ban_duration_minutes": 30,
  "max_failed_attempts": 3,
  "rate_window_seconds": 60
}
EOF
    chmod 644 "${CONFIG_FILE}"
    info "已生成配置文件: ${CONFIG_FILE}"

    # 安装 systemd 服务
    cat > "${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=QQAuth Unified Authentication Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=${BIN_INSTALL_PATH} -config ${CONFIG_FILE}
Restart=always
RestartSec=3
RuntimeDirectory=qqauthd
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF

    if command -v systemctl >/dev/null 2>&1 && systemctl status systemd-journald >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable qqauthd
        systemctl restart qqauthd
        info "已启动并启用 qqauthd 系统服务！"
    else
        warn "当前系统环境中未运行 systemd (如 Docker 容器环境)，已安装服务单元文件。"
        warn "你可以通过以下命令在后台启动守护进程: ${BIN_INSTALL_PATH} -config ${CONFIG_FILE} &"
    fi
}

# 6. 配置 PAM 与 SSHD
configure_pam_and_sshd() {
    heading "配置 PAM 与 SSHD"

    # 总是生成供 pamtester 测试的配置文件
    cat > "/etc/pam.d/qqauth-test" <<EOF
# qqauth-test service for testing
auth required ${PAM_INSTALL_PATH} $( [ "$ENABLE_PIN" = "false" ] && echo "nopin" )
EOF
    info "已更新测试配置: /etc/pam.d/qqauth-test"

    if [ "$PAM_MODE" -eq 3 ]; then
        info "模式 3 (仅测试模式)，跳过修改系统 SSH 与 PAM 配置。"
        return 0
    fi

    # 备份原有配置
    if [ -f "${PAM_SSHD_FILE}" ]; then
        cp "${PAM_SSHD_FILE}" "${PAM_SSHD_FILE}.bak.${BACKUP_TIMESTAMP}"
        info "已备份 ${PAM_SSHD_FILE} -> ${PAM_SSHD_FILE}.bak.${BACKUP_TIMESTAMP}"
    fi

    local pin_param=""
    if [ "$ENABLE_PIN" = "false" ]; then
        pin_param="nopin"
    fi

    if [ "$PAM_MODE" -eq 1 ]; then
        # 模式 1: 禁用密码，QQ 与公钥二选一
        info "应用模式 1: 禁用普通密码认证，开启 SSH 键盘交互 (QQ 授权)..."

        # 1. 配置 PAM: 在 /etc/pam.d/sshd 头部插入 qqauth 作为 sufficient，禁用 common-auth 的密码验证
        local temp_pam="/tmp/pam_sshd_qqauth"
        cat > "${temp_pam}" <<EOF
# ================= QQAuth Managed Configuration =================
# 密钥直接登录放行（由 sshd pubkey 处理）
# 键盘交互模式走 QQAuth 授权，无密钥时必须经过 QQ 确认
auth    sufficient      ${PAM_INSTALL_PATH} ${pin_param}
auth    requisite       pam_deny.so
# ================================================================
EOF
        # 保留 account, session, password 等基础栈
        grep -v "@include common-auth" "${PAM_SSHD_FILE}.bak.${BACKUP_TIMESTAMP}" >> "${temp_pam}" || true
        cp "${temp_pam}" "${PAM_SSHD_FILE}"
        rm -f "${temp_pam}"

    elif [ "$PAM_MODE" -eq 2 ]; then
        # 模式 2: 双因子 2FA 模式（必须经过 qqauth）
        info "应用模式 2: 双因子严格模式 (2FA)..."
        local temp_pam="/tmp/pam_sshd_qqauth"
        cat > "${temp_pam}" <<EOF
# ================= QQAuth 2FA Managed =================
auth    required        ${PAM_INSTALL_PATH} ${pin_param}
# =====================================================
EOF
        cat "${PAM_SSHD_FILE}.bak.${BACKUP_TIMESTAMP}" >> "${temp_pam}"
        cp "${temp_pam}" "${PAM_SSHD_FILE}"
        rm -f "${temp_pam}"
    fi

    # 配置 SSHD (优先使用 sshd_config.d，避免直接破坏主文件)
    if [ -d "${SSHD_CONFIG_DIR}" ]; then
        cat > "${SSHD_CONFIG_DIR}/99-qqauth.conf" <<EOF
# QQAuth Configuration
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes
UsePAM yes
EOF
        info "已写入 SSHD 配置补丁: ${SSHD_CONFIG_DIR}/99-qqauth.conf"
    else
        cp "${SSHD_CONFIG_FILE}" "${SSHD_CONFIG_FILE}.bak.${BACKUP_TIMESTAMP}"
        info "已备份 ${SSHD_CONFIG_FILE} -> ${SSHD_CONFIG_FILE}.bak.${BACKUP_TIMESTAMP}"
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "${SSHD_CONFIG_FILE}"
        sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' "${SSHD_CONFIG_FILE}"
        sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' "${SSHD_CONFIG_FILE}"
        sed -i 's/^#*UsePAM.*/UsePAM yes/' "${SSHD_CONFIG_FILE}"
    fi

    # 校验 sshd 配置是否语法正确
    if command -v sshd >/dev/null 2>&1; then
        if ! sshd -t; then
            error "SSHD 配置语法检查失败！正在回滚配置..."
            if [ -f "${PAM_SSHD_FILE}.bak.${BACKUP_TIMESTAMP}" ]; then
                cp "${PAM_SSHD_FILE}.bak.${BACKUP_TIMESTAMP}" "${PAM_SSHD_FILE}"
            fi
            rm -f "${SSHD_CONFIG_DIR}/99-qqauth.conf"
            exit 1
        fi
        info "SSHD 配置语法校验通过！"
    fi

    # 重启 sshd 服务
    if command -v systemctl >/dev/null 2>&1 && systemctl status systemd-journald >/dev/null 2>&1; then
        if systemctl is-active --quiet sshd; then
            systemctl restart sshd
        elif systemctl is-active --quiet ssh; then
            systemctl restart ssh
        fi
        info "SSHD 服务已成功重启！"
    elif command -v service >/dev/null 2>&1; then
        service ssh restart || service sshd restart || true
        info "SSHD 服务已成功重启！"
    else
        warn "未检测到运行中的 systemd/service 管理器，请手动重启 sshd 服务。"
    fi
}

# 7. 完成提示与自锁预防警告
finish_notice() {
    heading "安装配置完成"

    echo -e "${GREEN}${BOLD}恭喜！QQAuth 认证系统已安装部署就绪！${RESET}\n"
    echo -e "• 配置文件路径：${CYAN}${CONFIG_FILE}${RESET}"
    echo -e "• PAM 模块位置：${CYAN}${PAM_INSTALL_PATH}${RESET}"
    echo -e "• 守护进程服务：${CYAN}systemctl status qqauthd${RESET}"
    echo -e "• Socket 通信：${CYAN}/run/qqauthd/auth.sock${RESET} (PAM) | ${CYAN}/run/qqauthd/botipc.sock${RESET} (Bot)"
    echo -e "• 约定 PIN 状态：$( [ "$ENABLE_PIN" = "true" ] && echo -e "${GREEN}已启用 (PIN: ${PIN_CODE})${RESET}" || echo -e "${YELLOW}已禁用${RESET}" )"

    echo -e "\n${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━ ⚠️ 安全自锁预防警告 ⚠️ ━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${YELLOW}1. 请【千万不要立即关闭】当前的 SSH 终端窗口！${RESET}"
    echo -e "2. 请在【另一个新的终端窗口】发起连接测试，确保能正常连入。"
    echo -e "3. 如有任何意外，当前窗口可随时回滚："
    if [ -f "${PAM_SSHD_FILE}.bak.${BACKUP_TIMESTAMP}" ]; then
        echo -e "   回滚命令: ${CYAN}cp ${PAM_SSHD_FILE}.bak.${BACKUP_TIMESTAMP} ${PAM_SSHD_FILE} && rm -f /etc/ssh/sshd_config.d/99-qqauth.conf && systemctl restart sshd${RESET}"
    fi
    echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
}

main() {
    check_root
    check_deps
    build_targets
    interactive_setup
    install_files
    configure_pam_and_sshd
    finish_notice
}

main "$@"
