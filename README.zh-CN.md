# Bolt Sandbox

[English](README.md) | [简体中文](README.zh-CN.md)

Bolt Sandbox 是一个低延迟、通用的 Windows 进程沙箱，面向 AI 编程
Agent、自动化 Worker、构建工具，以及任何需要按宿主策略执行不可信命令或
模型生成命令的程序。

它会以挂起状态创建目标进程，在任何应用代码运行之前安装与目标架构匹配的
用户态 Hook，把不可变策略应用到完整进程树，并向宿主返回类型化事件、原样
保留字节的输出流，以及确定性的终态结果。它不需要递归修改工作区 ACL，不
启动虚拟机，也不要求安装内核驱动。

> [!IMPORTANT]
> Bolt Sandbox 是针对常规 Windows 应用、意外越界和模型生成越界行为的
> 用户态隔离边界。它不是内核安全边界，也不声称能够隔离蓄意使用直接系统
> 调用、移除 Hook、进程篡改、特权 Broker、内核驱动或操作系统漏洞的恶意
> Native 程序。需要对抗恶意二进制时，应使用 AppContainer/BaseContainer
> 或虚拟机后端。

## 项目用途

AI Agent 经常需要运行包管理器、编译器、测试工具、Shell、Git 和用户提供的
程序。适用于这些任务的沙箱不能只做一次单进程 Allow/Deny 判断，它还必须：

- 足够快，能够进入交互式 Agent 循环；
- 在子进程用户代码执行前继承同一隔离边界；
- 统一执行文件系统、注册表、进程和网络策略；
- 避免 stdout、stderr、事件、取消、超时和崩溃清理互相死锁；
- 防止密钥进入子进程环境、策略载荷、事件、日志或保护不足的恢复存储；
- 在组件缺失、协议损坏、注入失败或审计通道丢失时 Fail Closed，绝不降级为
  非沙箱执行。

Bolt Sandbox 通过 Rust 库提供这一 Windows Native 执行边界，并附带一个可选
的轻量 CLI。

## 主要能力

| 领域 | 能力 |
| --- | --- |
| 文件系统 | 读写、只读、仅元数据、继承用户权限和拒绝规则；统一 Win32/NT 路径；覆盖链接、Reparse Point、句柄操作、重命名、删除、截断、内存映射、异步 I/O 和 Shell API。 |
| 进程树 | 挂起启动、入口点前注入；支持 x64/x86 目标和后代；Job Object 清理；超时与取消；Breakaway、提权、弱化 Mitigation 和不支持的 Token 切换 Fail Closed。 |
| 网络 | `Unrestricted`、`Denied`、域名/IP/端口 Allow List；DNS 绑定；IPv4/IPv6；覆盖 Winsock、WinHTTP 和 WinInet；限制模式拒绝不支持的 UDP、Raw Socket 和自定义协议路径。 |
| 注册表 | NT 与 Win32 的打开、查询、枚举、创建、设置、删除、重命名；WOW64 View、符号链接与句柄语义；敏感键强制拒绝；初版拒绝远程与事务注册表操作。 |
| 恢复 | 在允许的破坏性文件操作前进行可选的有界备份；字节、条目和保留期配额；原子 Artifact；子进程归因；目标无法访问恢复命名空间。没有加密存储时不会备份 Secret 路径。 |
| 事件与流 | 有序类型化事件；有界 Native 队列；Rust 重复事件聚合；独立的二进制 stdout/stderr；Receiver Loss 报告；确定性的终态顺序。 |
| 组件信任 | 带版本的 x64/x86 组件集、SHA-256 Manifest、可选宿主 Manifest Digest 固定、文件身份 Lease、可信目录 ACL、Authenticode 和原子打包。 |
| 生产加固 | 凭据路径/注册表键强制拒绝、子进程凭据剥离、进程 Mitigation、协议 Fail Closed、Rust/C++ 确定性 Mutation 测试、资源预算与发布性能门。 |

## 工作原理

```text
Agent / 宿主应用
        |
        | 类型化 SandboxRequest + 宿主拥有的策略
        v
Rust 控制面
  校验 -> 剥离凭据 -> 编译/密封策略 -> 验证组件
        |
        | 私有 launcher-start v2 请求
        v
架构匹配的 Launcher
  创建 Job -> 创建受保护事件管道 -> 挂起启动目标
  -> 注入 Hook -> 验证认证 Ready -> 恢复执行
        |
        +---- stdout / stderr / 类型化事件 ----> Rust 生命周期控制器
        |
        v
目标及其后代
  文件系统 + 注册表 + 进程 + 网络策略执行
```

Rust 负责公共 API、策略编译、组件验证、恢复、事件聚合和生命周期结果。
Native 代码负责最小化 Windows Launcher、基于 Detours 的拦截和有界事件发送。
项目以固定 Revision 使用 BuildXL 路径处理代码和 Microsoft Detours，并保留
上游许可证；不复制任何闭源产品代码。

## 当前状态与性能

当前实现包括 Rust 库与 CLI、x64/x86 Launcher 和 Hook DLL、文件/进程/网络/
注册表策略、有界恢复、事务式 Staged 与可选 ProjFS Workspace、显式 ConPTY、
组件 Manifest、ACL 加固打包、Rust 与 Native 协议 Mutation 测试，以及签名
发布工作流。`Projected` 会启动有界的进程外 Provider，以只读方式提供源内容，
目标退出后固化最终合并视图，再复用可信的 query/commit/discard/revert 协调器。
主机未安装 ProjFS Windows 功能时，会在创建目标前明确失败，绝不回退 Direct。

当前发布预算要求：

- Warm Sandbox 启动低于 100 ms；
- Hook 初始化低于 50 ms；
- 稳态文件系统开销低于 5%；
- Private Bytes、句柄和线程必须配置绝对值与增长上限。

当前代表性工作站的本地发布证据约为 40 ms Warm Startup、4% 稳态文件系统
开销。项目还始终单独记录 Path Churn（每次迭代都做 metadata/open/read/
close），因为最终身份校验存在显著固定成本；该指标不会被隐藏进稳态数字。
不同机器结果会变化，正式发布必须重新采集。

## 在 Agent 中使用

### 1. 一起部署全部运行时组件

Agent 必须把以下文件作为一个整体放到受 ACL 保护、带版本的目录：

- `bolt-sandbox.exe`：可选 CLI；
- `bolt-sandbox-launcher.exe`：x64 Launcher；
- `bolt-sandbox-launcher-x86.exe`：x86 Launcher；
- `bolt-sandbox-x64.dll`：x64 Hook；
- `bolt-sandbox-x86.dll`：x86 Hook；
- `bolt-sandbox-dns-proxy.exe`：仅由 `AllowList` 使用的可信 x64 DNS/TCP
  策略代理；
- `bolt-sandbox-compatibility.profile`：受 Manifest 绑定的只读和元数据只读
  兼容授权；
- `bolt-sandbox-components.manifest`：兼容组件集的版本、长度与 SHA-256 身份。

不要在不同 Release 之间单独复制 DLL。生产宿主应固定 Manifest SHA-256，要求
有效 Authenticode 签名，并禁止沙箱目标写入组件目录。

### 2. Rust Agent 优先使用库 API

当前可从仓库或固定 Git Revision 引用：

```toml
[dependencies]
bolt-sandbox = { git = "https://github.com/upczww/bolt-sandbox", rev = "<commit>" }
```

最小集成示例：

```rust,no_run
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, time::Duration};

use bolt_sandbox::{
    ChildProcessPolicy, DEFAULT_STREAM_CAPACITY,
    DEFAULT_VIOLATION_AGGREGATE_CAPACITY, NetworkPolicy, Sandbox,
    SandboxConfig, SandboxPolicy, SandboxRequest,
};

fn main() {
    let component_root = PathBuf::from(r"C:\Program Files\Bolt\sandbox\0.1.0");
    let workspace = PathBuf::from(r"C:\agent-work\task-123");

    let sandbox = Sandbox::new(SandboxConfig {
        component_root,
        credential_environment_variables: vec![
            OsString::from("OPENAI_API_KEY"),
            OsString::from("ANTHROPIC_API_KEY"),
            OsString::from("GITHUB_TOKEN"),
        ],
        stream_capacity: DEFAULT_STREAM_CAPACITY,
        violation_aggregate_capacity: DEFAULT_VIOLATION_AGGREGATE_CAPACITY,
        mandatory_filesystem_denies: vec![PathBuf::from(r"C:\host-secrets")],
        mandatory_registry_denies: vec![
            String::from(r"HKCU\SOFTWARE\Example\Credentials"),
        ],
        // 生产环境应设置 Some([u8; 32])，固定可信 Manifest。
        component_manifest_sha256: None,
    })
    .expect("valid sandbox configuration");

    let mut policy = SandboxPolicy::default();
    // cwd 自动获得递归读写权限。
    policy.filesystem.read_only.push(PathBuf::from(r"C:\SDK"));
    policy.filesystem.deny.push(PathBuf::from(r"C:\Users\Alice\.ssh"));
    policy.registry.read_only.push(String::from(r"HKCU\SOFTWARE\Example"));
    policy.network = NetworkPolicy::Denied;
    policy.child_processes = ChildProcessPolicy::Inherit;

    let mut handle = sandbox.start(SandboxRequest {
        program: PathBuf::from(r"C:\Program Files\PowerShell\7\pwsh.exe"),
        arguments: vec![
            OsString::from("-NoProfile"),
            OsString::from("-Command"),
            OsString::from("cargo test"),
        ],
        cwd: workspace,
        environment: std::env::vars_os().collect::<BTreeMap<_, _>>(),
        policy,
        timeout: Some(Duration::from_secs(120)),
    })
    .expect("sandbox execution starts");

    // 三个通道必须并发 Drain，再等待终态。
    let stdout = handle.take_stdout().expect("stdout is available");
    let stderr = handle.take_stderr().expect("stderr is available");
    let events = handle.take_events().expect("events are available");
    let (stdout, stderr, events, result) = std::thread::scope(|scope| {
        let out = scope.spawn(|| stdout.flatten().collect::<Vec<_>>());
        let err = scope.spawn(|| stderr.flatten().collect::<Vec<_>>());
        let evt = scope.spawn(|| events.collect::<Vec<_>>());
        let result = handle.wait();
        (
            out.join().expect("stdout reader"),
            err.join().expect("stderr reader"),
            evt.join().expect("event reader"),
            result,
        )
    });
    let result = result.expect("sandbox execution completes");

    println!("stdout bytes: {}", stdout.len());
    println!("stderr bytes: {}", stderr.len());
    println!("public events: {}", events.len());
    println!("violation aggregates: {}", result.violation_aggregates.len());
    println!("terminal: {:?}", result.terminal);
}
```

Agent 集成原则：

1. 由宿主构造 `SandboxPolicy`，不要让 Prompt 或子进程决定策略。
2. 使用独立任务工作区作为 `cwd`；它会自动获得递归读写。
3. 只添加工具链确实需要的窄范围外部授权。
4. 把 Broker/模型凭据变量名放入 `credential_environment_variables`；库会按
   Windows 环境变量语义忽略大小写地剥离它们。
5. 把 Secret 路径和注册表键放在 `SandboxConfig` 的 Mandatory Deny 中，避免
   Request Policy 覆盖。
6. 并发 Drain stdout、stderr、events，然后检查 `ExecutionResult`、Receiver
   Loss、Violation Aggregate 与终态原因。
7. 初始化或基础设施失败必须使 Agent 任务失败，禁止退回直接启动命令。

`ExecutionHandle::cancel()` 会请求取消整个 Job。Request Timeout 同样终止完整
后代树，然后 Drain 终态流。

需要在写回源工作区前审查变更时，使用 `start_with_options` 并设置
`WorkspaceMode::Staged`。命令会在同级、隔离且有配额的副本中运行；完成后的
`ExecutionResult::workspace_transaction` 是事务标识。可信宿主随后可调用
`query_workspace_changes`、`commit_workspace`、`discard_workspace` 或
`revert_workspace`。Commit 前会重新校验源目录，检测到外部修改就拒绝；任何
Mandatory Deny 路径与 Staged Root 重叠时也会在复制和启动前 Fail Closed。

`WorkspaceMode::Projected` 使用相同事务 API，但不预先复制全部源内容。它要求
启用 Windows `Client-ProjFS` 可选组件。Provider、投影固化器和授权校验器都有
配额；源路径与固化路径只在完整性保护的私有 IPC 中传输，不进入命令行或环境。

在管理员 PowerShell 中执行
`Enable-WindowsOptionalFeature -Online -FeatureName Client-ProjFS -NoRestart`
即可启用组件；仅在 Windows 提示时重启。随后用以下命令验证真实 Provider 以及
250 ms Cold / 100 ms Warm 预算：

```powershell
pwsh scripts/verify-projected-workspace.ps1 `
  -ComponentRoot C:\Bolt\sandbox\0.1.0
```

交互工具需要显式选择
`TerminalMode::PseudoConsole(PseudoConsoleSize::new(columns, rows).unwrap())`，
再通过 `ExecutionHandle::write_input` 和 `resize_pseudo_console` 输入及调整窗口。
输入帧和控制队列都有界。默认仍是低开销 Pipe 模式，不创建 ConPTY 资源；
ConPTY 的终端输出统一从 stdout 返回，stderr 会无数据结束。

### 3. 非 Rust Agent 使用 CLI

CLI 委托给同一个 Rust 库，适合其他 Agent Runtime、MCP Tool 或独立 Broker：

```powershell
bolt-sandbox.exe run `
  --component-root C:\Bolt\sandbox\0.1.0 `
  --manifest-sha256 <64-hex-trusted-manifest-digest> `
  --cwd C:\agent-work\task-123 `
  --timeout-ms 120000 `
  --read-only C:\SDK `
  --read-write C:\package-cache `
  --deny C:\host-secrets `
  --registry-read-only HKCU\SOFTWARE\Example `
  --network denied `
  --child-processes inherit `
  -- C:\tools\program.exe argument1 argument2
```

文件策略参数：`--read-write`、`--read-only`、`--deny`、
`--metadata-read`、`--inherit-user`。注册表参数：
`--registry-no-access`、`--registry-read-only`、
`--registry-inherit-user`、`--registry-read-write`。启用恢复时必须同时设置
`--recovery-dir`、`--recovery-max-bytes`、`--recovery-max-items` 和
`--recovery-retention-seconds`。

网络模式包括 `unrestricted`、`denied` 和 `allow-list`。AllowList 使用可重复
指定的 `--allow-domain`、`--allow-cidr`、`--allow-port`；端口可以是单值或
闭区间：

```powershell
bolt-sandbox.exe run `
  --component-root C:\Bolt\sandbox\0.1.0 `
  --cwd C:\agent-work\task-123 `
  --network allow-list `
  --allow-domain example.org `
  --allow-domain *.example.net `
  --allow-cidr 192.0.2.0/24 `
  --allow-port 443 `
  --allow-port 8000-8080 `
  -- C:\Windows\System32\curl.exe --noproxy * https://example.org
```

AllowList 至少需要一条规则。域名授权会在 DNS TTL 内绑定到解析出的 IP 和
发起请求的进程；TCP 目标端口仍独立校验。限制模式下不支持的传输会 Fail
Closed。

CLI 会继承宿主环境，并用内置凭据名列表剥离已知 Broker/模型 Secret。诊断只
输出固定类别与 PID，不输出命令参数、环境值或路径。需要类型化事件、自定义
凭据名、取消和聚合结果时，应优先使用 Rust 库。

## 策略语义

- 规则会被规范化、Canonicalize、去重并执行长度/数量限制，再写入不可变且受
  SHA-256 保护的 Native Payload。
- 更具体的授权可以细化宽泛授权，但显式 Deny 和 Mandatory Deny 优先。
- 子进程输入不能申请 Compatibility Grant，也不能弱化 Mandatory Deny。
- 兼容授权来自受 Manifest 绑定的 `bolt-sandbox-compatibility.profile`，产品
  代码不保存工具专用路径。V1 只支持文件只读、文件元数据只读和注册表只读。
- Profile 仅提供 `system-root`、`program-dir`、`cwd-anchor`、`user-profile`
  等通用宿主基座；Node、Python、Git、Cargo、Rustup 具体路径属于 Profile 数据。
- `NetworkPolicy::Unrestricted` 保留操作系统正常授权行为；`Denied` 与
  `AllowList` 执行限制性网络拦截。
- `ChildProcessPolicy::Inherit` 只在子进程安装匹配 Hook 与策略后允许执行；
  `Deny` 禁止创建子进程。
- Agent Runtime 可以使用自己创建的无名标准输入输出管道。该能力按句柄授权，
  不是路径授权；命名管道、Mailslot、跨进程复制和任意管道命名空间访问仍被拒绝。
- 恢复失败不改变原始 Allow/Deny 决策；允许的破坏性操作继续执行并产生类型化
  Recovery Failure。

完整优先级、协议、生命周期和威胁模型见
[架构文档](docs/architecture/windows-sandbox.md)。

## 构建与测试

前置条件：

- Windows 10/11 或 Windows Server；
- Rust 1.85 或更高版本；
- PowerShell 7；
- Visual Studio Build Tools 2019+，安装 Desktop C++ Workload；
- CMake 与 Windows SDK。

```powershell
# Rust 质量门
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets

# Traceability、上游输入与 x64/x86 Native 构建
pwsh scripts/verify-test-traceability.ps1
pwsh scripts/test-third-party.ps1
pwsh scripts/build-windows.ps1 -Configuration Release -Architecture All

# Native 测试
pwsh scripts/test-windows.ps1 -Suite Unit -Architecture x64 -Configuration Release
pwsh scripts/test-windows.ps1 -Suite Unit -Architecture x86 -Configuration Release

# 真实 Agent Runtime 场景（声明的 Runtime 必须存在）
pwsh scripts/test-agent-scenarios.ps1 `
  -ComponentRoot target\native\x64\Release `
  -PythonPath C:\trusted-runtimes\python\python.exe
```

可选 Rust 覆盖率需要 `cargo-llvm-cov 0.9.0`、Nightly Toolchain 和匹配的
LLVM Tools：

```powershell
rustup toolchain install nightly --profile minimal --component llvm-tools-preview
cargo +stable install cargo-llvm-cov --version 0.9.0 --locked
pwsh scripts/test-rust-coverage.ps1
```

## 打包与签名

```powershell
# 开发包
pwsh scripts/package-windows.ps1 -Version 0.1.0

# 使用不可导出临时证书验证本地严格签名链路
pwsh scripts/test-signing-pipeline.ps1
```

打包器会先签名/验证最终字节，再生成组件 Manifest；随后移除继承 ACL、拒绝
Reparse Point，只允许打包身份、SYSTEM 和 Administrators 修改目录，验证最终
ACL，并把 Staging 目录原子重命名为最终包。

`Signed Windows release` 工作流需要 `WINDOWS_SIGNING_PFX_BASE64`、
`WINDOWS_SIGNING_PFX_PASSWORD` 和 HTTPS RFC3161 时间戳 URL。公开可信发布必须
使用 CA 签发的代码签名证书；临时本地测试签名不是生产签名。

## 已知限制

- 当前运行时仅支持 Windows；Linux 与 macOS 需要不同的执行后端。
- 暂不支持 Windows ARM64/ARM64EC。
- AppContainer/BaseContainer、注册表虚拟化与内核驱动执行后端尚未实现。
- 远程和事务注册表操作会被拒绝，而不是虚拟化。
- 限制网络模式会拒绝不支持的 UDP、Raw Socket、QUIC 和自定义协议栈。
- Secret 文件的加密恢复尚未实现；初版会拒绝对它们进行备份。
- 提权宿主 Token 会被拒绝；Bolt Sandbox 应以非提权方式运行。
- 用户态 Hook 不提供恶意二进制隔离保证。

## 项目文档

- [Windows 架构与安全模型](docs/architecture/windows-sandbox.md)
- [BuildXL 导入与适配边界](docs/architecture/buildxl-import.md)
- [测试策略](docs/testing/test-plan.md)
- [完整行为目录](docs/testing/test-catalog.md)
- [需求追踪矩阵](docs/testing/requirements-matrix.md)
- [Native API 覆盖](docs/testing/api-coverage.md)
- [第三方声明](THIRD_PARTY_NOTICES.md)

## 许可证

Bolt Sandbox 使用 MIT License。Vendored 第三方代码保留上游许可证与固定来源，
详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
