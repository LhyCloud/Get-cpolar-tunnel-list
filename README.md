# cpolar 隧道列表 + 一键打开

单文件脚本 **`cpolar_tunnels.py`**（另有打包好的 **`cpolar_tunnels.exe`**），只用 Python 标准库
（3.7+ 实测通过，无需 pip 安装任何东西）。运行后抓取 cpolar 账号下的隧道列表，
用 **↑/↓ 选中、回车直接打开**。

```
cpolar 隧道列表  账号: you@example.com  抓取时间: 2026-10-10 23:05:08  共 3 条
------------------------------------------------------------------------------------------
▸ remoteDesktop  cn_vip  tcp://127.0.0.1:3389    tcp://12.tcp.vip.cpolar.cn:12345
  tunnel-1       cn_vip  http://localhost:12345  https://xxxxxxxx.r21.vip.cpolar.cn
                                                 http://xxxxxxxx.r21.vip.cpolar.cn
  AList          cn_top  http://localhost:80     https://xxxxxxxx.r36.cpolar.top
                                                 http://xxxxxxxx.r36.cpolar.top
------------------------------------------------------------------------------------------
↑/↓ 选择   Enter 打开（https 优先 / 本机 3389 走远程桌面）   h 用 http 打开   c 复制地址   o 打印地址   r 刷新   q 退出
```

## 账号存储

账号密码、登录 Cookie、限速状态统一放在**程序同级的单个外部文件** `cpolar_config.json`：

```json
{
  "email": "you@example.com",
  "password": "********",
  "cookies": [ ... 登录会话，自动维护 ... ],
  "state":   { "last_request_ts": 0, "last_login_ok_ts": 0 }
}
```

* 第一次运行如果文件里没有账号，会提示输入（密码不回显）并自动保存；
* 直接跑 .py 时该文件在脚本所在目录；跑 exe 时在 **exe 所在目录**；
* 想换账号：`--set-account`；也可以用 `--config 路径` 指定别的文件，或用环境变量
  `CPOLAR_EMAIL` / `CPOLAR_PASSWORD` 临时覆盖
  （优先级：命令行 > 环境变量 > 配置文件 > 交互输入）；
* **这个文件等于账号+会话凭据，别外传、别提交到 git。**

## 打包成单文件 exe

成品就是本目录下的 **`cpolar_tunnels.exe`**（约 5 MB，双击或命令行运行都可以），
它和 `cpolar_tunnels.py`、`cpolar_config.json` 放在同一目录，开箱即用。自己重新打包：

```powershell
python -m PyInstaller --onefile --console --name cpolar_tunnels ^
  --distpath dist --workpath build --specpath build --noconfirm --clean cpolar_tunnels.py
```

打包注意事项：

* **不要**加 `--add-data` 把 `cpolar_config.json` 打进 exe；脚本也没有以资源方式引用它，
  所以 exe 里只有代码，不含任何账号、Cookie、隧道数据；
* exe 里配置文件的路径是 **exe 自身所在目录**（脚本用 `sys.frozen` + `sys.executable` 判断，
  避免落到 PyInstaller 的一次性临时解包目录，那样配置会被立刻删掉）；
* 自检命令（搜不到就说明没打进去）：

  ```powershell
  findstr /m /c:"你的邮箱" cpolar_tunnels.exe    # 无输出 = 干净
  ```

* exe 别放在只读目录（如 `C:\Program Files`），否则写不了配置文件；
* 单文件 exe 启动时会先把运行时解压到系统临时目录（`%TEMP%`）。如果所在环境限制了
  `%TEMP%` 写入，先 `set TMP=可写目录` 再运行即可；
* PyInstaller 产物偶尔被杀软误报，加白名单即可；exe 体积约 5 MB 属正常（内含 Python 运行时）。

## 回车键打开规则

| 隧道类型 | 动作 |
| --- | --- |
| 有 https 公网地址 | 默认浏览器打开 **https**（`h` 键可改用 http 打开） |
| 本机 `3389` 的 TCP 隧道 | `mstsc /v:公网主机:端口` 打开远程桌面 |
| 其它 TCP 隧道 | 没有通用打开方式，复制地址到剪贴板 |
| http 隧道（无 https） | 默认浏览器打开 http |

其它按键：`c` 复制地址、`o` 在状态行打印地址、`r` 刷新列表、`q`/`Esc` 退出。

## 常用参数

```
--set-account           重新输入并保存账号密码
--json                  只输出 JSON（脚本调用，不进菜单）
-o, --output FILE       结果写入 JSON 文件
--no-menu               只打印表格，不进菜单（stdout 不是终端时也自动走这里）
--dry-run               只显示将要执行的动作，不真的打开浏览器/远程桌面
--dump-html FILE        保存 /status 原始页面，页面改版时排查解析
--config FILE           指定配置文件
--min-interval SEC      请求最小间隔，默认 20（防高频访问）
--login-backoff SEC     登录失败退避，默认 600
--force                 忽略最小请求间隔
--timeout SEC           请求超时，默认 25
--insecure              跳过 HTTPS 证书校验
--keys "down,enter,q"   自动测试用：脚本化按键序列，配合 --dry-run 不产生副作用
-v / -q                 更啰嗦 / 静默
```

退出码：`0` 成功 / `2` 登录失败 / `3` 未解析到隧道 / `4` 被本地限速拦下 / `5` 网络错误。

## 实现原理（为什么是解析 HTML）

* cpolar 控制台**没有可用的 JSON 接口**：实测 `GET https://dashboard.cpolar.com/api/tunnels` → `404 Not Found`。
* 隧道列表只在需要登录的 `https://dashboard.cpolar.com/status` 页面的
  `<table class="table table-sm">` 里，表头 `隧道名称 | URL | 地区 | 本地地址 | 创建时间`。
* 登录流程：`GET /login` 取隐藏域 `csrf_token` → `POST /login`（`login`/`password`/`csrf_token`）
  → 带会话 Cookie 再取 `/status`。
* 解析用标准库 `html.parser` 自写的迷你表格解析器（不依赖 bs4）；同名隧道的 http / https
  两行合并成一条，地址去重排序（https 优先）。
* TCP 隧道在页面里是 `<a href="#ZgotmplZ">`（Go 模板把 `tcp://` 转义了），脚本退回读单元格文本，
  所以 `tcp://12.tcp.vip.cpolar.cn:12345` 这样的地址也能正确拿到。

## 防封号设计

| 机制 | 说明 |
| --- | --- |
| Cookie 持久化在配置文件里 | 正常运行时 0 次登录请求，只发 1 个 `/status` 请求 |
| `--min-interval` 默认 20 秒 | 间隔不足直接拒绝发请求并退出码 4（`r` 刷新同样受约束） |
| 登录失败退避默认 600 秒 | 避免连续失败触发验证码/风控 |
| 每次运行最多登录 1 次 | 不做任何自动重试；登录后仍被跳回登录页就放弃本轮 |

## 定时/脚本用法

不需要菜单时用 `--json` 或 `--no-menu`，例如 Windows 计划任务每 5 分钟存一次结果：

```powershell
schtasks /create /tn "cpolar tunnels" /sc minute /mo 5 /tr ^
  "D:\DSH\cpolar-tools\cpolar_tunnels.exe --json -o D:\DSH\cpolar-tools\tunnels.json"
```

页面改版会导致解析失败（退出码 3），加 `--dump-html page.html` 存下页面即可对照修解析。
