// Package hosttools 是「宿主环境体检」：把渗透常用的外部工具编成一份目录，
// 逐个探测是否存在、版本是多少，并按需一键安装。
//
// 设计取向：
//   - 目录是**静态白名单**，安装命令只从目录里取，不接受前端传来的任意命令
//     （否则这就是一个「以 root 执行任意 shell」的接口）。
//   - 探测用 exec.LookPath + 一次 `--version`（3 秒超时），结果缓存 30 秒：
//     页面每次刷新都 fork 50 个进程没有意义。
//   - 安装串行执行，逐条回传输出；安装命令本身失败不影响其他工具。
package hosttools

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Tool 是目录里的一件工具。Kind: binary（可执行文件）/ dir（目录，如字典）。
type Tool struct {
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Bin       string   `json:"bin"`
	Category  string   `json:"category"`
	Kind      string   `json:"kind,omitempty"` // 空=binary
	VersionIn []string `json:"-"`              // version 探测参数，空=--version
	Install   string   `json:"-"`              // 安装命令（sh -c），空=无自动安装
	Hint      string   `json:"hint,omitempty"` // 手工安装提示
	Note      string   `json:"note,omitempty"`
	// Offline=true 表示镜像/挂载卷里**已经预置**，断网环境开箱即用。
	// false 表示只能联网安装（apt / go install / pip 都要出网）。
	// 前端据此区分「安装」按钮和「需联网」提示，运维据此判断离线部署缺什么。
	Offline bool `json:"offline"`
}

// preinstalled 是镜像默认预置的工具集合（与 docker/apt-core.txt、
// docker/apt-tools.txt、docker/hostbin/fetch.sh 的 VERSIONS 表保持一致）。
//
// 为什么单独维护：catalog 是「能装什么」的能力清单，不是「装了什么」的事实清单。
// 把两者混在一起，只要 Dockerfile 改了一行，页面就会说谎。这里显式声明基线，
// 探测结果仍然以 exec.LookPath 为准——预置了但探不到，说明镜像构建有问题，
// 页面会显示「应内置但缺失」，而不是假装能离线装。
var preinstalled = map[string]bool{
	// apt 核心层（docker/apt-core.txt）：只放 Debian bookworm 仓库里确实存在的包。
	// feroxbuster / exploitdb 是 Kali 专有包，Debian 源里没有，不能写进清单——
	// 一个包名不存在会让整条 apt install 失败，镜像直接构建不出来。
	"nmap": true, "masscan": true, "nc": true, "socat": true, "curl": true,
	"wget": true, "tcpdump": true, "tshark": true, "fping": true, "arp-scan": true,
	"dig": true, "whois": true, "smbclient": true, "sshpass": true,
	"whatweb": true, "sqlmap": true, "gobuster": true,
	"proxychains4": true,
	// apt 工具层（docker/apt-tools.txt）：体积大、装失败不该拖垮构建，单独循环安装。
	// 它们装在容器可写层，重建容器会丢——run.sh 每次启动按同一份清单补回来。
	"file": true, "strings": true,
	"hashcat": true, "hydra": true, "john": true, "medusa": true,
	"gdb": true, "binwalk": true, "exiftool": true, "aws": true, "xfreerdp": true,
	// Go 二进制层（docker/hostbin/fetch.sh VERSIONS）
	"nuclei": true, "httpx": true, "subfinder": true, "katana": true,
	"dnsx": true, "tlsx": true, "chisel": true, "amass": true,
	// NetExec 烘在底座里（docker/base/Dockerfile）：它的依赖全是 git+GitHub，
	// 受限网络下从页面装必然失败，所以不做成「可自动安装」。
	"nxc": true,
	// ffuf / dalfox 是可选件：镜像里有就装，没有也不阻断构建（见 Dockerfile.hostbin）。
}

// ToolStatus 是探测结果。
type ToolStatus struct {
	Tool
	Present bool   `json:"present"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	// Installable=false 表示目录里没有自动安装命令，只能手工装。
	Installable bool `json:"installable"`
}

// Result 是整轮体检结果。
type Result struct {
	Summary   Summary   `json:"summary"`
	Groups    []Group   `json:"groups"`
	CheckedAt time.Time `json:"checked_at"`
	Platform  string    `json:"platform"`
	// Container 表示 artex 进程跑在容器里。容器里装出来的工具属于「这一层镜像」，
	// 镜像重建就没了——页面要明确告诉用户，别让人以为是宿主装好了。
	Container bool `json:"container"`
	// BinDir 是 go install / pip 实际落地的目录，容器部署建议用 ARTEX_HOSTBIN
	// 指到挂载卷（如 /app/data/hostbin）。
	BinDir string `json:"bin_dir"`
}

type Summary struct {
	Total   int `json:"total"`
	Present int `json:"present"`
	Missing int `json:"missing"`
}

type Group struct {
	Name  string       `json:"name"`
	Tools []ToolStatus `json:"tools"`
}

var (
	cacheMu   sync.Mutex
	cacheAt   time.Time
	cacheData *Result
	cacheTTL  = 30 * time.Second
)

// BinDir 是工具二进制落地的目录。默认 /usr/local/bin（在 PATH 里）；
// 容器部署可设 ARTEX_HOSTBIN=/app/data/hostbin，把工具落到 data 卷上，
// 镜像重建也不会丢。
func BinDir() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_HOSTBIN")); v != "" {
		return v
	}
	return "/usr/local/bin"
}

// inContainer 用 /.dockerenv 判断（docker 与 containerd 都会建这个文件）。
// 不追求覆盖所有容器运行时，只用来决定页面要不要提示「重建即丢」。
func inContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	b, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd")
}

func init() {
	// ARTEX_HOSTBIN 指到挂载卷时，把它加进本进程 PATH：之后所有子进程
	// （agent 的 bash 工具、体检探测）都能直接按名字找到装在那里的工具。
	if v := strings.TrimSpace(os.Getenv("ARTEX_HOSTBIN")); v != "" {
		_ = os.MkdirAll(v, 0o755)
		os.Setenv("PATH", v+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	// ARTEX_HOSTPY 指到挂载卷时（容器部署），pip --prefix 装的 CLI 入口在
	// <prefix>/bin、库在 <prefix>/lib/python3.*/site-packages，两者都要进
	// 本进程环境，否则装完 which 找不到、import 也失败。重建镜像不丢。
	//
	// 注意顺序：bin 必须【追加】到 PATH 末尾，不能像 HOSTBIN 那样前置。
	// pip 生态里有和 Go 工具重名的 CLI——最典型的是 python 的 httpx
	// （pip install impacket 会连带装上），它的入口一旦排在 /usr/local/bin
	// 前面，镜像里预装的 ProjectDiscovery httpx 就永远探测不到，页面显示
	// 「已安装」但跑起来是另一个程序。追加到末尾保证：页面装的（HOSTBIN）
	// > 镜像预装（/usr/local/bin）> pip 入口。python 库本身靠 PYTHONPATH，
	// 与 PATH 顺序无关。
	if v := strings.TrimSpace(os.Getenv("ARTEX_HOSTPY")); v != "" {
		bin := filepath.Join(v, "bin")
		_ = os.MkdirAll(bin, 0o755)
		if cur := os.Getenv("PATH"); cur != "" {
			os.Setenv("PATH", cur+string(os.PathListSeparator)+bin)
		} else {
			os.Setenv("PATH", bin)
		}
		if matches, _ := filepath.Glob(filepath.Join(v, "lib", "python3*", "site-packages")); len(matches) > 0 {
			old := os.Getenv("PYTHONPATH")
			if old != "" {
				os.Setenv("PYTHONPATH", matches[0]+string(os.PathListSeparator)+old)
			} else {
				os.Setenv("PYTHONPATH", matches[0])
			}
		}
	}
}

// Catalog 返回静态目录。安装命令按 Debian/Ubuntu 的 apt 写；其他发行版
// 只在 Hint 里给方向，不假装能装。
func Catalog() []Tool {
	apt := func(pkg string) string { return "apt-get install -y " + pkg }
	goInstall := func(mod string) string {
		return "GOBIN=" + BinDir() + " go install " + mod + "@latest"
	}
	// pip 工具默认装进系统 site-packages（容器重建即丢）；容器部署把
	// ARTEX_HOSTPY 指到挂载卷后用 --prefix 安装，入口与库都落在卷上。
	pipx := func(pkg string) string {
		if v := strings.TrimSpace(os.Getenv("ARTEX_HOSTPY")); v != "" {
			return "pip3 install --break-system-packages --prefix=" + v + " -q " + pkg
		}
		return "pip3 install --break-system-packages -q " + pkg
	}

	tools := []Tool{
		// ---- 网络与主机 ----
		{Key: "nmap", Name: "nmap", Bin: "nmap", Category: "网络与主机", Install: apt("nmap"), Note: "端口/服务识别，-sS 需要 root"},
		{Key: "masscan", Name: "masscan", Bin: "masscan", Category: "网络与主机", Install: apt("masscan"), Note: "大网段快速扫描"},
		{Key: "nc", Name: "netcat", Bin: "nc", Category: "网络与主机", Install: apt("netcat-openbsd")},
		{Key: "socat", Name: "socat", Bin: "socat", Category: "网络与主机", Install: apt("socat")},
		{Key: "curl", Name: "curl", Bin: "curl", Category: "网络与主机", Install: apt("curl")},
		{Key: "wget", Name: "wget", Bin: "wget", Category: "网络与主机", Install: apt("wget")},
		{Key: "tcpdump", Name: "tcpdump", Bin: "tcpdump", Category: "网络与主机", Install: apt("tcpdump")},
		{Key: "tshark", Name: "tshark", Bin: "tshark", Category: "网络与主机", Install: apt("tshark")},
		{Key: "fping", Name: "fping", Bin: "fping", Category: "网络与主机", Install: apt("fping")},
		{Key: "arp-scan", Name: "arp-scan", Bin: "arp-scan", Category: "网络与主机", Install: apt("arp-scan")},

		// ---- 子域与 DNS ----
		{Key: "dig", Name: "dig", Bin: "dig", Category: "子域与 DNS", Install: apt("dnsutils")},
		{Key: "whois", Name: "whois", Bin: "whois", Category: "子域与 DNS", Install: apt("whois")},
		{Key: "subfinder", Name: "subfinder", Bin: "subfinder", Category: "子域与 DNS", Install: goInstall("github.com/projectdiscovery/subfinder/v2/cmd/subfinder")},
		{Key: "amass", Name: "amass", Bin: "amass", Category: "子域与 DNS", Install: goInstall("github.com/owasp-amass/amass/v4/...")},
		{Key: "dnsx", Name: "dnsx", Bin: "dnsx", Category: "子域与 DNS", Install: goInstall("github.com/projectdiscovery/dnsx/cmd/dnsx")},
		{Key: "tlsx", Name: "tlsx", Bin: "tlsx", Category: "子域与 DNS", Install: goInstall("github.com/projectdiscovery/tlsx/cmd/tlsx")},

		// ---- Web 与 API ----
		{Key: "httpx", Name: "httpx", Bin: "httpx", Category: "Web 与 API", Install: goInstall("github.com/projectdiscovery/httpx/cmd/httpx"), Note: "探活/指纹；注意与 python httpx 同名，安装后确认 which"},
		{Key: "katana", Name: "katana", Bin: "katana", Category: "Web 与 API", Install: goInstall("github.com/projectdiscovery/katana/cmd/katana")},
		{Key: "ffuf", Name: "ffuf", Bin: "ffuf", Category: "Web 与 API", VersionIn: []string{"-V"}, Install: goInstall("github.com/ffuf/ffuf/v2")},
		{Key: "gobuster", Name: "gobuster", Bin: "gobuster", Category: "Web 与 API", Install: apt("gobuster")},
		{Key: "feroxbuster", Name: "feroxbuster", Bin: "feroxbuster", Category: "Web 与 API", Hint: "Debian 源无此包；用官方脚本：curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s /usr/local/bin"},
		{Key: "dirsearch", Name: "dirsearch", Bin: "dirsearch", Category: "Web 与 API", Install: pipx("dirsearch")},
		{Key: "nuclei", Name: "nuclei", Bin: "nuclei", Category: "Web 与 API", Install: goInstall("github.com/projectdiscovery/nuclei/v3/cmd/nuclei")},
		{Key: "nikto", Name: "nikto", Bin: "nikto", Category: "Web 与 API", Hint: "Debian 源无 nikto；用官方 Perl 版：git clone https://github.com/sullo/nikto /opt/nikto"},
		{Key: "whatweb", Name: "whatweb", Bin: "whatweb", Category: "Web 与 API", Install: apt("whatweb")},
		{Key: "wafw00f", Name: "wafw00f", Bin: "wafw00f", Category: "Web 与 API", Install: pipx("wafw00f")},
		{Key: "sqlmap", Name: "sqlmap", Bin: "sqlmap", Category: "Web 与 API", Install: apt("sqlmap")},
		{Key: "dalfox", Name: "dalfox", Bin: "dalfox", Category: "Web 与 API", VersionIn: []string{"version"}, Install: goInstall("github.com/hahwul/dalfox/v2")},

		// ---- 注入与利用 ----
		{Key: "hydra", Name: "hydra", Bin: "hydra", Category: "注入与利用", Install: apt("hydra")},
		{Key: "medusa", Name: "medusa", Bin: "medusa", Category: "注入与利用", Install: apt("medusa")},
		{Key: "john", Name: "john", Bin: "john", Category: "注入与利用", Install: apt("john")},
		{Key: "hashcat", Name: "hashcat", Bin: "hashcat", Category: "注入与利用", Install: apt("hashcat")},
		{Key: "searchsploit", Name: "searchsploit", Bin: "searchsploit", Category: "注入与利用", Hint: "exploitdb 是 Kali 源专有包；Debian 下改用 apt 源 kali-archive-keyring 或手工放 /usr/share/exploitdb"},
		{Key: "msfconsole", Name: "metasploit", Bin: "msfconsole", Category: "注入与利用", Install: "", Hint: "官方源安装：https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"},

		// ---- 后渗透 ----
		{Key: "impacket", Name: "impacket (secretsdump.py)", Bin: "secretsdump.py", Category: "后渗透", Install: pipx("impacket"), Note: "smbexec/wmiexec/secretsdump 一族"},
		{Key: "nxc", Name: "netexec", Bin: "nxc", Category: "后渗透", Hint: "镜像已内置 v1.5.1。升级：pip3 install --break-system-packages -U git+https://github.com/Pennyw0rth/NetExec@v1.5.1（需能访问 GitHub）"},
		{Key: "evil-winrm", Name: "evil-winrm", Bin: "evil-winrm", Category: "后渗透", Hint: "Debian 源无此包；用 gem install evil-winrm（需 ruby）"},
		{Key: "chisel", Name: "chisel", Bin: "chisel", Category: "后渗透", Install: goInstall("github.com/jpillora/chisel")},
		{Key: "ligolo-ng", Name: "ligolo-ng (proxy)", Bin: "ligolo-proxy", Category: "后渗透", Install: "", Hint: "下载 release：https://github.com/nicocha30/ligolo-ng/releases"},
		{Key: "proxychains4", Name: "proxychains4", Bin: "proxychains4", Category: "后渗透", Install: apt("proxychains4")},
		{Key: "sshpass", Name: "sshpass", Bin: "sshpass", Category: "后渗透", Install: apt("sshpass")},
		{Key: "smbclient", Name: "smbclient", Bin: "smbclient", Category: "后渗透", Install: apt("smbclient")},
		{Key: "xfreerdp", Name: "xfreerdp", Bin: "xfreerdp", Category: "后渗透", Install: apt("freerdp2-x11")},
		{Key: "bloodhound-python", Name: "bloodhound-python", Bin: "bloodhound-python", Category: "后渗透", Install: pipx("bloodhound")},

		// ---- 逆向与取证 ----
		{Key: "strings", Name: "strings", Bin: "strings", Category: "逆向与取证", Install: apt("binutils")},
		{Key: "file", Name: "file", Bin: "file", Category: "逆向与取证", Install: apt("file")},
		{Key: "binwalk", Name: "binwalk", Bin: "binwalk", Category: "逆向与取证", Install: apt("binwalk")},
		{Key: "exiftool", Name: "exiftool", Bin: "exiftool", Category: "逆向与取证", Install: apt("libimage-exiftool-perl")},
		{Key: "gdb", Name: "gdb", Bin: "gdb", Category: "逆向与取证", Install: apt("gdb")},
		{Key: "radare2", Name: "radare2", Bin: "r2", Category: "逆向与取证", Hint: "bookworm 已移除 radare2；用官方脚本 https://github.com/radareorg/radare2/blob/master/sys/install.sh"},

		// ---- 容器与云 ----
		{Key: "docker", Name: "docker", Bin: "docker", Category: "容器与云", Install: "", Hint: "按官方文档装 docker-ce；本机若已在容器里跑，可能没有宿主机 docker"},
		{Key: "kubectl", Name: "kubectl", Bin: "kubectl", Category: "容器与云", Install: "", Hint: "https://kubernetes.io/docs/tasks/tools/"},
		{Key: "aws", Name: "awscli", Bin: "aws", Category: "容器与云", Install: apt("awscli")},

		// ---- 语料 ----
		{Key: "seclists", Name: "SecLists 字典", Bin: "/usr/share/seclists", Category: "语料", Kind: "dir", Hint: "Debian 源无此包；git clone https://github.com/danielmiessler/SecLists /usr/share/seclists（约 2.5G）"},
		{Key: "nuclei-templates", Name: "nuclei 模板", Bin: filepath.Join(homeDir(), "nuclei-templates"), Category: "语料", Kind: "dir", Install: "nuclei -update-templates", Note: "nuclei 首次运行也会自动拉"},
	}
	// 基线标记：与 docker/apt-core.txt、docker/hostbin/fetch.sh 对齐。
	// 只影响页面提示，不改变探测结果。
	for i := range tools {
		tools[i].Offline = preinstalled[tools[i].Key]
		// NetExec 只在 amd64 底座里（arm64 构建跳过，见 docker/base/Dockerfile）。
		// 不按架构收口的话，arm64 用户的页面会一直显示「应内置但缺失」。
		if tools[i].Key == "nxc" && runtime.GOARCH != "amd64" {
			tools[i].Offline = false
		}
	}
	return tools
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "/root"
}

// Detect 返回体检结果（带 30 秒缓存）。
func Detect(force bool) *Result {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if !force && cacheData != nil && time.Since(cacheAt) < cacheTTL {
		return cacheData
	}
	tools := Catalog()
	// 并发探测：55 件工具里缺失的很快（LookPath 失败），装着的要跑一次
	// --version（最多 3s）。串行最坏 60s+，页面首屏会等到超时；8 路并发压到 10s 内。
	type probeResult struct {
		idx int
		st  ToolStatus
	}
	results := make([]ToolStatus, len(tools))
	ch := make(chan probeResult, len(tools))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, t := range tools {
		wg.Add(1)
		go func(i int, t Tool) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ch <- probeResult{idx: i, st: probe(t)}
		}(i, t)
	}
	wg.Wait()
	close(ch)
	for r := range ch {
		results[r.idx] = r.st
	}
	byCat := map[string][]ToolStatus{}
	for _, st := range results {
		byCat[st.Category] = append(byCat[st.Category], st)
	}
	res := &Result{
		CheckedAt: time.Now(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Container: inContainer(),
		BinDir:    BinDir(),
	}
	names := make([]string, 0, len(byCat))
	for name := range byCat {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		list := byCat[name]
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		res.Groups = append(res.Groups, Group{Name: name, Tools: list})
		res.Summary.Total += len(list)
		for _, t := range list {
			if t.Present {
				res.Summary.Present++
			} else {
				res.Summary.Missing++
			}
		}
	}
	cacheData, cacheAt = res, time.Now()
	return res
}

func probe(t Tool) ToolStatus {
	st := ToolStatus{Tool: t, Installable: strings.TrimSpace(t.Install) != ""}
	if t.Kind == "dir" {
		if info, err := os.Stat(t.Bin); err == nil && info.IsDir() {
			st.Present, st.Path = true, t.Bin
		}
		return st
	}
	if path, err := exec.LookPath(t.Bin); err == nil {
		st.Present, st.Path = true, path
		st.Version = toolVersion(path, t.VersionIn)
	}
	return st
}

// toolVersion 跑一次 `--version`（或目录里指定的参数）取版本行，3 秒超时。
// 很多工具把版本打到 stderr，两个流都收。
//
// 取哪一行：优先【含语义化版本号的那行】，而不是机械取首行——ProjectDiscovery
// 这一族（nuclei/httpx/subfinder/katana/dnsx/tlsx）的 `--version` 先打一段
// ASCII banner，首行往往是空行或 `__  __` 这种装饰，直接取首行会让页面显示
// 空白或乱码，用户据此会误判「这个工具没装好」。没有版本号格式的输出（自研
// 脚本、打印自定义头的工具）退回首个非空行。
func toolVersion(path string, args []string) string {
	if len(args) == 0 {
		args = []string{"--version"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if text == "" && err != nil {
		return ""
	}
	var first string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if first == "" {
			first = line
		}
		if reVersionLine.MatchString(line) {
			return clipVersionLine(line)
		}
	}
	if first == "" {
		return ""
	}
	return clipVersionLine(first)
}

// reVersionLine 认「v1.2.3 / 1.2.3 / 1.2」这类版本号（前后可以有词）。
// 只用于挑行，不做严格解析——挑错最多是显示不好看，不影响任何判定。
var reVersionLine = regexp.MustCompile(`\bv?\d+\.\d+(\.\d+)?\b`)

// clipVersionLine 截到 120 字节以内（页面一格放不下更长的）。
func clipVersionLine(line string) string {
	if len(line) > 120 {
		line = line[:120]
	}
	return strings.TrimSpace(line)
}

// InstallItem 是单件工具的安装结果。
type InstallItem struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	State  string `json:"state"` // running | done | failed | skipped
	Output string `json:"output,omitempty"`
}

// Job 是一次「一键装齐」。串行执行，前端轮询状态。
type Job struct {
	ID         string        `json:"id"`
	State      string        `json:"state"` // running | done
	Items      []InstallItem `json:"items"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at,omitempty"`
	Err        string        `json:"error,omitempty"`
}

var (
	jobsMu sync.Mutex
	jobs   = map[string]*Job{}
)

// GetJob 返回任务快照（拷贝，避免调用方与后台协程互相踩）。
func GetJob(id string) *Job {
	jobsMu.Lock()
	defer jobsMu.Unlock()
	j, ok := jobs[id]
	if !ok {
		return nil
	}
	cp := *j
	cp.Items = append([]InstallItem(nil), j.Items...)
	return &cp
}

// Install 按 key 串行安装。未知 key、无自动安装命令的都记为 skipped。
// 安装动作以当前进程身份执行——本平台按 root 部署，这就是「特权运行」的前提；
// 若以普通用户跑，apt 会失败并在输出里体现。
func Install(keys []string) *Job {
	byKey := map[string]Tool{}
	for _, t := range Catalog() {
		byKey[t.Key] = t
	}
	job := &Job{ID: fmt.Sprintf("ht%d", time.Now().UnixNano()), State: "running", StartedAt: time.Now()}
	for _, k := range keys {
		item := InstallItem{Key: k, State: "skipped"}
		if t, ok := byKey[k]; ok {
			item.Name = t.Name
		}
		job.Items = append(job.Items, item)
	}
	jobsMu.Lock()
	jobs[job.ID] = job
	jobsMu.Unlock()

	go func() {
		for i, item := range job.Items {
			t, ok := byKey[item.Key]
			if !ok || strings.TrimSpace(t.Install) == "" {
				jobsMu.Lock()
				job.Items[i].State = "skipped"
				if !ok {
					job.Items[i].Output = "目录里没有这件工具"
				} else {
					job.Items[i].Output = "没有自动安装命令，见 hint"
				}
				jobsMu.Unlock()
				continue
			}
			jobsMu.Lock()
			job.Items[i].State = "running"
			jobsMu.Unlock()

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			cmd := exec.CommandContext(ctx, "sh", "-c", t.Install)
			cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			out, err := cmd.CombinedOutput()
			cancel()
			text := strings.TrimSpace(string(out))
			if len(text) > 4000 {
				text = text[len(text)-4000:]
			}
			jobsMu.Lock()
			if err != nil {
				job.Items[i].State = "failed"
				if text == "" {
					text = err.Error()
				}
			} else {
				job.Items[i].State = "done"
			}
			job.Items[i].Output = text
			jobsMu.Unlock()
		}
		jobsMu.Lock()
		job.State = "done"
		job.FinishedAt = time.Now()
		jobsMu.Unlock()
		cacheMu.Lock()
		cacheData = nil // 装完让下次体检重新探测
		cacheMu.Unlock()
	}()
	return job
}
