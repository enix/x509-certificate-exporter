package product

import (
	"bytes"
	"fmt"
	"runtime"
	"text/template"
)

const (
	versionTemplate = `Version:    {{.Version}}
Build time: {{.BuildTime}}
Git commit: {{.GitCommit}}
Runtime:    {{.Runtime}}
Platform:   {{.Os}}/{{.Arch}}`
)

var (
	version   = ""
	buildTime = ""
	gitCommit = ""
)

type buildInfo struct {
	Version   string
	BuildTime string
	GitCommit string
	Runtime   string
	Os        string
	Arch      string
}

func BuildInfo() buildInfo {
	info := buildInfo{
		Runtime: runtime.Version(),
		Os:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}

	if len(version) > 0 {
		info.Version = version
	} else {
		info.Version = "0.0.0"
	}

	if len(buildTime) > 0 {
		info.BuildTime = buildTime
	} else {
		info.BuildTime = "unknown"
	}

	if len(gitCommit) > 0 {
		info.GitCommit = gitCommit
	} else {
		info.GitCommit = "unknown"
	}

	return info
}

func (bi buildInfo) Format(short bool) string {
	if short {
		if len(bi.GitCommit) >= 7 {
			suffix := fmt.Sprintf("g%s", bi.GitCommit[:7])
			return fmt.Sprintf("%s+%s", bi.Version, suffix)
		}
		return bi.Version
	}

	var buf bytes.Buffer
	tpl, _ := template.New("").Parse(versionTemplate)
	_ = tpl.Execute(&buf, bi)
	return buf.String()
}

func VariadicBuildInfo() []any {
	info := BuildInfo()
	return []any{
		"version", info.Version,
		"built", info.BuildTime,
		"git_commit", info.GitCommit,
		"go_runtime", info.Runtime,
		"go_os", info.Os,
		"go_arch", info.Arch,
	}
}
