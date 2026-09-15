# 分支状态说明：experimental/agent-sandbox-security-exploration

这个分支是从已关闭的巨型 PR #24（`dev`→`master` 全量对比，见 `docs/superpowers/plans/2026-09-15-pr24-split-plan.md`）里打捞出的 5 个"孤儿提交"，**归档保留，不开 PR，不合并**。

## 为什么单独存档而不进正式 PR

这 5 个提交（`internal/agent/security/`、`internal/agent/audit/`、`internal/agent/sandbox/gvisor.go`+`runner.go`、`cmd/lattice/cmd/sandbox/netns_linux.go`，以及两份"三层防御监控"设计文档）在 `dev` 分支的最终状态里**没有被任何代码引用**——写完之后没有接入 `cmd/lattice/cmd/sandbox/run.go` 等实际调用链。

更关键的是：这批代码写于 2026-05-30，而 dev 分支自己在前一天（5/29）已经把 sandbox 方案从 "gVisor + netns + tproxy" 重构成了 "kernel TUN 直接路由"（那两个 refactor 提交已经确认被 `master` 的 #26 吸收）。这 5 个提交却又引入了一套独立的 gVisor/netns 隔离方案，跟已经采纳的方向相反，也跟 `master` #26 实际落地的 `cmd/lattice/cmd/sandbox/driver_runsc.go` 是两套不同实现。基本可以确定是当时的一次探索性尝试，没有收尾就被搁置了。

## 各部分现状

| 提交 | 内容 | 状态 |
|---|---|---|
| `cmd/lattice/cmd/sandbox/netns_linux.go` | netns+veth 生命周期 helper | 未接线，方向疑似已放弃（kernel TUN 路线胜出） |
| `internal/agent/sandbox/gvisor.go` + `runner.go` | gVisor 自动下载安装、none/gvisor/auto 隔离模式 | 未接线，同上，跟 master #26 的 `driver_runsc.go` 是不同实现 |
| `internal/agent/security/`（SQL注入/路径穿越/危险命令/SSRF 检测）+ `internal/agent/audit/`（JSONL 审计日志） | 完整实现，**带单元测试** | 未接线，代码质量本身不错，如果以后要做 agent 侧安全检测/审计，值得回来参考，但不是"已完成的功能" |
| 两份"AI Agent sandbox 三层防御"设计文档 | 纯设计文档 | 描述的三层防御从未真正按此方案实现 |

## 如果以后想捡回来用

- `internal/agent/security/` + `internal/agent/audit/` 是最值得复用的部分——先确认现在（`master` #26 之后）的 sandbox 实际执行路径是什么，再决定接入点，不要直接原样接线。
- gVisor/netns 那两部分建议重新评估是否还有必要，`master` 已经用 kernel TUN + `driver_runsc.go` 走通了一套方案。
