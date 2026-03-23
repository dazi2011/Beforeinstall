import Foundation

enum FailureIssueClassifier {
    static func classify(warnings: [String]) -> [FailureIssue] {
        var issues: [FailureIssue] = []

        for warning in warnings {
            let lower = warning.lowercased()

            if lower.contains("codesign") {
                issues.append(
                    issue(
                        code: "codesign_failed",
                        zh: "codesign 调用失败或签名字段不完整",
                        en: "codesign failed or returned incomplete signature fields",
                        suggestionZH: "可先用静态基础分析继续，并检查样本是否损坏或被保护。",
                        suggestionEN: "Continue with baseline static analysis and verify sample integrity/protection.",
                        raw: warning
                    )
                )
                continue
            }

            if lower.contains("spctl") {
                issues.append(
                    issue(
                        code: "spctl_failed",
                        zh: "spctl 校验失败或受系统策略限制",
                        en: "spctl validation failed or was blocked by system policy",
                        suggestionZH: "可尝试授予相关权限或仅参考签名信息。",
                        suggestionEN: "Grant relevant permissions or rely on signature-only evidence.",
                        raw: warning
                    )
                )
                continue
            }

            if lower.contains("permission") || lower.contains("没有权限") || lower.contains("not permitted") {
                issues.append(
                    issue(
                        code: "permission_denied",
                        zh: "读取权限不足",
                        en: "Insufficient permission to read required targets",
                        suggestionZH: "建议授予 Full Disk Access 后重试，或改用静态分析。",
                        suggestionEN: "Grant Full Disk Access and retry, or switch to static analysis.",
                        raw: warning
                    )
                )
                continue
            }

            if lower.contains("hdiutil") || lower.contains("dmg") {
                issues.append(
                    issue(
                        code: "dmg_mount_failed",
                        zh: "DMG 挂载或解析失败",
                        en: "DMG mount or parse failed",
                        suggestionZH: "可先导出日志，确认镜像文件可读且未损坏。",
                        suggestionEN: "Export diagnostics and verify the image is readable and not corrupted.",
                        raw: warning
                    )
                )
                continue
            }

            if lower.contains("launch") && lower.contains("failed") {
                issues.append(
                    issue(
                        code: "dynamic_launch_failed",
                        zh: "动态分析目标未成功启动",
                        en: "Dynamic target failed to launch",
                        suggestionZH: "可改用静态分析或缩短时长后重试。",
                        suggestionEN: "Try static analysis or retry with shorter runtime.",
                        raw: warning
                    )
                )
                continue
            }

            if lower.contains("lsof") || lower.contains("network") {
                issues.append(
                    issue(
                        code: "network_observation_partial",
                        zh: "网络观测结果不完整",
                        en: "Network observation is partial",
                        suggestionZH: "可授予更多权限并重试，或结合静态结果判断。",
                        suggestionEN: "Retry with additional permissions or combine with static signals.",
                        raw: warning
                    )
                )
                continue
            }

            if lower.contains("snapshot") || lower.contains("diff") {
                issues.append(
                    issue(
                        code: "fs_diff_partial",
                        zh: "文件差分监控不完整",
                        en: "File-system diff monitoring is incomplete",
                        suggestionZH: "可导出诊断日志后反馈，当前结论需保守解释。",
                        suggestionEN: "Export diagnostics and treat conclusions as conservative.",
                        raw: warning
                    )
                )
                continue
            }

            issues.append(
                issue(
                    code: "generic_partial",
                    zh: "部分信息无法获取",
                    en: "Some analysis data is unavailable",
                    suggestionZH: "可导出日志并重试，或使用静态+动态联合分析。",
                    suggestionEN: "Export diagnostics and retry, or run combined static+dynamic analysis.",
                    raw: warning
                )
            )
        }

        return issues.uniqueByCodeAndMessage()
    }

    private static func issue(
        code: String,
        zh: String,
        en: String,
        suggestionZH: String,
        suggestionEN: String,
        raw: String
    ) -> FailureIssue {
        FailureIssue(
            code: code,
            titleZH: zh,
            titleEN: en,
            suggestionZH: suggestionZH,
            suggestionEN: suggestionEN,
            rawMessage: raw
        )
    }
}

private extension Array where Element == FailureIssue {
    func uniqueByCodeAndMessage() -> [FailureIssue] {
        var seen = Set<String>()
        return filter { issue in
            let key = "\(issue.code)|\(issue.rawMessage)"
            if seen.contains(key) {
                return false
            }
            seen.insert(key)
            return true
        }
    }
}
