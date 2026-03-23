import Foundation
import Darwin

struct CommandResult {
    var commandDescription: String
    var exitCode: Int32
    var stdout: String
    var stderr: String

    var combinedOutput: String {
        if stderr.isEmpty { return stdout }
        if stdout.isEmpty { return stderr }
        return "\(stdout)\n\(stderr)"
    }

    var succeeded: Bool {
        exitCode == 0
    }
}

enum ShellCommandError: LocalizedError {
    case launchFailed(String)

    var errorDescription: String? {
        switch self {
        case let .launchFailed(message):
            return "命令执行失败：\(message)"
        }
    }
}

protocol CommandRunning {
    func run(executable: String, arguments: [String]) -> Result<CommandResult, ShellCommandError>
    func runShell(_ command: String) -> Result<CommandResult, ShellCommandError>
}

private final class OutputAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private let maxBytes: Int

    private var stdoutData = Data()
    private var stderrData = Data()
    private var stdoutTruncated = false
    private var stderrTruncated = false

    init(maxBytes: Int) {
        self.maxBytes = maxBytes
    }

    func appendStdout(_ data: Data) {
        append(data, isStdout: true)
    }

    func appendStderr(_ data: Data) {
        append(data, isStdout: false)
    }

    func snapshot() -> (stdout: Data, stderr: Data, stdoutTruncated: Bool, stderrTruncated: Bool) {
        lock.lock()
        defer { lock.unlock() }
        return (stdoutData, stderrData, stdoutTruncated, stderrTruncated)
    }

    private func append(_ data: Data, isStdout: Bool) {
        guard !data.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }

        if isStdout {
            appendData(data, target: &stdoutData, truncated: &stdoutTruncated)
        } else {
            appendData(data, target: &stderrData, truncated: &stderrTruncated)
        }
    }

    private func appendData(_ data: Data, target: inout Data, truncated: inout Bool) {
        let remaining = max(0, maxBytes - target.count)
        if remaining <= 0 {
            truncated = true
            return
        }

        if data.count > remaining {
            target.append(data.prefix(remaining))
            truncated = true
        } else {
            target.append(data)
        }
    }
}

final class ShellCommandService: CommandRunning {
    private let defaultTimeoutSeconds: TimeInterval = 45
    private let maxCapturedOutputBytes = 2 * 1024 * 1024

    func run(executable: String, arguments: [String]) -> Result<CommandResult, ShellCommandError> {
        let commandDescription = ([executable] + arguments).joined(separator: " ")
        return execute(executable: executable, arguments: arguments, commandDescription: commandDescription)
    }

    func runShell(_ command: String) -> Result<CommandResult, ShellCommandError> {
        execute(executable: "/bin/zsh", arguments: ["-lc", command], commandDescription: command)
    }

    func shellEscape(_ value: String) -> String {
        let escaped = value.replacingOccurrences(of: "'", with: "'\\''")
        return "'\(escaped)'"
    }

    private func execute(executable: String, arguments: [String], commandDescription: String) -> Result<CommandResult, ShellCommandError> {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let output = OutputAccumulator(maxBytes: maxCapturedOutputBytes)

        stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            output.appendStdout(chunk)
        }

        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else { return }
            output.appendStderr(chunk)
        }

        do {
            let terminated = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in
                terminated.signal()
            }

            try process.run()

            var timedOut = false
            if terminated.wait(timeout: .now() + defaultTimeoutSeconds) == .timedOut {
                timedOut = true
                process.terminate()
                if terminated.wait(timeout: .now() + 2) == .timedOut {
                    process.interrupt()
                    if process.isRunning {
                        kill(process.processIdentifier, SIGKILL)
                    }
                    _ = terminated.wait(timeout: .now() + 2)
                }
            }

            stdoutPipe.fileHandleForReading.readabilityHandler = nil
            stderrPipe.fileHandleForReading.readabilityHandler = nil

            let remainingStdout = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
            let remainingStderr = stderrPipe.fileHandleForReading.readDataToEndOfFile()

            output.appendStdout(remainingStdout)
            output.appendStderr(remainingStderr)

            stdoutPipe.fileHandleForReading.closeFile()
            stderrPipe.fileHandleForReading.closeFile()

            let snapshot = output.snapshot()
            var stdout = String(data: snapshot.stdout, encoding: .utf8) ?? ""
            var stderr = String(data: snapshot.stderr, encoding: .utf8) ?? ""

            if snapshot.stdoutTruncated {
                stdout += "\n[truncated: stdout exceeded \(maxCapturedOutputBytes) bytes]"
            }
            if snapshot.stderrTruncated {
                stderr += "\n[truncated: stderr exceeded \(maxCapturedOutputBytes) bytes]"
            }
            if timedOut {
                let timeoutHint = "Command timeout after \(Int(defaultTimeoutSeconds)) seconds."
                stderr = stderr.isEmpty ? timeoutHint : "\(stderr)\n\(timeoutHint)"
            }

            return .success(
                CommandResult(
                    commandDescription: commandDescription,
                    exitCode: timedOut ? 124 : process.terminationStatus,
                    stdout: stdout.trimmingCharacters(in: .whitespacesAndNewlines),
                    stderr: stderr.trimmingCharacters(in: .whitespacesAndNewlines)
                )
            )
        } catch {
            stdoutPipe.fileHandleForReading.readabilityHandler = nil
            stderrPipe.fileHandleForReading.readabilityHandler = nil
            return .failure(.launchFailed(error.localizedDescription))
        }
    }
}
