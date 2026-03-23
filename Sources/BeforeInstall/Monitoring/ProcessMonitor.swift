import Foundation

struct ProcessEntry {
    var pid: Int
    var ppid: Int
    var commandLine: String
}

final class ProcessMonitor {
    private let commandRunner: CommandRunning

    init(commandRunner: CommandRunning) {
        self.commandRunner = commandRunner
    }

    func snapshotProcesses() -> [ProcessEntry] {
        switch commandRunner.run(executable: "/bin/ps", arguments: ["-axo", "pid=,ppid=,command="]) {
        case let .success(result):
            return parsePSOutput(result.stdout)
        case .failure:
            return []
        }
    }

    func descendantPIDs(rootPID: Int, from entries: [ProcessEntry]) -> Set<Int> {
        var descendants: Set<Int> = [rootPID]
        var changed = true

        while changed {
            changed = false
            for entry in entries where descendants.contains(entry.ppid) && !descendants.contains(entry.pid) {
                descendants.insert(entry.pid)
                changed = true
            }
        }

        return descendants
    }

    func collectOpenFiles(for pids: Set<Int>) -> [String] {
        guard !pids.isEmpty else { return [] }
        let pidArg = pids.sorted().map(String.init).joined(separator: ",")

        switch commandRunner.run(executable: "/usr/sbin/lsof", arguments: ["-w", "-n", "-P", "-p", pidArg]) {
        case let .success(result):
            return parseLsofFiles(result.stdout)
        case .failure:
            return []
        }
    }

    private func parsePSOutput(_ output: String) -> [ProcessEntry] {
        output
            .split(whereSeparator: \ .isNewline)
            .compactMap { line in
                let raw = String(line).trimmingCharacters(in: .whitespaces)
                guard !raw.isEmpty else { return nil }

                let comps = raw.split(maxSplits: 2, whereSeparator: { $0 == " " || $0 == "\t" })
                guard comps.count >= 3,
                      let pid = Int(comps[0]),
                      let ppid = Int(comps[1])
                else {
                    return nil
                }

                return ProcessEntry(pid: pid, ppid: ppid, commandLine: String(comps[2]))
            }
    }

    private func parseLsofFiles(_ output: String) -> [String] {
        var files: [String] = []
        let lines = output.split(whereSeparator: \ .isNewline).map(String.init)
        guard lines.count > 1 else { return [] }

        for line in lines.dropFirst() {
            let cols = line.split(whereSeparator: \ .isWhitespace).map(String.init)
            guard let name = cols.last, name.hasPrefix("/") else {
                continue
            }
            files.append(name)
        }

        return files.uniquePreservingOrder()
    }
}
