import Foundation
import Darwin

final class NetworkMonitor {
    private let commandRunner: CommandRunning

    init(commandRunner: CommandRunning) {
        self.commandRunner = commandRunner
    }

    func collectConnectionRecords(for pids: Set<Int>, timestamp: Date = Date()) -> [NetworkConnectionRecord] {
        guard !pids.isEmpty else { return [] }
        let pidArg = pids.sorted().map(String.init).joined(separator: ",")

        switch commandRunner.run(executable: "/usr/sbin/lsof", arguments: ["-w", "-n", "-P", "-i", "-p", pidArg]) {
        case let .success(result):
            return parseConnectionRecords(result.stdout, timestamp: timestamp)
        case .failure:
            return []
        }
    }

    func collectConnections(for pids: Set<Int>) -> [NetworkObservation] {
        let records = collectConnectionRecords(for: pids)
        guard !records.isEmpty else { return [] }

        var counter: [String: (count: Int, first: Date?, last: Date?)] = [:]
        for record in records {
            let key = "\(record.protocolName)|\(record.destination)|\(record.port)"
            if var existing = counter[key] {
                existing.count += 1
                existing.last = maxDate(existing.last, record.timestamp)
                existing.first = minDate(existing.first, record.timestamp)
                counter[key] = existing
            } else {
                counter[key] = (1, record.timestamp, record.timestamp)
            }
        }

        return counter.map { key, value in
            let parts = key.split(separator: "|", maxSplits: 2).map(String.init)
            return NetworkObservation(
                endpoint: parts.count > 1 ? parts[1] : "unknown",
                port: parts.count > 2 ? parts[2] : "?",
                proto: parts.first ?? "unknown",
                count: value.count,
                firstSeenAt: value.first,
                lastSeenAt: value.last
            )
        }
        .sorted { $0.count > $1.count }
    }

    private func parseConnectionRecords(_ output: String, timestamp: Date) -> [NetworkConnectionRecord] {
        let lines = output.split(whereSeparator: \ .isNewline).map(String.init)
        guard lines.count > 1 else { return [] }

        var records: [NetworkConnectionRecord] = []
        var seenKeys = Set<String>()

        for line in lines.dropFirst() {
            let cols = line.split(whereSeparator: \ .isWhitespace).map(String.init)
            guard cols.count >= 9 else { continue }
            guard let pid = Int(cols[1]) else { continue }

            let processName = cols[0]
            let proto = cols[7]
            let nameField = cols.dropFirst(8).joined(separator: " ")
            let endpointRaw = nameField.split(separator: " ").first.map(String.init) ?? cols[8]
            let state = parseState(from: nameField)

            let destinationRaw: String
            if let arrow = endpointRaw.range(of: "->") {
                destinationRaw = String(endpointRaw[arrow.upperBound...])
            } else {
                destinationRaw = endpointRaw
            }

            let cleanedDestination = cleanEndpoint(destinationRaw)
            let hostPort = parseHostPort(cleanedDestination)
            let host = hostPort.host
            let port = hostPort.port
            let destinationIP = looksLikeIPAddress(host) ? host : nil
            let dnsDomain = (!looksLikeIPAddress(host) && host != "*" && !host.isEmpty) ? host : nil
            let isRemote = isRemoteHost(host)

            let dedupeKey = "\(processName)|\(pid)|\(proto)|\(cleanedDestination)|\(port)|\(state ?? "")"
            if seenKeys.contains(dedupeKey) {
                continue
            }
            seenKeys.insert(dedupeKey)

            records.append(
                NetworkConnectionRecord(
                    timestamp: timestamp,
                    processName: processName,
                    processID: pid,
                    destination: cleanedDestination,
                    destinationHost: host.isEmpty ? nil : host,
                    destinationIP: destinationIP,
                    port: port,
                    protocolName: proto,
                    whetherRemote: isRemote,
                    dnsDomain: dnsDomain,
                    sourceAddress: nil,
                    sourcePort: nil,
                    transportState: state,
                    bytesSent: nil,
                    bytesReceived: nil
                )
            )
        }

        return records.sorted { lhs, rhs in
            if lhs.timestamp == rhs.timestamp {
                return lhs.processID < rhs.processID
            }
            return lhs.timestamp < rhs.timestamp
        }
    }

    private func parseState(from nameField: String) -> String? {
        guard let start = nameField.range(of: "("),
              let end = nameField.range(of: ")", range: start.upperBound..<nameField.endIndex)
        else {
            return nil
        }
        let state = String(nameField[start.upperBound..<end.lowerBound]).trimmingCharacters(in: .whitespacesAndNewlines)
        return state.isEmpty ? nil : state
    }

    private func cleanEndpoint(_ endpoint: String) -> String {
        endpoint
            .replacingOccurrences(of: "(", with: "")
            .replacingOccurrences(of: ")", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func parseHostPort(_ endpoint: String) -> (host: String, port: String) {
        if endpoint.hasPrefix("["),
           let bracketEnd = endpoint.firstIndex(of: "]")
        {
            let host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<bracketEnd])
            let remaining = endpoint[bracketEnd...]
            if let colon = remaining.firstIndex(of: ":") {
                let port = String(remaining[remaining.index(after: colon)...])
                return (host, port.isEmpty ? "?" : port)
            }
            return (host, "?")
        }

        if let lastColon = endpoint.lastIndex(of: ":") {
            let host = String(endpoint[..<lastColon])
            let port = String(endpoint[endpoint.index(after: lastColon)...])
            return (host, port.isEmpty ? "?" : port)
        }

        return (endpoint, "?")
    }

    private func looksLikeIPAddress(_ host: String) -> Bool {
        if host.isEmpty { return false }
        var ipv4Addr = in_addr()
        var ipv6Addr = in6_addr()
        if inet_pton(AF_INET, host, &ipv4Addr) == 1 {
            return true
        }
        if inet_pton(AF_INET6, host, &ipv6Addr) == 1 {
            return true
        }
        return false
    }

    private func isRemoteHost(_ host: String) -> Bool {
        let lower = host.lowercased()
        if lower.isEmpty || lower == "*" || lower == "localhost" || lower == "127.0.0.1" || lower == "::1" {
            return false
        }
        if lower.hasPrefix("127.") || lower.hasPrefix("0.0.0.0") {
            return false
        }
        return true
    }

    private func minDate(_ lhs: Date?, _ rhs: Date?) -> Date? {
        switch (lhs, rhs) {
        case let (l?, r?):
            return min(l, r)
        case let (l?, nil):
            return l
        case let (nil, r?):
            return r
        default:
            return nil
        }
    }

    private func maxDate(_ lhs: Date?, _ rhs: Date?) -> Date? {
        switch (lhs, rhs) {
        case let (l?, r?):
            return max(l, r)
        case let (l?, nil):
            return l
        case let (nil, r?):
            return r
        default:
            return nil
        }
    }
}
