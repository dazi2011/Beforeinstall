import Foundation

final class BenchmarkService {
    private let discoveryService: BenchmarkDiscoveryService
    private let runner: BenchmarkRunner

    init(
        discoveryService: BenchmarkDiscoveryService = BenchmarkDiscoveryService(),
        runner: BenchmarkRunner = BenchmarkRunner()
    ) {
        self.discoveryService = discoveryService
        self.runner = runner
    }

    func discoverSamples(rootURL: URL) throws -> BenchmarkDiscoveryResult {
        try discoveryService.discover(rootURL: rootURL)
    }

    func runBenchmark(
        rootURL: URL,
        language: AppLanguage,
        progress: @escaping @Sendable (BenchmarkRunnerProgress) -> Void
    ) async throws -> BenchmarkRunExecution {
        try await runner.run(rootURL: rootURL, language: language, progress: progress)
    }

    func loadLatestRun(rootURL: URL) -> BenchmarkRun? {
        runner.loadLatestRun(rootURL: rootURL)
    }

    func loadRecentRuns(rootURL: URL, limit: Int = 10) -> [BenchmarkRun] {
        runner.loadRecentRuns(rootURL: rootURL, limit: limit)
    }

    func exportArtifacts(for run: BenchmarkRun, to destinationDirectory: URL) throws -> URL {
        try runner.exportArtifacts(for: run, to: destinationDirectory)
    }

    func exportArtifactPath(for run: BenchmarkRun, artifact: BenchmarkExportArtifact) -> String? {
        runner.exportArtifactPath(for: run, artifact: artifact)
    }
}
