import SwiftUI

@main
struct ClaudeUsageMonitorApp: App {
    @StateObject private var calculator = UsageCalculator()
    @StateObject private var updateChecker = UpdateChecker()

    var body: some Scene {
        MenuBarExtra {
            UsagePopoverView(calculator: calculator, updateChecker: updateChecker)
        } label: {
            menuBarLabel
        }
        .menuBarExtraStyle(.window)
    }

    private var menuBarLabel: some View {
        HStack(spacing: 3) {
            Image(systemName: "cloud.fill")
                .symbolRenderingMode(.palette)
                .foregroundStyle(menuBarColor)

            if let summary = calculator.summary {
                // session · weekly. Left uniformly colored so the two numbers
                // read as one value; the icon carries the warning.
                Text("\(Self.percentText(summary.fiveHour.percentage)) · \(Self.percentText(summary.weekly.percentage))")
                    .monospacedDigit()
            } else {
                Text("-- · --")
            }
        }
        .onAppear {
            calculator.start()
            updateChecker.checkForUpdates()
        }
    }

    /// Reflects whichever window is closest to its limit. Thresholding on the
    /// 5-hour window alone showed a green cloud while the weekly limit was
    /// nearly exhausted, which is the case where a warning matters most.
    private var menuBarColor: Color {
        guard let summary = calculator.summary else { return .secondary }
        let p = max(summary.fiveHour.percentage, summary.weekly.percentage)
        if p >= 0.8 { return .red }
        if p >= 0.5 { return .orange }
        return .green
    }

    private static func percentText(_ percentage: Double) -> String {
        "\(Int(percentage * 100))%"
    }
}
