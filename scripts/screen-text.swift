// Prints the text Vision reads in an image, one line per piece: `swift scripts/screen-text.swift shot.png`.
// The iOS e2e scripts use it on simulator screenshots to check what an app shows.
import Foundation
import Vision

let url = URL(fileURLWithPath: CommandLine.arguments[1])
let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
do {
    try VNImageRequestHandler(url: url).perform([request])
} catch {
    // Vision sometimes fails (e5rt errors, 1 run in 3 on macOS 27 on 2026-10-29); callers retry.
    FileHandle.standardError.write("screen-text: \(error)\n".data(using: .utf8)!)
    exit(1)
}
for observation in request.results ?? [] {
    if let text = observation.topCandidates(1).first?.string { print(text) }
}
