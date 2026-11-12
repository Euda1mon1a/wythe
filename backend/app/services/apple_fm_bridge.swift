// Wythe Apple Intelligence (`FoundationModels`) on-device helper (macOS 26.0+ / 27.0).
// Preserves strict macOS FoundationModels ABI & concurrency invariants:
//   1. Compile with `-target arm64-apple-macos26.0` for macOS 26.x + 27.0 compatibility.
//   2. Inspect `LanguageModelError` via `Mirror(reflecting:)` (no static macOS 27 symbol import).
//   3. Always supply `sampling: nil` in `GenerationOptions(sampling: nil, temperature:maximumResponseTokens:)`.
//   4. Read one UTF-8 JSON request on stdin and emit one UTF-8 JSON object on stdout.

import Foundation
import FoundationModels

@Generable struct WytheArchitectureAnswer {
  @Guide(description: "Direct 2 to 4 sentence architectural answer grounded strictly in the supplied Wythe X-Ray facts")
  var summary: String

  @Guide(description: "Why the node or cluster is colored or flagged, citing exact rule codes and file:line pointers from the brief")
  var rootCauseOrRole: String

  @Guide(description: "Concrete safe next engineering or verification step")
  var safeNextStep: String

  @Guide(description: "Exact node IDs, table names, or service names referenced from the brief, up to 6 items")
  var referencedNodes: [String]
}

func emit(_ payload: [String: Any]) {
  guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return }
  FileHandle.standardOutput.write(data)
}

func checkAvailability() -> [String: Any] {
  switch SystemLanguageModel.default.availability {
  case .available:
    return ["available": true]
  case .unavailable(let reason):
    let why: String
    switch reason {
    case .deviceNotEligible: why = "deviceNotEligible"
    case .appleIntelligenceNotEnabled: why = "appleIntelligenceNotEnabled"
    case .modelNotReady: why = "modelNotReady"
    @unknown default: why = "unknown"
    }
    return ["available": false, "reason": why]
  }
}

func explainError(_ error: Error) -> [String: Any] {
  let declined: [String: Any] = [
    "ok": false,
    "code": "declined",
    "error": "Apple Intelligence declined this architectural prompt."
  ]
  let tooLong: [String: Any] = [
    "ok": false,
    "code": "too-long",
    "error": "The architectural context exceeded Apple Intelligence's 4,096-token window."
  ]
  if String(reflecting: type(of: error)).hasSuffix(".LanguageModelError"),
     let child = Mirror(reflecting: error).children.first {
    switch child.label {
    case "guardrailViolation", "refusal":
      return declined
    case "contextSizeExceeded":
      return tooLong
    case "rateLimited":
      let resetDate = Mirror(reflecting: child.value).children.first { $0.label == "resetDate" }?.value as? Date
      let waitSec = max(2.5, min(30.0, (resetDate?.timeIntervalSinceNow ?? 4.0) + 0.5))
      return [
        "ok": false,
        "code": "rate-limited",
        "retryAfterMs": Int(waitSec * 1000),
        "error": "Apple Intelligence rate limit reached; cooling down…"
      ]
    case "timeout":
      return ["ok": false, "code": "rate-limited", "retryAfterMs": 2500, "error": "Apple Intelligence timed out; retrying…"]
    default:
      break
    }
  }
  if let genErr = error as? LanguageModelSession.GenerationError {
    switch genErr {
    case .guardrailViolation:
      return declined
    case .exceededContextWindowSize:
      return tooLong
    case .rateLimited:
      return ["ok": false, "code": "rate-limited", "retryAfterMs": 4000, "error": "Apple Intelligence rate limit reached; cooling down…"]
    case .concurrentRequests:
      return ["ok": false, "code": "rate-limited", "retryAfterMs": 1500, "error": "Apple Intelligence busy with a prior request; retrying…"]
    default:
      break
    }
  }
  return ["ok": false, "error": "Apple Intelligence error (\(error.localizedDescription))."]
}

@main struct WytheAppleFMHelper {
  static func main() async {
    let raw = FileHandle.standardInput.readDataToEndOfFile()
    guard !raw.isEmpty,
          let msg = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
          let kind = msg["type"] as? String else {
      emit(["ok": false, "error": "Invalid JSON request on stdin."])
      return
    }
    if kind == "hello" {
      emit(checkAvailability().merging(["ok": true, "version": 1]) { cur, _ in cur })
      return
    }
    guard kind == "ask",
          let instructions = msg["instructions"] as? String,
          let prompt = msg["prompt"] as? String else {
      emit(["ok": false, "error": "Unsupported request type."])
      return
    }
    let state = checkAvailability()
    guard state["available"] as? Bool == true else {
      emit(state.merging(["ok": false, "error": "Apple Intelligence is not available."]) { cur, _ in cur })
      return
    }
    do {
      let session = LanguageModelSession(instructions: instructions)
      let res = try await session.respond(
        to: prompt,
        generating: WytheArchitectureAnswer.self,
        options: GenerationOptions(sampling: nil, temperature: 0.35, maximumResponseTokens: 650)
      )
      emit([
        "ok": true,
        "summary": res.content.summary,
        "rootCauseOrRole": res.content.rootCauseOrRole,
        "safeNextStep": res.content.safeNextStep,
        "referencedNodes": res.content.referencedNodes
      ])
    } catch {
      let mapped = explainError(error)
      let code = mapped["code"] as? String ?? ""
      if code != "declined" && code != "rate-limited" && code != "too-long" {
        do {
          let fallbackSession = LanguageModelSession(instructions: instructions)
          let plain = try await fallbackSession.respond(
            to: prompt,
            options: GenerationOptions(sampling: nil, temperature: 0.45, maximumResponseTokens: 550)
          )
          emit(["ok": true, "plainText": plain.content])
          return
        } catch {
          emit(explainError(error))
          return
        }
      }
      emit(mapped)
    }
  }
}
