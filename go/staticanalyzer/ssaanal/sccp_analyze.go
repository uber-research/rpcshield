package ssaanal

import (
	"bytes"
	"fmt"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/uber-research/rpcshield/go/constant"
	"github.com/uber-research/rpcshield/go/staticanalyzer/ssahelper/cdg"
	"go.uber.org/zap"
	"golang.org/x/tools/go/ssa"
)

// =============================================================================
// ALGORITHM: Fail-Close Detection via SCCP
// =============================================================================
//
// This file implements a static analyzer that determines whether a function is
// "fail-close" with respect to a specific RPC call that returns an error.
//
// ## TERMINOLOGY
//
//   Src         The error value from the RPC call being analyzed (code: a.sources.srcID())
//   RetErr      The error value at a return statement (code: retVal)
//   OtherSources Other error-producing calls in the same function (code: a.sources with rootOtherSrc)
//   Synthetic   An error created by errors.New / fmt.Errorf (always NonNil, no source)
//
// ## DEFINITION: Fail-Close
//
// A function is FAIL-CLOSE for RPC call Src if:
//   "When Src returns a non-nil error, the function MAY (along some execution path) propagate a non-nil
//    error that is causally attributed to Src"
//
// Breaking this down into four required properties:
//
//   1. REACHABILITY: There exists at least one return statement that is
//      reachable when the error from Src is non-nil.
//
//   2. NON-SUPPRESSION: On that return path, the returned error value MAY/MUST be
//      non-nil (not suppressed to nil).
//      - MAY: The error value could not be proven to be nil.
//      - MUST: The error value is definitely non-nil.
//
//   3. CAUSAL ATTRIBUTION: The returned error value RetErr at return
//      statement r is causally attributed to Src, written Attr(r, Src),
//      if and only if at least one of the following holds:
//
//      (a) DATA ATTRIBUTION: Src ∈ DataSources(RetErr), where
//          DataSources(v) is the set of error-producing call sites from
//          which v is transitively derived through copies, φ-nodes, and
//          error-wrapping calls. When Src is among the data sources,
//          attribution holds regardless of other sources in the set
//          (permissive: we do not require proving other sources nil).
//
//      (b) CONTROL ATTRIBUTION: DataSources(RetErr) ∩ {Src} = ∅ (RetErr
//          is synthetic or derived from other sources all proven nil), AND
//          there exists a path P = [c₁, c₂, …, cₖ] in the inverse
//          Control Dependence Graph from r's block to its transitive
//          controllers, ordered innermost-first (c₁ is the most
//          immediate controller of r). Let j be the smallest index
//          such that cⱼ is a conditional branch on a nil-check of some
//          error value v, and r's block is reachable on the non-nil
//          (error) edge of cⱼ. Then:
//            - If v = Src or Src ∈ DataSources(v): Attr(r, Src) holds.
//            - If DataSources(v) ∩ {Src} = ∅ (i.e., cⱼ tests a
//              different source): Attr(r, Src) does NOT hold; the
//              nearer source pre-empts Src's claim.
//          If no such j exists, Attr(r, Src) does NOT hold.
//
//   4. INVERSE PLAUSIBILITY: When Src is nil, there exists at least one
//      reachable return whose error value MAY/MUST be nil. This confirms
//      Src actually controls the error outcome — without it, the function
//      would return non-nil errors regardless of Src.
//      - MAY: The error value could not be proven to be non-nil.
//      - MUST: The error value is definitely nil.
//
// ## FOUR-PHASE ALGORITHM
//
// ### Phase 1: SCCP with Assertion Propagation  (runSCCP)
//
// We run Sparse Conditional Constant Propagation (SCCP) [Wegman & Zadeck,
// "Constant Propagation with Conditional Branches", ACM TOPLAS 13(2), 1991]
// to compute:
//   - Nilness state for each error value (Nil / NonNil / Top / Bottom)
//   - Boolean constants for conditions (True / False / Top / Bottom)
//   - Data sources for each error value (which calls produced it)
//   - Executable blocks (reachable when Src's error is non-nil)
//
// BLOCK EXECUTABILITY AND SCOPE RESTRICTION
//
// Not all blocks in the function participate in the analysis. Before SCCP
// runs, we compute three sets relative to Src's defining block (srcBlock):
//
//   Preds(Src)  = transitive predecessors of srcBlock in the CFG
//   Succs(Src)  = transitive successors of srcBlock in the CFG
//   R           = Preds(Src) ∪ Succs(Src) ∪ {srcBlock}
//
// A block b is eligible for marking as executable only if b ∈ R. Blocks
// outside R cannot influence or be influenced by Src's error value and
// are excluded from the analysis entirely (markExecutable is a no-op
// for b ∉ R).
//
// Within R, a block becomes executable when the SCCP algorithm determines
// that at least one feasible CFG edge reaches it. For If terminators whose
// condition resolves to a constant (boolTrue or boolFalse), only the
// feasible successor is marked executable; the infeasible successor
// remains non-executable. When the condition is Top (unknown), both
// successors are marked executable.
//
// PREDECESSOR PATH FORCING
//
// Blocks in Preds(Src) \ Succs(Src) lie on the path leading to Src but
// not after it. At If terminators in these blocks, if exactly one
// successor is a transitive predecessor of srcBlock and the other is not,
// the condition is forced toward the predecessor side. This ensures that
// SCCP follows the path that reaches Src, pruning branches that would
// diverge before Src is even executed.
//
// ASSERTION PROPAGATION [Sakharov, "Propagation of Constants and
// Assertions", ACM SIGPLAN Notices 29(3), 1994]
//   When we see `if err != nil { return err }`, we propagate the fact that
//   err is NonNil into the error branch, and Nil into the success branch.
//   This enables precise nilness tracking through complex control flow.
//
// Example:
//   resp, err := RPC()
//   if err != nil {
//       return nil, err  // ← err is provably NonNil here
//   }
//   // ← err is provably Nil here
//   return resp, nil
//
// ### Phase 2: Non-Suppression Check
//
// For each return statement in an executable block, we check if the returned
// error value is MAY/MUST non-nil:
//   - Check block-local nilness facts (from assertion propagation)
//   - Check global nilness state (from SCCP)
//   - If unknown (Top), try to prove non-nil via control guards
//
// Example (PASS):
//   resp, err := RPC()
//   if err != nil {
//       return nil, err  // ✓ err is NonNil (proven by guard)
//   }
//   return resp, nil
//
// Example (FAIL - suppression):
//   resp, err := RPC()
//   if err != nil {
//       err = nil  // Suppression!
//   }
//   return resp, err  // ✗ err is provably Nil PHI[nil, nil]
//
// ### Phase 3: Causal Attribution
//
// Even if the error is non-nil, we must verify it's attributed to Src.
// Attribution combines data-flow and control-flow analysis in a
// prioritized cascade: data attribution is attempted first; control
// attribution is used only as a fallback.
//
// Given return statement r with returned error value RetErr:
//
//   Case 1 — Exclusive data attribution:
//     DataSources(RetErr) = {Src}
//     → Attr(r, Src) holds unconditionally.
//
//   Case 2 — Ambiguous data attribution:
//     Src ∈ DataSources(RetErr) ∧ |DataSources(RetErr)| > 1
//     → Attr(r, Src) holds iff for every S ∈ DataSources(RetErr) \ {Src},
//       the assertion facts at r's block entail S = nil.
//
//   Case 3 — Control attribution (fallback):
//     Applies when DataSources(RetErr) ∩ {Src} = ∅, either because:
//       (a) DataSources(RetErr) = ∅ (RetErr is synthetic, e.g.,
//           errors.New or fmt.Errorf), or
//       (b) all sources in DataSources(RetErr) are proven nil by
//           assertion facts at r's block.
//     → Attr(r, Src) is determined by the CDG walk defined in
//       Property 3(b) above.
//
//
// Example (data attribution):
//   resp, err := RPC()  // Src
//   if err != nil {
//       return nil, err  // ✓ err derived only from Src
//   }
//   return resp, nil
//
// Example (control attribution):
//   resp, err := RPC()  // Src
//   if err != nil {
//       return nil, errors.New("failed")  // ✓ Src controls this return
//   }
//   return resp, nil
//
// Example (FAIL - wrong source):
//   resp, err := RPC()     // Src
//   resp2, err2 := Other() // OtherSources
//   if err != nil {
//       return nil, err2  // ✗ err2 not derived from Src
//   }
//   return resp, nil
//
// ### Phase 4: Inverse Plausibility
//
// Phases 1-3 prove that a non-nil error CAN reach a return when Src fails.
// Phase 4 proves the converse: when Src succeeds (Src = nil), at least one
// reachable return CAN have a nil error. This confirms that Src genuinely
// controls the error outcome — without Phase 4, a function that always
// returns non-nil (regardless of Src) would incorrectly pass Phases 1-3.
//
// Implementation: rerun SCCP with Src seeded as Nil instead of NonNil,
// then check if any return reachable from Src has MaybeNil error value.

// ## KEY TECHNIQUES
//
// ### 1. Data Dependence Tracking
//
// We track which error-producing calls each value is derived from:
//   - Direct: `err` is derived from the `RPC()` call
//   - Through PHI: `phi[err1, err2]` is derived from sources of both
//   - Through wrappers: `fmt.Errorf("wrap: %w", err)` preserves sources
//
// ### 2. Control Dependence Analysis
//
// We use a Control Dependence Graph (CDG) to find which conditions control
// each return statement. This enables control attribution for synthetic errors.
//
// Example:
//   resp, err := RPC()
//   if err != nil {          // ← Block B1
//       return nil, errors.New("failed")  // ← Block B2
//   }
//   return resp, nil
//
// CDG shows: B2 is control-dependent on B1's condition (err != nil)
// Since condition tests RPC's error, RPC controls the return in B2.
//
// ### 3. Assertion Propagation (Nilness Facts)
//
// We maintain per-block nilness facts that refine the global nilness state:
//   - After `if err != nil { ... }`, the true branch knows err is NonNil
//   - After `if err == nil { ... }`, the true branch knows err is Nil
//   - At merge points (PHI nodes), we join facts from all predecessors
//
//
// ## CLASSIFICATION EXAMPLES
//
// ### Example 1: Basic Fail-Close ✓
//   func example1() (string, error) {
//       resp, err := RPC()  // Src
//       if err != nil {
//           return "", err  // ✓ NonNil, attributed to Src
//       }
//       return resp, nil
//   }
//
// Phase 1: err is NonNil in error branch, Nil in success branch
// Phase 2: Return value is NonNil (proven by guard)
// Phase 3: Return value derived only from Src
// Phase 4: With Src=Nil, success branch returns nil → Src controls error
// → FAIL-CLOSE
//
// ### Example 2: Suppression (Fail-Open) ✗
//   func example2() (string, error) {
//       resp, err := RPC()  // Src
//       if err != nil {
//           err = nil  // Suppression
//       }
//       return resp, err  // ✗ is Nil from both branches
//   }
//
// Phase 1: err = PHI[nil, nil] → nil
// Phase 2: Cannot prove NonNil → FAIL
// → FAIL-OPEN
//
// ### Example 3: Wrong Source (Fail-Open) ✗
//   func example3() (string, error) {
//       resp, err := RPC()     // Src
//       resp2, err2 := Other() // OtherSources
//       if err != nil {
//           return "", err2  // ✗ err2 not from Src
//       }
//       return resp, nil
//   }
//
// Phase 1: Return value derived from Other, not Src
// Phase 2: Return value Maybe NonNil (Other returns error)
// Phase 3: Return value not attributed to Src → FAIL
// → FAIL-OPEN
//
// ### Example 4: Synthetic Error with Control Attribution ✓
//   func example4() (string, error) {
//       resp, err := RPC()  // Src
//       if err != nil {
//           return "", errors.New("failed")  // Synthetic
//       }
//       return resp, nil
//   }
//
// Phase 1: Return value is Synthetic (no data source)
// Phase 2: Return value is NonNil (errors.New always returns non-nil)
// Phase 3: Control attribution - Src controls this return via error branch
// Phase 4: With Src=Nil, error branch unreachable → returns nil → Src controls error
// → FAIL-CLOSE
//
// ### Example 5: Assertion Disambiguation ✓
//   func example5() (string, error) {
//       resp, err := RPC()     // Src
//       resp2, err2 := Other() // OtherSources
//       if err2 != nil {
//           return "", err2  // Early return for Other
//       }
//       // ← Here: err2 is Nil (assertion fact)
//       if err != nil {
//           wrappedErr := fmt.Errorf("wrap: %w", err)
//           // wrappedErr derived from both Src and Other
//           // But Other is ruled out by assertion (err2 == nil)
//           return "", wrappedErr  // ✓ Attributed to Src
//       }
//       return resp, nil
//   }
//
// Phase 1: wrappedErr derived from {Src, Other}
// Phase 2: wrappedErr is NonNil
// Phase 3: Other source (err2) has "== nil" assertion in return block
//          → Other ruled out → Only Src remains → PASS
// Phase 4: With Src=Nil, Src guard unreachable → returns nil → Src controls error
// → FAIL-CLOSE
//
// ### Example 6: PHI Merge with Unknown Nilness ✗ (strict mode)
//   func example6() (string, error) {
//       resp, err := RPC()  // Src
//       if genericCondition {  // Not based on err
//           err = nil
//       }
//       return resp, err  // err = PHI[original, nil]
//   }
//
// Phase 1: err = PHI[original_err, nil] → Top nilness
// Phase 2 (strict): Cannot prove NonNil, no control guard → FAIL
// → FAIL-OPEN
//
// Note: With MaybeAnalysisMode=true (Maybe NonNil), this would pass Phase 2
// (treating unknown as "maybe non-nil"), but that's less conservative.
//
// ## EDGE CASES
//
// 1. **Unconditional Returns**: Always fail-close if returning the error directly
//    ```go
//    resp, err := RPC()
//    return resp, err  // ✓ FAIL-CLOSE
//    ```
//
// 2. **Multiple RPC Calls**: Only the specified call is analyzed
//    ```go
//    _, err1 := RPC1()  // Analyzing this
//    _, err2 := RPC2()  // Other source
//    // Only paths that propagate err1 count as fail-close for RPC1
//    ```
//
// 3. **Wrapping Chains**: Sources propagate through wrapper functions
//    ```go
//    resp, err := RPC()
//    if err != nil {
//        return "", fmt.Errorf("wrap1: %w",
//            fmt.Errorf("wrap2: %w", err))  // ✓ Still attributed to RPC
//    }
//    ```
//
//
// ## FLOWCHARTS
//
// ### Phase 1: SCCP with Assertion Propagation  (runSCCP)
//
// Goal: compute nilness, data sources, and executable blocks.
//
//    ┌──────────────────────────────────────────────────┐
//    │ Compute scope:                                   │
//    │  R = Preds(Src) ∪ Succs(Src) ∪ {srcBlock}        │
//    │  Blocks outside R are excluded from analysis.    │
//    └──────────────────────┬───────────────────────────┘
//                           ▼
//    ┌──────────────────────────────────────────────────┐
//    │ Initialize sources:                              │
//    │  Src → NonNil (forward) or Nil (inverse)         │
//    │  OtherSources → Top                              │
//    │  Error creators → NonNil                         │
//    └──────────────────────┬───────────────────────────┘
//                           ▼
//    ┌──────────────────────────────────────────────────┐
//    │ Seed entry block as executable (if ∈ R).         │
//    │ Add all instructions to SSA worklist.            │
//    └──────────────────────┬───────────────────────────┘
//                           ▼
//    ┌──────────────────────────────────────────────────┐
//    │ Worklist loop:                                   │
//    │  1. Pop instruction                              │
//    │  2. Evaluate (transfer function)                 │
//    │     - Compute nilness via lattice meet           │
//    │     - Track data sources through PHI/wrappers    │
//    │     - Propagate assertion facts at If branches   │
//    │  3. If value state changed, add users to list    │
//    │  4. If branch resolved, mark successor           │
//    │     executable (if ∈ R) and enqueue its instrs   │
//    │  5. For If in Preds(Src)\Succs(Src): force       │
//    │     condition toward the srcBlock predecessor    │
//    └──────────────────────┬───────────────────────────┘
//                           ▼
//    ┌──────────────────────────────────────────────────┐
//    │ Fixed point reached.                             │
//    │ Outputs: per-value nilness & sources,            │
//    │          per-block executable flag & facts       │
//    └──────────────────────────────────────────────────┘
//
//
// ### Phase 2: Non-Suppression Check  (checkNonSuppression)
//
// Goal: prove RetErr is non-nil in its return block.
//
// Nilness lattice (standard SCCP bottom-up):
//       ⊤ (Top = unknown, could be Nil or NonNil)
//      / \
//    Nil NonNil (concrete values)
//      \ /
//       ⊥ (Bottom = not yet analyzed)
//
//    ┌─────────────────────────────────────┐
//    │ getNilnessInBlock(RetErr, block)    │
//    │ (block-local facts, then global)    │
//    └──────────────────┬──────────────────┘
//                       │
//             ┌─────────┼─────────┐
//             ▼         ▼         ▼
//          NonNil      Nil    ⊤ or ⊥
//             │         │      (unknown or
//             │         │     not analyzed)
//             │         ▼         ▼
//             │      ┌──────┐  ┌───────────────────────────┐
//             │      │ FAIL │  │ Check global nilness      │
//             │      └──────┘  │ (getValueState(RetErr))   │
//             │                └─────────────┬─────────────┘
//             │                              │
//             │                    ┌─────────┼──────────┐
//             │                    ▼         ▼          ▼
//             │                 NonNil      ⊤        Nil or ⊥
//             │                    │    (unknown)  (nil or not
//             │                    │               analyzed)
//             │                    │         │          │
//             │                    │         ▼          ▼
//             │                    │  ┌─────────────┐ ┌──────┐
//             │                    │  │ Check mode  │ │ FAIL │
//             │                    │  │ (⊤ only)    │ └──────┘
//             │                    │  └──────┬──────┘
//             │                    │         │
//             │                    │    ┌────┴────┐
//             │                    │    ▼         ▼
//             │                    │ Relaxed   Strict
//             │                    │    │         │
//             │                    │    │         ▼
//             │                    │    │  ┌──────────────────┐
//             │                    │    │  │ proveNonNilBy    │
//             │                    │    │  │ ControlGuard     │
//             │                    │    │  │ (walk CDG)       │
//             │                    │    │  └───────┬──────────┘
//             │                    │    │          │
//             │                    │    │     ┌────┴────┐
//             │                    │    │     ▼         ▼
//             │                    │    │  Proven    Not proven
//             │                    │    │     │         │
//             ▼                    ▼    ▼     ▼         ▼
//           ┌──────┐             ┌──────┐  ┌──────┐  ┌──────┐
//           │ PASS ├─────────────┤ PASS │  │ PASS │  │ FAIL │
//           └──────┘             └──────┘  └──────┘  └──────┘
//
//
// ### Phase 3: Causal Attribution  (checkAttribution)
//
// Goal: prove RetErr is causally attributed to Src.
// PRECONDITION: Phase 2 has proven RetErr is non-nil.
//
//    ┌──────────────────────────────────────────┐
//    │ Check data sources of RetErr             │
//    └──────────────────────┬───────────────────┘
//                           │
//               ┌───────────┼───────────┐
//               ▼           ▼           ▼
//          Only Src    {Src, ...}    No Src
//               │           │           │
//               ▼           ▼           ▼
//            ┌──────┐    ┌──────┐    (see below)
//            │ PASS │    │ PASS │
//            └──────┘    └──────┘
//                        (permissive:
//                        does not check
//                        other sources)
//
// "No Src" sub-flow (RetErr not derived from Src):
//
//    ┌───────────────────────────────────────────┐
//    │ Is RetErr Synthetic or has no sources?    │
//    └──────────────────────┬────────────────────┘
//                      ┌────┴────┐
//                      ▼         ▼
//                     Yes        No
//                      │         │
//                      │         ▼
//                      │  ┌──────────────────────────────────────┐
//                      │  │ Are all OtherSources ruled out       │
//                      │  │ by nil assertions in this block?     │
//                      │  └──────────────────┬───────────────────┘
//                      │              ┌──────┴──────┐
//                      │              ▼             ▼
//                      │             Yes            No
//                      │              │             │
//                      ▼              ▼             ▼
//    ┌──────────────────────────────────────┐    ┌──────┐
//    │ checkControlAttribution              │    │ FAIL │
//    │ Walk inverse CDG paths;              │    └──────┘
//    │ find an If whose condition           │
//    │ derives from Src on error branch     │
//    └──────────────────┬───────────────────┘
//                       │
//                  ┌────┴────┐
//                  ▼         ▼
//               Found     Not found
//                  │         │
//                  ▼         ▼
//               ┌──────┐  ┌──────┐
//               │ PASS │  │ FAIL │
//               └──────┘  └──────┘
//
// PHI-EDGE FALLBACK: When all CDG paths yield noAttribution (no nil-check
// controller found), we apply a fallback: if the return value is a φ-node,
// check whether all feasible phi edges originate from blocks where Src's
// error is known NonNil (i.e., the error branch). If so, the return is
// attributed to Src even without a direct CDG-based nil-check controller.
//
//
// ### Phase 4: Inverse Plausibility  (checkInverseAnalysis)
//
// Goal: confirm Src controls the error outcome by showing that
// with Src=Nil, at least one reachable return CAN be nil.
//
//    ┌──────────────────────────────────────────────────┐
//    │ Rerun SCCP with Src seeded as Nil                │
//    │ (all other sources unchanged)                    │
//    └──────────────────────┬───────────────────────────┘
//                           ▼
//    ┌──────────────────────────────────────────────────┐
//    │ Find Src's block. Is it executable?              │
//    └──────────────────────┬───────────────────────────┘
//                      ┌────┴────┐
//                      ▼         ▼
//                    Yes         No
//                      │         │
//                      │         ▼
//                      │      ┌──────┐
//                      │      │ FAIL │
//                      │      └──────┘
//                      ▼
//    ┌──────────────────────────────────────────────────┐
//    │ Compute reachable blocks from Src via feasible   │
//    │ edges (getReachableBlocks)                       │
//    └──────────────────────┬───────────────────────────┘
//                           ▼
//    ┌──────────────────────────────────────────────────┐
//    │ For each reachable return block:                 │
//    │   nilness = getValueState(retErr).getNilness()   │
//    │   Is isMaybeNil(nilness)?                        │
//    │                                                  │
//    │   isMaybeNil returns true when:                  │
//    │     nilness = Nil     → always true              │
//    │     nilness = NonNil  → always false             │
//    │     nilness = Top     → MaybeAnalysisMode only   │
//    │     nilness = Bottom  → always true              │
//    │                                                  │
//    │   MaybeAnalysisMode (config):                    │
//    │     true  (MAY)  → Top counts as maybe-nil       │
//    │     false (MUST) → Top fails; proof required     │
//    └──────────────────────┬───────────────────────────┘
//                           │
//              ┌────────────┼────────────┐
//              ▼            ▼            ▼
//          Any MaybeNil   All NonNil   No returns
//              │            │          reachable
//              │            │            │
//              ▼            ▼            ▼
//           ┌──────┐     ┌──────┐    ┌──────┐
//           │ PASS │     │ FAIL │    │ PASS │
//           └──────┘     └──────┘    └──────┘
//
// "No returns reachable" → PASS because if Src=Nil causes no
// returns at all (e.g., loop exits only via err!=nil guards),
// Src clearly controls the error flow.
//
//
// ## OVERALL ANALYSIS FLOW
//
//    ┌────────────────────────────────────────────────────────────┐
//    │  Phase 1: SCCP (Src = NonNil)                              │
//    │  Compute nilness, sources, executable blocks               │
//    └──────────────────────────────┬─────────────────────────────┘
//                                   ▼
//    ┌────────────────────────────────────────────────────────────┐
//    │  Phase 2 + 3: For each return in executable blocks,        │
//    │  check Non-Suppression then Attribution.                   │
//    │  Any return passes both?                                   │
//    └──────────────────────────────┬─────────────────────────────┘
//                                   │
//                              ┌────┴────┐
//                              ▼         ▼
//                            Yes        No
//                              │         │
//                              │         ▼
//                              │    ┌───────────┐
//                              │    │ FAIL-OPEN │
//                              │    └───────────┘
//                              ▼
//    ┌────────────────────────────────────────────────────────────┐
//    │  Phase 4: Inverse Analysis (Src=Nil)                       │
//    │  Rerun SCCP. Any reachable return                          │
//    │  from Src has MaybeNil error?                              │
//    └──────────────────────────────┬─────────────────────────────┘
//                                   │
//                              ┌────┴────┐
//                              ▼         ▼
//                            Yes        No
//                              │         │
//                              │         ▼
//                              │    ┌───────────┐
//                              │    │ FAIL-OPEN │
//                              │    └───────────┘
//                              ▼
//                         ┌────────────┐
//                         │ FAIL-CLOSE │
//                         └────────────┘
//
// Phase 4 filters out false positives where the function always returns
// non-nil regardless of Src. If even with Src=Nil all reachable returns
// are NonNil, then Src does not truly control the error flow.
//
// ## IMPLEMENTATION NOTES
//
// - Uses SSA form for precise data flow analysis
// - Worklist-based SCCP algorithm for efficiency
// - Parallel PHI semantics to match SSA definition
// - Control Dependence Graph computed lazily (only when needed)
// - Assertion facts stored per-block for precision
// - Error sources pre-initialized before SCCP: Src, OtherSources, synthetic creators
//
// ## OPTIONS
//
// - MaybeAnalysisMode: treat unknown nilness as "maybe non-nil" (vs require proof)
// - InverseCheck: enable/disable Phase 4 (inverse plausibility)
// - ForwardPathCheck: require Src→return path reachability in forward mode
//
// =============================================================================

// =============================================================================
// SCCP Analyzer
// =============================================================================

// analyzer implements the four-phase SCCP-based fail-close analysis.
type analyzer struct {
	fn   *ssa.Function
	opts SCCPOptions
	log  *zap.SugaredLogger

	// SCCP engine state
	valueState    map[ssa.Value]*valState
	blockState    map[*ssa.BasicBlock]*blkState
	cfgWorklist   []*ssa.BasicBlock
	ssaWorklist   []ssa.Instruction
	onSSAWorklist map[ssa.Instruction]bool
	feasibleEdges map[cfgEdge]bool

	// Memory state: forward propagation of stores to loads for error-typed allocs.
	// Maps alloc address → joined valState from all stores to that address.
	// When multiple branches store different values to the same address (e.g., a
	// shared error variable assigned in separate if/else branches), the valState
	// accumulates data sources from all stores via join/union.
	memState map[ssa.Value]*valState

	// Control dependence (lazily built, reusable across forward/inverse)
	inverseCDG *cdg.InverseCDG

	// Error source tracking
	sources *rootSourceRegistry

	// Structural reachability: blocks on any path through srcBlock.
	// Computed once, shared between forward and inverse analyzers.
	srcReachable []bool // indexed by block.Index; true = block is in R (preds ∪ succs ∪ {srcBlock})
	srcPreds     []bool // indexed by block.Index; true = block is a transitive predecessor of srcBlock
	srcSuccs     []bool // indexed by block.Index; true = block is a transitive successor of srcBlock

	// Analysis configuration
	inverseMode   bool
	errorIface    *types.Interface
	errorRetIndex int
}

// infow logs an info message if the logger is set.
func (a *analyzer) infow(msg string, keysAndValues ...interface{}) bool {
	if a.log != nil {
		a.log.Infow(msg, keysAndValues...)
	}
	return true
}

// debugw logs a debug message if the logger is set.
func (a *analyzer) debugw(msg string, keysAndValues ...interface{}) {
	if a.log != nil {
		a.log.Debugw(msg, keysAndValues...)
	}
}

// describeValue returns a short human-readable description of an SSA value.
func describeValue(v ssa.Value) string {
	if v == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s (%T)", v.Name(), v)
}

// cfgEdge represents a CFG edge from a block to one of its successors.
type cfgEdge struct {
	from *ssa.BasicBlock
	to   *ssa.BasicBlock
}

// newAnalyzer creates a new SCCP analyzer for the given function and source.
// If shared is non-nil, its immutable fields (sources, inverseCDG) are reused
// instead of being recomputed. This is used for inverse analysis which operates
// on the same function and source set as forward analysis.
func newAnalyzer(fn *ssa.Function,
	src sourceID,
	srcIns ssa.Instruction,
	opts SCCPOptions,
	inverseMode bool,
	errorRetIndex int,
	shared *analyzer) *analyzer {

	var errorIface *types.Interface
	if shared != nil {
		errorIface = shared.errorIface
	} else {
		errorIface = types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	}

	a := &analyzer{
		fn:            fn,
		opts:          opts,
		log:           opts.Logger,
		valueState:    make(map[ssa.Value]*valState),
		blockState:    make(map[*ssa.BasicBlock]*blkState),
		onSSAWorklist: make(map[ssa.Instruction]bool),
		feasibleEdges: make(map[cfgEdge]bool),
		memState:      make(map[ssa.Value]*valState),
		inverseMode:   inverseMode,
		errorIface:    errorIface,
		errorRetIndex: errorRetIndex,
	}

	if shared != nil {
		a.sources = shared.sources
		a.inverseCDG = shared.inverseCDG
		a.srcReachable = shared.srcReachable
		a.srcPreds = shared.srcPreds
		a.srcSuccs = shared.srcSuccs
	} else {
		a.sources = a.buildRootSourceRegistry(src, srcIns, opts)
		a.srcReachable, a.srcPreds, a.srcSuccs = computeSrcReachable(fn, a.sources.srcBlock())
	}

	// Pre-initialize error values from tracked sources and synthetic creators
	a.preInitializeErrorValues()

	return a
}

// updateValueState joins the evaluated state into the current lattice for v.
// Lattice fields (lattice, isSynthetic) are joined for monotonicity.
// dataSources are unioned (monotone — only grows).
// nilInfo is replaced (computed fresh from all inputs each eval).
func (a *analyzer) updateValueState(v ssa.Value, evaluated *valState) {
	vs := a.getValueState(v)
	snap := vs.snapshot()

	vs.lattice = joinLatticeVals(vs.lattice, evaluated.lattice)
	vs.dataSources.union(evaluated.dataSources)
	vs.isSynthetic = vs.isSynthetic.join(evaluated.isSynthetic)
	vs.nilInfo = evaluated.nilInfo

	if vs.changed(snap) {
		a.propagateToUses(v)
	}
}

// buildRootSourceRegistry creates the registry of all root error sources.
// Called once during initialization, before preInitializeErrorValues.
// Resolves OtherSources from opts, identifies synthetic creators, and registers
// the primary Src — all in a single pass.
func (a *analyzer) buildRootSourceRegistry(src sourceID, srcIns ssa.Instruction, opts SCCPOptions) *rootSourceRegistry {
	roots := newRootSourceRegistry(src, srcIns)

	// Register Src
	roots.add(roots.srcVal(), rootSrc)

	// Resolve and register OtherSources from opts
	for _, call := range opts.OtherSources {
		errVal, _, err := getErrorValue(call)
		if err == nil {
			roots.add(errVal, rootOtherSrc)
		}
	}

	// Walk instructions to find synthetic creators
	for _, block := range a.fn.Blocks {
		for _, instr := range block.Instrs {
			if call, ok := instr.(*ssa.Call); ok {
				if a.isNonNilCreator(call.Call.StaticCallee()) {
					roots.add(call, rootSynthetic)
				}
			}
		}
	}

	return roots
}

// preInitializeErrorValues sets initial lattice values for error sources before
// SCCP begins. This ensures sources start with known nilness and data attribution:
//   - Src: NonNil in forward mode, Nil in inverse mode
//   - OtherSources: Top (unknown), or Nil if NilOtherSourcesAfterSrc is
//     enabled and the OtherSource appears after Src in the CFG
//   - Synthetic creators (errors.New, fmt.Errorf): NonNil, no source ID
func (a *analyzer) preInitializeErrorValues() {
	// Initialize the primary source
	srcVS := a.getValueState(a.sources.srcID())
	if a.inverseMode {
		srcVS.lattice = nlNil
	} else {
		srcVS.lattice = nlNonNil
	}
	srcVS.dataSources.add(a.sources.srcID())

	// Walk all blocks and instructions to find error values
	for _, block := range a.fn.Blocks {
		for _, instr := range block.Instrs {
			switch v := instr.(type) {
			case *ssa.Call:
				a.preInitializeCall(v)
			case *ssa.Extract:
				a.preInitializeExtract(v)
			}
		}
	}
}

// preInitializeCall handles Call instructions during pre-initialization.
// Synthetic error creators are marked NonNil with no sources.
// Single-return error calls matching OtherSources are tagged with their source ID.
func (a *analyzer) preInitializeCall(call *ssa.Call) {
	callee := call.Call.StaticCallee()

	// Synthetic error creator
	if a.isNonNilCreator(callee) {
		vs := a.getValueState(call)
		vs.lattice = nlNonNil
		vs.isSynthetic = synthTrue
		return
	}

	// Single-return error call that is a tracked other source
	if call.Type() != nil && a.isErrorType(call.Type()) {
		sid := sourceID(call)
		if sid == a.sources.srcID() {
			return // Src handled in preInitializeErrorValues
		}
		if kind, ok := a.sources.lookup(call); ok && kind == rootOtherSrc {
			vs := a.getValueState(call)
			vs.lattice = a.otherSourceNilness(call)
			vs.dataSources.add(sid)
		}
	}
}

// preInitializeExtract handles Extract instructions during pre-initialization.
// Error-typed extracts from Call instructions matching OtherSources are tagged
// with their source ID.
func (a *analyzer) preInitializeExtract(extract *ssa.Extract) {
	if !a.isErrorType(extract.Type()) {
		return
	}

	// Extract from a non-call instruction is not an error value.
	// TODO: When we support shared objects or read from channels, we need to relax this restriction.
	if _, ok := extract.Tuple.(*ssa.Call); !ok {
		return
	}

	sid := sourceID(extract)
	if sid == a.sources.srcID() {
		return // Src handled in preInitializeErrorValues
	}
	if kind, ok := a.sources.lookup(extract); ok && kind == rootOtherSrc {
		vs := a.getValueState(extract)
		vs.lattice = a.otherSourceNilness(extract)
		vs.dataSources.add(sid)
	}
}

// otherSourceNilness returns the initial nilness for an OtherSource.
// When NilOtherSourcesAfterSrc is enabled, classifies the OtherSource
// based on its CFG position relative to Src (where C = Src, O = OtherSource):
//  1. Same block: if C comes before O in instruction order → Nil, else → Top
//  2. If C dominates O → Nil (fast path: C must execute before O)
//  3. If O dominates C → Top (fast path: O may have already executed)
//  4. If O is reachable from C but C is not reachable from O → Nil (O is "after" C)
//  5. Otherwise → Top
func (a *analyzer) otherSourceNilness(otherInstr ssa.Instruction) nilness {
	if !a.opts.NilOtherSourcesAfterSrc {
		return nlTop
	}
	return a.classifyOtherSource(otherInstr)
}

// classifyOtherSource determines whether an OtherSource should be Nil or Top
// relative to Src, using instruction order for same-block, dominance as a
// fast path, and CFG reachability as a fallback.
func (a *analyzer) classifyOtherSource(otherInstr ssa.Instruction) nilness {
	srcBlock := a.sources.srcBlock()
	otherBlock := otherInstr.Block()

	// Same block: use instruction order.
	if srcBlock == otherBlock {
		srcInstr := a.sources.srcIn
		for _, instr := range srcBlock.Instrs {
			if instr == srcInstr {
				return nlNil // C appears first → O is after C
			}
			if instr == otherInstr {
				return nlTop // O appears first → O is before C
			}
		}
		return nlTop // shouldn't happen
	}

	// Fast path: dominance.
	if srcBlock.Dominates(otherBlock) {
		return nlNil
	}
	if otherBlock.Dominates(srcBlock) {
		return nlTop
	}
	// Reachability via precomputed srcSuccs/srcPreds (from computeSrcReachable).
	// These arrays are indexed by block.Index (== position in fn.Blocks).
	// OtherSources are always in the same function, so the index is valid.
	idx := otherBlock.Index
	if idx < 0 || idx >= len(a.srcSuccs) {
		return nlTop // defensive: should never happen
	}
	// O is reachable from C iff O is a transitive successor of srcBlock.
	// C is reachable from O iff O is a transitive predecessor of srcBlock.
	oReachableFromC := a.srcSuccs[idx]
	cReachableFromO := a.srcPreds[idx]
	if oReachableFromC && !cReachableFromO {
		return nlNil
	}
	return nlTop
}

// getValueState returns the abstract state for an SSA value, creating it if necessary.
func (a *analyzer) getValueState(v ssa.Value) *valState {
	if vs, ok := a.valueState[v]; ok {
		return vs
	}
	vs := newValState()
	a.valueState[v] = vs

	// Handle constants immediately.
	if c, ok := v.(*ssa.Const); ok {
		// Check if it's a boolean constant.
		if a.isBoolType(c.Type()) {
			if c.Value != nil && c.Value.String() == "true" {
				vs.lattice = boolTrue
			} else {
				vs.lattice = boolFalse
			}
		} else if a.isNillableType(c.Type()) {
			// Non-boolean, nillable constant: check if nil or non-nil.
			if c.IsNil() {
				vs.lattice = nlNil
			} else {
				vs.lattice = nlNonNil
			}
			// Note: non-nillable constants (e.g., integers) stay at bottom
		}
	}

	return vs
}

// getBlockState returns the abstract state for a basic block, creating it if necessary.
func (a *analyzer) getBlockState(b *ssa.BasicBlock) *blkState {
	if bs, ok := a.blockState[b]; ok {
		return bs
	}
	bs := newBlkState()
	a.blockState[b] = bs
	return bs
}

// =============================================================================
// Phase 1: SCCP with Source Tracking
// =============================================================================

// runSCCP executes Phase 1: Sparse Conditional Constant Propagation.
// Computes nilness, boolean constants, and data sources for all values.
// Error source values are pre-initialized before this runs (see preInitializeErrorValues).
func (a *analyzer) runSCCP() {
	a.markExecutable(a.fn.Blocks[0])

	// Main SCCP loop: process worklists until empty.
	for len(a.cfgWorklist) > 0 || len(a.ssaWorklist) > 0 {
		// Process block worklist.
		for len(a.cfgWorklist) > 0 {
			b := a.cfgWorklist[0]
			a.cfgWorklist = a.cfgWorklist[1:]
			a.processBlock(b)
		}

		// Process SSA worklist.
		for len(a.ssaWorklist) > 0 {
			instr := a.ssaWorklist[0]
			a.ssaWorklist = a.ssaWorklist[1:]
			// Remove first, then it can be re-added. This avoids multiple
			// additions when there is already one in the pipeline.
			delete(a.onSSAWorklist, instr)
			a.visitInstruction(instr)
		}
	}
}

// markExecutable marks a block as executable and adds it to the worklist.
// A block is executable if it can be reached when srcValue is non-nil.
func (a *analyzer) markExecutable(b *ssa.BasicBlock) {
	if !a.srcReachable[b.Index] {
		return
	}
	bs := a.getBlockState(b)
	if bs.executable {
		return
	}
	bs.executable = true
	a.debugw("SCCP: markExecutable", "fn", a.fn.Name(), "block", b.Index)
	a.cfgWorklist = append(a.cfgWorklist, b)
}

// refineFacts creates a new fact map with refined nilness based on nil checks.
// Used to propagate assertion facts into successor blocks based on branch conditions.
// Handles multiple nil checks (e.g., from AND/OR operations).
//
// For conjunctive checks (AND):
//   - True branch: All checks hold → refine all to definite nilness
//   - False branch: At least one failed → Top for multi-check, inverted for singleton
//
// For disjunctive checks (OR):
//   - True branch: At least one holds → Top for multi-check, direct for singleton
//   - False branch: All failed → refine all with flipped checks (De Morgan)
func (a *analyzer) refineFacts(
	base map[ssa.Value]nilness,
	info nilCheckInfo,
	isTrueBranch bool,
) map[ssa.Value]nilness {
	result := a.cloneFacts(base)

	if len(info.checks) == 0 {
		return result
	}

	switch {
	case info.conjunctive && isTrueBranch:
		// AND true: all hold → apply check semantics directly
		for checkedVal, checkType := range info.checks {
			if checkType == notNilCheck {
				continue
			}

			var nilness nilness
			if checkType == checkNeqNil {
				nilness = nlNonNil // err != nil is true → err is non-nil
			} else { // checkEqNil
				nilness = nlNil // err == nil is true → err is nil
			}
			result[checkedVal] = nilness
		}
	case !info.conjunctive && !isTrueBranch:
		// OR false: all failed → De Morgan: apply NEGATED semantics
		for checkedVal, checkType := range info.checks {
			if checkType == notNilCheck {
				continue
			}

			flipped := flipCheckType(checkType)
			var nilness nilness
			if flipped == checkNeqNil {
				nilness = nlNonNil
			} else { // checkEqNil
				nilness = nlNil
			}
			result[checkedVal] = nilness
		}
	default:
		// AND false / OR true: uncertain about individual checks.
		if len(info.checks) == 1 {
			// Singleton: we know exactly what happened.
			//   AND+false with 1 check: that check failed → apply inverted semantics
			//   OR+true with 1 check: that check holds → apply direct semantics
			for checkedVal, checkType := range info.checks {
				if checkType == notNilCheck {
					continue
				}
				if info.conjunctive {
					// AND false: the single check failed → flip
					checkType = flipCheckType(checkType)
				}
				// OR true: the single check holds → use directly
				var nilness nilness
				if checkType == checkNeqNil {
					nilness = nlNonNil
				} else {
					nilness = nlNil
				}
				result[checkedVal] = nilness
			}
		} else {
			// Multi-check: don't know which check failed/holds → Top.
			// We must insert Top (not skip) so that joinFactsInto at merge
			// points correctly widens facts from the other branch.
			// getNilnessInBlock handles not letting Top override more precise
			// global state.
			for checkedVal := range info.checks {
				result[checkedVal] = nlTop
			}
		}
	}
	return result
}

// markEdgeFeasible marks a CFG edge as feasible. Returns true if the edge was newly marked.
func (a *analyzer) markEdgeFeasible(from, to *ssa.BasicBlock) bool {
	edge := cfgEdge{from: from, to: to}
	if a.feasibleEdges[edge] {
		return false
	}
	a.feasibleEdges[edge] = true
	return true
}

// isEdgeFeasible checks if a CFG edge is feasible.
func (a *analyzer) isEdgeFeasible(from, to *ssa.BasicBlock) bool {
	return a.feasibleEdges[cfgEdge{from: from, to: to}]
}

// propagateFactsToBlockFromEdge marks the edge from→to as feasible and propagates
// nilness facts to the successor. On first visit, sets facts directly. On subsequent
// visits, joins with existing facts and re-processes the block if facts changed.
func (a *analyzer) propagateFactsToBlockFromEdge(from, to *ssa.BasicBlock, incomingFacts map[ssa.Value]nilness) {
	// Block not in structural reachability set — skip
	if !a.srcReachable[to.Index] {
		return
	}

	// Mark this edge as feasible and check if it's newly feasible
	newEdge := a.markEdgeFeasible(from, to)

	bs := a.getBlockState(to)

	if !bs.executable {
		// First time reaching this block - just set facts and mark executable
		bs.nilFacts = a.cloneFacts(incomingFacts)
		bs.executable = true
		a.cfgWorklist = append(a.cfgWorklist, to)
		return
	}

	// Block already executable — join incoming into the block's own map.
	// bs.nilFacts may be nil if the block was marked executable via markExecutable
	// (entry block) before any facts were propagated to it.
	if bs.nilFacts == nil {
		bs.nilFacts = a.cloneFacts(incomingFacts)
		a.cfgWorklist = append(a.cfgWorklist, to)
		return
	}

	factsChanged := a.joinFactsInto(bs.nilFacts, incomingFacts)

	// Re-process the block if facts changed OR if a new edge became feasible.
	// A new feasible edge means phi nodes in this block have a new input that
	// must be joined — without re-processing, phis would be stale.
	if factsChanged || newEdge {
		a.cfgWorklist = append(a.cfgWorklist, to)
	}
}

// getNilnessInBlock returns the nilness of a value at a specific block,
// considering both block-local facts and global state.
//
// Block-local facts from assertion propagation (e.g., on the true branch of
// `err != nil`, err is NonNil) override global state — they are strictly more
// precise. However, a block-local Top (from the uncertain branch of a compound
// condition like AND-false) should NOT override a more precise global state
// (e.g., Src is globally NonNil). In that case, we fall through to global.
func (a *analyzer) getNilnessInBlock(v ssa.Value, block *ssa.BasicBlock) nilness {
	bs := a.getBlockState(block)
	if bs.nilFacts != nil {
		if localNil, ok := bs.nilFacts[v]; ok {
			if localNil != nlTop {
				return localNil // Definite assertion (Nil/NonNil) — use it
			}
			// Local is Top (uncertain branch). Use global if more precise.
			globalNil := a.getValueState(v).getNilness()
			if globalNil == nlNil || globalNil == nlNonNil {
				return globalNil
			}
			return nlTop
		}
	}

	// Fall back to global state
	return a.getValueState(v).getNilness()
}

// addToSSAWorklist adds an instruction to the worklist for re-evaluation.
func (a *analyzer) addToSSAWorklist(instr ssa.Instruction) {
	if a.onSSAWorklist[instr] {
		return
	}
	a.onSSAWorklist[instr] = true
	a.ssaWorklist = append(a.ssaWorklist, instr)
}

// propagateToUses adds all users of v to the SSA worklist if their block is
// executable. This includes both value-producing instructions and terminators
// (If, Jump), so that changes to a condition re-evaluate the branch.
// Also propagates through memory: if v is stored to a tracked error alloc,
// all loads from that alloc are scheduled for re-evaluation.
func (a *analyzer) propagateToUses(v ssa.Value) {
	refs := v.Referrers()
	if refs == nil {
		return
	}
	for _, ref := range *refs {
		if _, ok := ref.(*ssa.DebugRef); ok {
			continue
		}
		// Propagate through stores: if v is stored to a tracked address,
		// re-evaluate all loads from that address.
		if store, ok := ref.(*ssa.Store); ok && store.Val == v {
			if a.isTrackedErrorAddr(store.Addr) {
				a.visitStore(store)
			}
			continue
		}
		if a.getBlockState(ref.Block()).executable {
			a.addToSSAWorklist(ref)
		}
	}
}

// processBlock processes all instructions in a block that has become executable.
// PHI nodes are processed first with parallel semantics, then all remaining
// instructions (including terminators) are visited in order.
func (a *analyzer) processBlock(b *ssa.BasicBlock) {
	// Process all PHI nodes first with parallel semantics.
	// Read all RHS values before updating any LHS.
	a.visitPhisInBlock(b)

	// Process remaining instructions in order (non-PHIs, including terminators).
	for _, instr := range b.Instrs {
		if _, ok := instr.(*ssa.Phi); ok {
			continue // Already processed in visitPhisInBlock
		}
		a.visitInstruction(instr)
	}
}

// visitPhisInBlock processes all PHI nodes in a block with parallel semantics.
// This ensures that all RHS values are read before any LHS is updated, which is
// critical for correctness when multiple PHIs in the same block reference each other.
func (a *analyzer) visitPhisInBlock(b *ssa.BasicBlock) {
	type phiResult struct {
		phi  *ssa.Phi
		eval valState
	}
	var results []phiResult

	for _, instr := range b.Instrs {
		phi, ok := instr.(*ssa.Phi)
		if !ok {
			continue
		}
		results = append(results, phiResult{phi: phi, eval: a.evalPhi(phi)})
	}

	for _, r := range results {
		a.updateValueState(r.phi, &r.eval)
	}
}

// visitInstruction evaluates an SSA instruction to update abstract state.
// For value-producing instructions, uses eval + updateValueState pattern.
// For terminators (If, Jump), evaluates branch feasibility and marks successors.
func (a *analyzer) visitInstruction(instr ssa.Instruction) {
	switch i := instr.(type) {
	// Value-producing instructions
	case *ssa.Call:
		if v := ssa.Value(i); a.sources.isRoot(v) {
			// Root RPC sources are not re-evaluated; their lattice values
			// are pinned at pre-initialization (preInitializeErrorValues):
			//   - Src: NonNil (forward mode) or Nil (inverse mode)
			//   - OtherSrc after Src: Nil if NilOtherSourcesAfterSrc, else Top
			//   - OtherSrc before Src: always Top
			// Just propagate the pre-initialized value to uses.
			a.propagateToUses(v)
			return
		}
		eval := a.evalCall(i)
		a.updateValueState(i, &eval)
	case *ssa.Extract:
		if v := ssa.Value(i); a.sources.isRoot(v) {
			// Same as *ssa.Call root handling above — propagate pinned value.
			a.propagateToUses(v)
			return
		}
		eval := a.evalExtract(i)
		a.updateValueState(i, &eval)
	case *ssa.Phi:
		eval := a.evalPhi(i)
		a.updateValueState(i, &eval)
	case *ssa.BinOp:
		eval := a.evalBinOp(i)
		a.updateValueState(i, &eval)
	case *ssa.UnOp:
		eval := a.evalUnOp(i)
		a.updateValueState(i, &eval)
	case *ssa.ChangeType:
		eval := a.evalPassthrough(i.X)
		a.updateValueState(i, &eval)
	case *ssa.Convert:
		eval := a.evalPassthrough(i.X)
		a.updateValueState(i, &eval)
	case *ssa.MakeInterface:
		eval := a.evalPassthrough(i.X)
		a.updateValueState(i, &eval)
	case *ssa.ChangeInterface:
		eval := a.evalPassthrough(i.X)
		a.updateValueState(i, &eval)
	case *ssa.TypeAssert:
		eval := a.evalPassthrough(i.X)
		a.updateValueState(i, &eval)

	// Terminators
	case *ssa.If:
		a.visitIf(i)
	case *ssa.Jump:
		a.visitJump(i)
	case *ssa.Return:
		// Return is a sink, nothing to propagate.

	// Memory operations
	case *ssa.Store:
		a.visitStore(i)

	// Allocation / construction instructions always produce non-nil values.
	case *ssa.Alloc, *ssa.MakeMap, *ssa.MakeSlice, *ssa.MakeChan, *ssa.MakeClosure:
		v := instr.(ssa.Value)
		vs := a.getValueState(v)
		if vs.lattice == nil || vs.lattice.isLatticeBottom() {
			vs.lattice = nlNonNil
			a.propagateToUses(v)
		}

	default:
		// For other value-producing instructions, default to Top.
		if v, ok := instr.(ssa.Value); ok {
			vs := a.getValueState(v)
			if vs.lattice == nil || vs.lattice.isLatticeBottom() {
				if a.isBoolType(v.Type()) {
					vs.lattice = boolTop
				} else {
					vs.lattice = nlTop
				}
				a.propagateToUses(v)
			}
		}
	}
}

// =============================================================================
// Pure Eval Functions
// =============================================================================
//
// Each eval* function computes a fresh valState from operands without mutating
// existing state. The caller uses updateValueState to join the result into the
// lattice and propagate if changed.

// evalPhi computes a fresh valState by joining all feasible edges of a Phi node.
// Handles lattice, dataSources, isSynthetic, and nilInfo (intersection).
func (a *analyzer) evalPhi(phi *ssa.Phi) valState {
	result := valState{
		dataSources: newSourceSet(),
		isSynthetic: synthBottom,
	}

	var edgeInfos []nilCheckInfo

	for i, edge := range phi.Edges {
		pred := phi.Block().Preds[i]
		feasible := a.isEdgeFeasible(pred, phi.Block())
		a.debugw("SCCP: evalPhi edge",
			"fn", a.fn.Name(),
			"phi", phi.Name(),
			"phiBlock", phi.Block().Index,
			"pred", pred.Index,
			"feasible", feasible,
			"edgeVal", describeValue(edge),
		)
		if !feasible {
			continue
		}
		edgeVS := a.getValueState(edge)
		result.lattice = joinLatticeVals(result.lattice, edgeVS.lattice)
		result.dataSources.union(edgeVS.dataSources)
		result.isSynthetic = result.isSynthetic.join(edgeVS.isSynthetic)

		edgeInfos = append(edgeInfos, edgeVS.nilInfo)
	}

	// Try short-circuit AND/OR detection before falling back to intersection.
	// Go SSA decomposes && and || into control flow + Phi. The pattern is:
	//   AND: phi [pred_false: false, pred_true: rhs_val]
	//   OR:  phi [pred_true:  true,  pred_false: rhs_val]
	// We detect this pattern and reconstruct the compound nilCheckInfo.
	if scInfo, ok := a.detectShortCircuitPhi(phi); ok {
		result.nilInfo = scInfo
	} else {
		// Propagate nil check info: only checks that ALL feasible edges agree on
		result.nilInfo = intersectNilChecks(edgeInfos)
	}

	return result
}

// detectShortCircuitPhi detects the SSA pattern for short-circuit && and ||.
//
// Go SSA decomposes `b := e1 != nil && e2 != nil` into:
//
//	block0: t2 = e1!=nil;   if t2 goto block1 else block2
//	block1: t3 = e2!=nil;   jump block2
//	block2: t4 = phi [block0: false, block1: t3]   // AND pattern
//
// Similarly for OR:
//
//	block0: t2 = e1!=nil;   if t2 goto block2 else block1
//	block1: t3 = e2!=nil;   jump block2
//	block2: t4 = phi [block0: true, block1: t3]    // OR pattern
//
// This function detects these patterns and reconstructs a compound nilCheckInfo
// by unioning the If condition's nilInfo with the non-constant edge's nilInfo.
// For nested short-circuits, this composes naturally since inner Phis already
// have their nilInfo reconstructed.
//
// Mixed conjunctive modes (e.g., (a||b) && c) are handled conservatively:
// only checks whose conjunctive mode matches the outer pattern are included.
func (a *analyzer) detectShortCircuitPhi(phi *ssa.Phi) (nilCheckInfo, bool) {
	// Step 1: Collect feasible edges
	type feasibleEdge struct {
		predIndex int
		pred      *ssa.BasicBlock
		edgeVal   ssa.Value
	}
	var feasible []feasibleEdge
	for i, edge := range phi.Edges {
		pred := phi.Block().Preds[i]
		if a.isEdgeFeasible(pred, phi.Block()) {
			feasible = append(feasible, feasibleEdge{i, pred, edge})
		}
	}
	if len(feasible) != 2 {
		return nilCheckInfo{}, false
	}

	// Step 2: Identify which edge (if any) is a boolean constant
	var constIdx, otherIdx int
	var isAND bool
	foundConst := false

	for i, fe := range feasible {
		if _, ok := fe.edgeVal.(*ssa.Const); !ok {
			continue
		}
		vs := a.getValueState(fe.edgeVal)
		bs := vs.getBoolState()
		if bs == boolFalse {
			isAND = true
			constIdx = i
			otherIdx = 1 - i
			foundConst = true
			break
		} else if bs == boolTrue {
			isAND = false
			constIdx = i
			otherIdx = 1 - i
			foundConst = true
			break
		}
	}
	if !foundConst {
		return nilCheckInfo{}, false
	}

	// Step 3: The constant edge's predecessor must have an If terminator
	// whose condition's nilInfo we want to capture.
	constPred := feasible[constIdx].pred
	ifInstr, ok := constPred.Instrs[len(constPred.Instrs)-1].(*ssa.If)
	if !ok {
		return nilCheckInfo{}, false
	}
	ifCondVS := a.getValueState(ifInstr.Cond)
	ifCondInfo := ifCondVS.nilInfo

	// Step 4: Get the non-constant edge's nilInfo
	otherEdgeVS := a.getValueState(feasible[otherIdx].edgeVal)
	otherInfo := otherEdgeVS.nilInfo

	// Step 5: Union compatible checks
	targetConj := isAND
	checks := make(map[ssa.Value]nilCheckType)

	// Include If condition's checks if compatible
	if len(ifCondInfo.checks) > 0 && (len(ifCondInfo.checks) <= 1 || ifCondInfo.conjunctive == targetConj) {
		for k, v := range ifCondInfo.checks {
			checks[k] = v
		}
	}

	// Include other edge's checks if compatible
	if len(otherInfo.checks) > 0 && (len(otherInfo.checks) <= 1 || otherInfo.conjunctive == targetConj) {
		for k, v := range otherInfo.checks {
			if existing, ok := checks[k]; ok && existing != v {
				// Contradiction — drop this check
				delete(checks, k)
			} else {
				checks[k] = v
			}
		}
	}

	if len(checks) == 0 {
		return nilCheckInfo{}, false
	}

	return nilCheckInfo{checks: checks, conjunctive: targetConj}, true
}

// evalCall computes a fresh valState for a Call instruction.
//   - Wrap-like functions (including fmt.Errorf): propagate sources from error arguments;
//     fmt.Errorf is always NonNil, others join nilness from args
//   - Functions returning error whose actual args carry error sources: propagate those sources
//   - Other calls: Top nilness, no sources
func (a *analyzer) evalCall(call *ssa.Call) valState {
	result := valState{
		dataSources: newSourceSet(),
		isSynthetic: synthBottom,
	}

	callee := call.Call.StaticCallee()

	// Wrap-like functions: propagate sources from error arguments.
	if a.isWrapLike(callee) {
		for _, arg := range call.Call.Args {
			argVS := a.getValueState(arg)
			// Only join nilness from arguments (call results are error-typed, not bools).
			argNilness := argVS.getNilness()
			if argNilness != nlBottom {
				result.lattice = joinLatticeVals(result.lattice, argNilness)
			}
			result.dataSources.union(argVS.dataSources)
			result.isSynthetic = result.isSynthetic.join(argVS.isSynthetic)

			// For varargs slices, also collect sources from values stored into the array.
			a.collectVarargsSources(arg, &result)
		}
		// Error constructors that always produce a non-nil error regardless of
		// the nilness of their error parameter. The wrap-like join above would
		// incorrectly conclude nil-in → nil-out for these.
		// TODO: replace this hardcoded list with a generalized
		// constructor-vs-wrapper detection (e.g. inspect the body to see whether
		// the error param is returned through any path, or use a curated registry
		// of known error constructors).
		if callee != nil {
			switch callee.String() {
			case "fmt.Errorf":
				result.lattice = nlNonNil
			default:
				if slices.Contains(a.opts.KnownErrorConstructorFuncs, callee.String()) {
					result.lattice = nlNonNil
				}
			}
		}
		return result
	}

	// For functions returning error that aren't signature-matched as wrap-like,
	// check if any actual argument (including through varargs) carries error sources.
	// This handles patterns like errors.New(code, fmt, err) where err is boxed into interface{}.
	if callee != nil && a.returnsError(callee) {
		for _, arg := range call.Call.Args {
			argVS := a.getValueState(arg)
			result.dataSources.union(argVS.dataSources)
			result.isSynthetic = result.isSynthetic.join(argVS.isSynthetic)
			a.collectVarargsSources(arg, &result)
		}
		if !result.dataSources.isEmpty() {
			// At least one arg carries error sources — treat as wrap-like for source propagation.
			// Use Top nilness since we don't know the function's nil behavior.
			result.lattice = nlTop
			return result
		}
	}

	// Interface method calls (invoke): StaticCallee() is nil, but we can check
	// the method signature. If it returns error and any arg carries error sources,
	// propagate those sources through the call.
	if callee == nil && call.Call.IsInvoke() {
		method := call.Call.Method
		if method != nil && a.methodReturnsError(method) {
			// Check if the method signature takes an error param (wrap-like).
			if a.methodIsWrapLike(method) {
				for _, arg := range call.Call.Args {
					argVS := a.getValueState(arg)
					argNilness := argVS.getNilness()
					if argNilness != nlBottom {
						result.lattice = joinLatticeVals(result.lattice, argNilness)
					}
					result.dataSources.union(argVS.dataSources)
					result.isSynthetic = result.isSynthetic.join(argVS.isSynthetic)
					a.collectVarargsSources(arg, &result)
				}
				return result
			}
			// Not signature-matched, but check if any arg carries error sources.
			for _, arg := range call.Call.Args {
				argVS := a.getValueState(arg)
				result.dataSources.union(argVS.dataSources)
				result.isSynthetic = result.isSynthetic.join(argVS.isSynthetic)
				a.collectVarargsSources(arg, &result)
			}
			if !result.dataSources.isEmpty() {
				result.lattice = nlTop
				return result
			}
		}
	}

	// Unrecognized calls: set to Top nilness
	result.lattice = nlTop
	return result
}

// collectVarargsSources traces a varargs slice argument back through its
// underlying array allocation to collect data sources from all stored values.
// Pattern: alloc [N]T → IndexAddr → Store val → Slice [:]
func (a *analyzer) collectVarargsSources(arg ssa.Value, result *valState) {
	sliceInstr, ok := arg.(*ssa.Slice)
	if !ok {
		return
	}
	alloc, ok := sliceInstr.X.(*ssa.Alloc)
	if !ok {
		return
	}
	refs := alloc.Referrers()
	if refs == nil {
		return
	}
	for _, ref := range *refs {
		idxAddr, ok := ref.(*ssa.IndexAddr)
		if !ok {
			continue
		}
		idxRefs := idxAddr.Referrers()
		if idxRefs == nil {
			continue
		}
		for _, idxRef := range *idxRefs {
			store, ok := idxRef.(*ssa.Store)
			if !ok {
				continue
			}
			storedVS := a.getValueState(store.Val)
			result.dataSources.union(storedVS.dataSources)
			result.isSynthetic = result.isSynthetic.join(storedVS.isSynthetic)
		}
	}
}

// evalExtract computes a fresh valState for an Extract instruction.
// Only error-typed extracts inherit nilness, dataSources, and isSynthetic from
// the tuple. Non-error extracts stay at bottom so wrap-like nilness doesn't
// leak to unrelated return values.
func (a *analyzer) evalExtract(extract *ssa.Extract) valState {
	tupleVS := a.getValueState(extract.Tuple)

	result := valState{
		dataSources: newSourceSet(),
		isSynthetic: synthBottom,
	}

	// Only propagate nilness, sources, and synthetic flag for error-typed extracts.
	if a.isErrorType(extract.Type()) {
		result.lattice = tupleVS.lattice
		result.dataSources.union(tupleVS.dataSources)
		result.isSynthetic = tupleVS.isSynthetic
	}

	return result
}

// evalBinOp computes a fresh valState for a BinOp instruction.
//   - EQL/NEQ nil check: set nilInfo singleton, compute lattice from testVal nilness.
//   - Default: boolTop.
//
// Note: Go SSA never produces LAND/LOR BinOps — it decomposes && and || into
// control flow + Phi. Short-circuit logic is handled in detectShortCircuitPhi.
func (a *analyzer) evalBinOp(binop *ssa.BinOp) valState {
	result := valState{
		dataSources: newSourceSet(),
		isSynthetic: synthBottom,
	}

	// Handle nil comparisons (== or !=)
	if binop.Op == token.EQL || binop.Op == token.NEQ {
		var testVal ssa.Value
		isNilCheck := false

		if a.isNilConst(binop.X) {
			testVal = binop.Y
			isNilCheck = true
		} else if a.isNilConst(binop.Y) {
			testVal = binop.X
			isNilCheck = true
		}

		if isNilCheck {
			// Record what nil check this boolean represents (singleton map)
			checks := make(map[ssa.Value]nilCheckType, 1)
			if binop.Op == token.NEQ {
				checks[testVal] = checkNeqNil
			} else {
				checks[testVal] = checkEqNil
			}
			result.nilInfo = nilCheckInfo{checks: checks, conjunctive: true}

			testVS := a.getValueState(testVal)
			result.dataSources.union(testVS.dataSources)

			switch testVS.getNilness() {
			case nlNonNil:
				if binop.Op == token.NEQ {
					result.lattice = boolTrue
				} else {
					result.lattice = boolFalse
				}
				return result
			case nlNil:
				if binop.Op == token.NEQ {
					result.lattice = boolFalse
				} else {
					result.lattice = boolTrue
				}
				return result
			}
			// For Top nilness, fall through to default handling but keep sources and check info.
		}
	}

	// Default: boolTop for unknown/indeterminate comparisons.
	result.lattice = boolTop
	return result
}

// evalUnOp computes a fresh valState for a UnOp instruction.
//   - NOT: negate bool lattice, flip nilInfo, copy dataSources.
//   - MUL (pointer deref/load): resolve from memState if address is a tracked error alloc.
//   - Other: nlTop.
func (a *analyzer) evalUnOp(unop *ssa.UnOp) valState {
	result := valState{
		dataSources: newSourceSet(),
		isSynthetic: synthBottom,
	}

	if unop.Op == token.NOT {
		xVS := a.getValueState(unop.X)
		result.lattice = xVS.getBoolState().negate()
		result.dataSources.union(xVS.dataSources)
		result.nilInfo = flipNilChecks(xVS.nilInfo)
		return result
	}

	// Pointer dereference (load): resolve from forward-propagated memory state.
	if unop.Op == token.MUL {
		if storedVS, ok := a.memState[unop.X]; ok {
			a.debugw("SCCP: evalUnOp MUL resolved from memState",
				"addr", describeValue(unop.X),
				"block", unop.Block().Index,
				"storedNilness", storedVS.lattice,
				"storedSources", storedVS.dataSources.len(),
			)
			resolved := valState{
				lattice:     storedVS.lattice,
				dataSources: newSourceSet(),
				isSynthetic: storedVS.isSynthetic,
				nilInfo:     storedVS.nilInfo,
			}
			resolved.dataSources.union(storedVS.dataSources)

			// When global memState joined to Top (conflicting stores across
			// blocks), refine with block-local store: walk backward within
			// the block to find the last store to this address before the
			// load. Its RHS nilness is more precise than the global join.
			if n, ok := resolved.lattice.(nilness); ok && n == nlTop {
				if localVS, ok := a.resolveBlockLocalStore(unop); ok {
					a.debugw("SCCP: evalUnOp MUL refined by block-local store",
						"addr", describeValue(unop.X),
						"block", unop.Block().Index,
						"globalNilness", resolved.lattice,
						"localNilness", localVS.lattice,
						"localSources", localVS.dataSources.len(),
					)
					return localVS
				}
			}

			return resolved
		}
	}

	// Default: Top for other operations.
	result.lattice = nlTop
	return result
}

// resolveBlockLocalStore walks backward through the block's instructions from
// the load (UnOp MUL) to find the last Store to the same address. When the
// global memState has joined stores from multiple blocks to Top, this recovers
// the precise nilness from the block-local store.
//
// If a RunDefers instruction appears between the last store and the load and
// the address is modifiable by a dominating deferred closure, the optimization
// is skipped.
func (a *analyzer) resolveBlockLocalStore(load *ssa.UnOp) (valState, bool) {
	block := load.Block()
	addr := load.X
	instrs := block.Instrs

	hasRunDefers := false
	seen := false
	for i := len(instrs) - 1; i >= 0; i-- {
		if instrs[i] == load {
			seen = true
			continue
		}
		if !seen {
			continue
		}
		if _, ok := instrs[i].(*ssa.RunDefers); ok {
			hasRunDefers = true
		}
		if store, ok := instrs[i].(*ssa.Store); ok && store.Addr == addr {
			if hasRunDefers && isAddrModifiableByRunDefers(addr, block) {
				return valState{}, false
			}
			storedVS := a.getValueState(store.Val)
			result := valState{
				lattice:     storedVS.lattice,
				dataSources: newSourceSet(),
				isSynthetic: storedVS.isSynthetic,
				nilInfo:     storedVS.nilInfo,
			}
			result.dataSources.union(storedVS.dataSources)
			return result, true
		}
	}
	return valState{}, false
}

// isAddrModifiableByRunDefers reports whether a RunDefers in loadBlock could
// modify addr. This is true when addr is bound into a closure that is
// registered as a defer dominating loadBlock, AND that closure stores to
// the corresponding FreeVar. We only check for the presence of a Store
// instruction to the FreeVar, not what value is stored; any write is
// treated as a potential modification.
func isAddrModifiableByRunDefers(addr ssa.Value, loadBlock *ssa.BasicBlock) bool {
	refs := addr.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		mc, ok := ref.(*ssa.MakeClosure)
		if !ok {
			continue
		}
		if !isDeferredAndDominates(mc, loadBlock) {
			continue
		}
		closureFn, ok := mc.Fn.(*ssa.Function)
		if !ok {
			continue
		}
		bindingIdx := -1
		for i, b := range mc.Bindings {
			if b == addr {
				bindingIdx = i
				break
			}
		}
		if bindingIdx < 0 || bindingIdx >= len(closureFn.FreeVars) {
			continue
		}
		fv := closureFn.FreeVars[bindingIdx]
		fvRefs := fv.Referrers()
		if fvRefs == nil {
			continue
		}
		for _, fvRef := range *fvRefs {
			if st, ok := fvRef.(*ssa.Store); ok && st.Addr == fv {
				return true
			}
		}
	}
	return false
}

// isDeferredAndDominates reports whether mc (a MakeClosure) is used as the
// argument to a Defer instruction whose block dominates target.
func isDeferredAndDominates(mc *ssa.MakeClosure, target *ssa.BasicBlock) bool {
	refs := mc.Referrers()
	if refs == nil {
		return false
	}
	for _, ref := range *refs {
		if d, ok := ref.(*ssa.Defer); ok {
			if d.Block().Dominates(target) {
				return true
			}
		}
	}
	return false
}

// visitStore processes a Store instruction during SCCP.
// For stores to error-typed or pointer-to-error allocs, updates the memory state
// and schedules all loads from the same address for re-evaluation.
// This enables forward propagation of error values through memory, handling
// patterns like named returns with defer where Go SSA generates store-then-load chains.
func (a *analyzer) visitStore(store *ssa.Store) {
	if !a.isTrackedErrorAddr(store.Addr) {
		return
	}
	storedVS := a.getValueState(store.Val)
	if existing, ok := a.memState[store.Addr]; ok {
		// Join: accumulate data sources and nilness from all stores to this address.
		existing.lattice = joinLatticeVals(existing.lattice, storedVS.lattice)
		existing.dataSources.union(storedVS.dataSources)
		existing.isSynthetic = existing.isSynthetic.join(storedVS.isSynthetic)
	} else {
		vs := valState{
			lattice:     storedVS.lattice,
			dataSources: newSourceSet(),
			isSynthetic: storedVS.isSynthetic,
			nilInfo:     storedVS.nilInfo,
		}
		vs.dataSources.union(storedVS.dataSources)
		a.memState[store.Addr] = &vs
	}
	a.debugw("SCCP: visitStore updated memState",
		"addr", describeValue(store.Addr),
		"storedVal", describeValue(store.Val),
		"block", store.Block().Index,
	)
	// Schedule all loads (UnOp MUL) from this address for re-evaluation.
	a.scheduleLoadsFromAddr(store.Addr)
}

// isTrackedErrorAddr returns true if the address is an Alloc or FreeVar whose
// element type is error or pointer-to-error. Allocs are created for named return
// variables that hold error values; FreeVars are created for closure-captured
// error variables (e.g., captured `err error` has type *error).
func (a *analyzer) isTrackedErrorAddr(addr ssa.Value) bool {
	switch addr.(type) {
	case *ssa.Alloc, *ssa.FreeVar:
		// ok
	default:
		return false
	}
	ptrType, ok := addr.Type().(*types.Pointer)
	if !ok {
		return false
	}
	elemType := ptrType.Elem()
	// error type (e.g., named return `err error` → alloc *error)
	if a.isErrorType(elemType) {
		return true
	}
	// pointer-to-error type (e.g., if a named return is *error → alloc **error)
	if inner, ok := elemType.(*types.Pointer); ok {
		return a.isErrorType(inner.Elem())
	}
	return false
}

// scheduleLoadsFromAddr finds all UnOp MUL instructions that load from the given
// address and adds them to the SSA worklist for re-evaluation.
func (a *analyzer) scheduleLoadsFromAddr(addr ssa.Value) {
	refs := addr.Referrers()
	if refs == nil {
		return
	}
	for _, ref := range *refs {
		unop, ok := ref.(*ssa.UnOp)
		if ok && unop.Op == token.MUL && a.getBlockState(unop.Block()).executable {
			a.addToSSAWorklist(unop)
		}
	}
}

// evalPassthrough computes a fresh valState by copying all fields from the operand's state.
// Used for ChangeType, Convert, MakeInterface, TypeAssert.
func (a *analyzer) evalPassthrough(x ssa.Value) valState {
	xVS := a.getValueState(x)
	result := valState{
		lattice:     xVS.lattice,
		dataSources: newSourceSet(),
		isSynthetic: xVS.isSynthetic,
		nilInfo:     xVS.nilInfo,
	}
	result.dataSources.union(xVS.dataSources)
	return result
}

// visitIf processes an If terminator, determining which successor blocks are executable
// and propagating refined nilness facts to each branch based on the condition.
func (a *analyzer) visitIf(ifInstr *ssa.If) {
	block := ifInstr.Block()
	trueBlk := block.Succs[0]
	falseBlk := block.Succs[1]

	condVS := a.getValueState(ifInstr.Cond)

	a.debugw("SCCP: visitIf",
		"fn", a.fn.Name(),
		"block", block.Index,
		"cond", describeValue(ifInstr.Cond),
		"boolState", condVS.getBoolState(),
		"trueBlk", trueBlk.Index,
		"falseBlk", falseBlk.Index,
	)

	// Get current block's facts to propagate forward
	currentFacts := a.getBlockFacts(block)

	// Get nil check info from the condition's value state (already propagated)
	nilInfo := condVS.nilInfo

	// On-demand: at predecessor boundaries, force branch conditions so the path
	// to srcBlock is always taken. Only applies at blocks strictly before srcBlock
	// (predecessors that are NOT successors). If one successor is a transitive
	// predecessor of srcBlock and the other is not, force the condition toward
	// the predecessor side. In loops, srcBlock is its own successor via back-edges,
	// so forcing is skipped — SCCP resolves conditions normally.
	if !a.srcSuccs[block.Index] {
		trueIsPred := a.srcPreds[trueBlk.Index]
		falseIsPred := a.srcPreds[falseBlk.Index]
		if trueIsPred && !falseIsPred {
			condVS.lattice = boolTrue
		} else if falseIsPred && !trueIsPred {
			condVS.lattice = boolFalse
		}
	}

	switch condVS.getBoolState() {
	case boolTrue:
		// Only true branch is feasible
		trueFacts := a.refineFacts(currentFacts, nilInfo, true)
		a.propagateFactsToBlockFromEdge(block, trueBlk, trueFacts)

	case boolFalse:
		// Only false branch is feasible
		falseFacts := a.refineFacts(currentFacts, nilInfo, false)
		a.propagateFactsToBlockFromEdge(block, falseBlk, falseFacts)

	default:
		// Both branches feasible - propagate refined facts to each
		trueFacts := a.refineFacts(currentFacts, nilInfo, true)
		falseFacts := a.refineFacts(currentFacts, nilInfo, false)
		a.propagateFactsToBlockFromEdge(block, trueBlk, trueFacts)
		a.propagateFactsToBlockFromEdge(block, falseBlk, falseFacts)
	}
}

// visitJump processes a Jump terminator, propagating the current block's facts
// to the single successor block.
func (a *analyzer) visitJump(jump *ssa.Jump) {
	// Propagate current block's facts to successor
	block := jump.Block()
	currentFacts := a.getBlockFacts(block)
	a.propagateFactsToBlockFromEdge(block, block.Succs[0], currentFacts)
}

// =============================================================================
// Phase 2: Non-Suppression Check
// =============================================================================

// isNonNil checks whether a nilness value satisfies the non-nil requirement
// under the current analysis mode. Used in forward analysis where Src is NonNil.
//   - Strict mode (MaybeAnalysisMode=false): only nlNonNil satisfies.
//   - Lenient mode (MaybeAnalysisMode=true):  nlNonNil or nlTop satisfies
//     (anything not proven nil is "maybe non-nil").
func (a *analyzer) isNonNil(n nilness) bool {
	if n == nlNonNil {
		return true
	}
	return a.opts.MaybeAnalysisMode && n == nlTop
}

// isMaybeNil returns true if the nilness value indicates "maybe nil".
// Used in inverse analysis where Src is Nil.
//   - nlNil: definitely nil → true
//   - nlNonNil: definitely non-nil → false
//   - nlTop: unknown → true if MaybeAnalysisMode (lenient), false otherwise (strict)
//   - nlBottom: uncomputed → true (conservative)
func (a *analyzer) isMaybeNil(n nilness) bool {
	switch n {
	case nlNil:
		return true
	case nlNonNil:
		return false
	case nlTop:
		return a.opts.MaybeAnalysisMode
	default: // nlBottom
		return true
	}
}

// checkNonSuppression verifies that the return value is provably non-nil
// (or maybe non-nil in May mode). Returns true if non-suppression is satisfied.
func (a *analyzer) checkNonSuppression(ret *ssa.Return, retVal ssa.Value) bool {
	// First, check block-local facts (from assertion propagation).
	blockNilness := a.getNilnessInBlock(retVal, ret.Block())

	if blockNilness == nlNil {
		return false // Proven nil - definitely fails non-suppression
	}
	if a.isNonNil(blockNilness) {
		return true // Proven non-nil (or maybe non-nil in May mode)
	}

	// Block-local fact is Bottom or Top (Must mode), check global state.
	retVS := a.getValueState(retVal)
	if a.isNonNil(retVS.getNilness()) {
		return true
	}

	// Still unknown (Top in Must mode) - try to prove non-nil via control guard.
	if retVS.getNilness() == nlTop || blockNilness == nlTop {
		return a.proveNonNilByControlGuard(ret, retVal)
	}

	// nilness is Nil or Bottom - not non-nil.
	return false
}

// proveNonNilByControlGuard tries to prove retVal is non-nil using control dependence.
// Uses the CDG to find which conditions control this return, then checks if any
// of them guard retVal with a nil check on the non-nil branch.
func (a *analyzer) proveNonNilByControlGuard(ret *ssa.Return, retVal ssa.Value) bool {
	a.ensureInverseCDG()

	block := ret.Block()
	paths, limitHit := a.inverseCDG.GetControllerPathsWithLimit(block, a.opts.MaxCDGPaths)
	_ = limitHit && a.infow("SCCP: CDG path limit hit in proveNonNilByControlGuard",
		"fn", a.fn.Name(), "retBlock", block.Index,
		"limit", a.opts.MaxCDGPaths, "paths", len(paths))

	// Check all paths from controlled block to transitive controllers
	for _, path := range paths {
		// Walk path from innermost to outermost
		for _, edge := range path {
			if !a.getBlockState(edge.Controller).executable {
				continue
			}

			ifInstr, ok := a.terminatingIf(edge.Controller)
			if !ok {
				continue
			}

			// Check if this If guards retVal
			condVS := a.getValueState(ifInstr.Cond)

			// Check if any of the nil checks in the condition match retVal
			for checkedVal, checkType := range condVS.nilInfo.checks {
				if checkedVal != retVal {
					continue
				}

				if isErrorBranch(edge.SuccIndex, checkType) {
					return true // Found a guard proving retVal is non-nil
				}
			}
		}
	}

	return false
}

// =============================================================================
// Phase 3: Causal Attribution
// =============================================================================
//
// Determines whether a returned error at return statement r is causally
// attributed to Src, written Attr(r, Src). Combines data-flow (source
// tracking) with control-flow (CDG or dominator tree) analysis.
//
// PRECONDITION: Phase 2 (Non-Suppression) has proven RetErr is non-nil.
//
// Given return statement r with returned error value RetErr:
//
//   Case 1 — Exclusive data attribution:
//     DataSources(RetErr) = {Src}
//     → Attr(r, Src) holds unconditionally.
//
//   Case 2 — Ambiguous data attribution:
//     Src ∈ DataSources(RetErr) ∧ |DataSources(RetErr)| > 1
//     → Attr(r, Src) holds iff for every S ∈ DataSources(RetErr) \ {Src},
//       the assertion facts at r's block entail S = nil.
//
//   Case 3 — Control attribution (fallback):
//     DataSources(RetErr) ∩ {Src} = ∅, either because:
//       (a) DataSources(RetErr) = ∅ (RetErr is synthetic), or
//       (b) all sources in DataSources(RetErr) are proven nil.
//     → Walk the inverse CDG from r's block. Let cⱼ be the first controller whose
//       If condition is a nil-check of a value v where v = Src or
//       Src ∈ DataSources(v), on the error branch:
//         - If cⱼ tests Src: Attr(r, Src) holds.
//         - If cⱼ tests another source: Attr(r, Src) does NOT hold.
//         - If no such cⱼ exists: Attr(r, Src) does NOT hold.

// checkAttribution determines whether a returned error is causally attributed to Src.
func (a *analyzer) checkAttribution(ret *ssa.Return, retVal ssa.Value) bool {
	retVS := a.getValueState(retVal)

	a.infow("SCCP: checkAttribution",
		"fn", a.fn.Name(), "block", ret.Block().Index,
		"retVal", describeValue(retVal),
		"numDataSources", retVS.dataSources.len(),
		"hasSrc", retVS.dataSources.contains(a.sources.srcID()),
		"srcID", describeValue(a.sources.srcID()),
	)

	// RetErr derived ONLY from Src
	if retVS.dataSources.len() == 1 && retVS.dataSources.contains(a.sources.srcID()) {
		a.opts.Metrics.IncDataAttrCount()
		a.opts.Metrics.IncDataAttrPass()
		return true
	}

	// RetErr derived from Src + OtherSources
	if retVS.dataSources.contains(a.sources.srcID()) {
		a.opts.Metrics.IncDataAttrCount()
		a.allOtherSourcesNilInBlock(ret.Block(), retVS.dataSources, a.sources.srcID()) // side effect: logged for debugging
		a.opts.Metrics.IncDataAttrPass()
		return true
	}

	// RetErr NOT derived from Src: fall back to control dependence
	if retVS.dataSources.isEmpty() {
		a.infow("SCCP: checkAttribution falling back to CDG (empty sources)",
			"fn", a.fn.Name(), "block", ret.Block().Index)
		a.opts.Metrics.IncControlAttrCount()
		if a.checkControlAttribution(ret) {
			a.opts.Metrics.IncControlAttrPass()
			return true
		}
		a.opts.Metrics.IncControlAttrFail()
		return false
	}

	// RetErr derived from OtherSources only: check if they're all ruled out
	if a.allOtherSourcesNilInBlock(ret.Block(), retVS.dataSources, a.sources.srcID()) {
		a.debugw("SCCP: checkAttribution falling back to CDG (other sources nil)",
			"fn", a.fn.Name(), "block", ret.Block().Index)
		a.opts.Metrics.IncControlAttrCount()
		if a.checkControlAttribution(ret) {
			a.opts.Metrics.IncControlAttrPass()
			return true
		}
		a.opts.Metrics.IncControlAttrFail()
		return false
	}

	a.debugw("SCCP: checkAttribution failed (other sources not nil)",
		"fn", a.fn.Name(), "block", ret.Block().Index)
	return false
}

// allOtherSourcesNilInBlock checks if every source except excludeSrc has a
// Nil assertion fact in the given block, ruling them out as error contributors.
func (a *analyzer) allOtherSourcesNilInBlock(block *ssa.BasicBlock, sources sourceSet, excludeSrc sourceID) bool {
	bs := a.getBlockState(block)

	for src := range sources {
		if src == excludeSrc {
			continue
		}
		if bs.nilFacts == nil {
			return false
		}
		if nilness, ok := bs.nilFacts[src]; !ok || nilness != nlNil {
			return false
		}
	}

	return true
}

// checkControlAttribution walks the inverse CDG to determine if Src controls
// this return. For each control dependence path from the return block to its
// transitive controllers, checks whether Src's nil check guards this return
// on the error branch.
func (a *analyzer) checkControlAttribution(ret *ssa.Return) bool {
	a.ensureInverseCDG()

	block := ret.Block()
	paths, limitHit := a.inverseCDG.GetControllerPathsWithLimit(block, a.opts.MaxCDGPaths)
	_ = limitHit && a.infow("SCCP: CDG path limit hit in checkControlAttribution",
		"fn", a.fn.Name(), "retBlock", block.Index,
		"limit", a.opts.MaxCDGPaths, "paths", len(paths))

	a.infow("SCCP: checkControlAttribution",
		"fn", a.fn.Name(), "retBlock", block.Index, "numPaths", len(paths))

	for i, path := range paths {
		verdict := a.attributeControlPath(path, block)
		a.infow("SCCP: CDG path result",
			"fn", a.fn.Name(), "retBlock", block.Index,
			"pathIdx", i, "pathLen", len(path), "verdict", verdict)
		if verdict == srcAttribution {
			return true
		}
	}

	// Fallback: check if all feasible phi edges come from Src's error path
	if retVal, ok := a.getReturnValue(ret); ok {
		return a.checkPhiEdgeControlAttribution(retVal)
	}
	return false
}

// attributeControlPath walks a single inverse CDG path (innermost to outermost
// controller) looking for which source controls this return.
//
// Returns:
//   - srcAttribution:   Src's nil check guards this return on the error branch
//   - otherAttribution: another source's nil check guards this path — stop here
//   - noAttribution:    no source attribution found on this path
func (a *analyzer) attributeControlPath(path []cdg.ControllerEdge, returnBlock *ssa.BasicBlock) pathVerdict {
	for _, edge := range path {
		if !a.getBlockState(edge.Controller).executable {
			a.debugw("SCCP: CDG edge skipped (not executable)",
				"fn", a.fn.Name(), "controller", edge.Controller.Index)
			continue
		}
		ifInstr, ok := a.terminatingIf(edge.Controller)
		if !ok {
			a.debugw("SCCP: CDG edge skipped (no if)",
				"fn", a.fn.Name(), "controller", edge.Controller.Index)
			continue
		}

		condVS := a.getValueState(ifInstr.Cond)
		// Log the condition and all its nil checks in detail
		checkDetails := make([]string, 0, len(condVS.nilInfo.checks))
		for checkedVal, checkType := range condVS.nilInfo.checks {
			checkedVS := a.getValueState(checkedVal)
			isErr := isErrorBranch(edge.SuccIndex, checkType)
			hasSrc := checkedVS.dataSources.contains(a.sources.srcID())
			isSrc := checkedVal == ssa.Value(a.sources.srcID())
			checkDetails = append(checkDetails, fmt.Sprintf(
				"checked=%s checkType=%v isErrorBranch=%v isSrc=%v hasSrcInSources=%v srcCount=%d",
				describeValue(checkedVal), checkType, isErr, isSrc, hasSrc, checkedVS.dataSources.len()))
		}
		a.debugw("SCCP: CDG edge examining if",
			"fn", a.fn.Name(), "controller", edge.Controller.Index,
			"succIndex", edge.SuccIndex,
			"cond", describeValue(ifInstr.Cond),
			"numChecks", len(condVS.nilInfo.checks),
			"condSources", condVS.dataSources.len(),
			"checkDetails", checkDetails,
		)
		if len(condVS.nilInfo.checks) == 0 {
			continue
		}

		// Does any nil check test Src on the error branch?
		srcCheck := a.checksSourceOnErrorBranch(condVS, edge.SuccIndex, a.sources.srcID())
		a.debugw("SCCP: CDG checksSourceOnErrorBranch",
			"fn", a.fn.Name(), "controller", edge.Controller.Index,
			"result", srcCheck)
		if srcCheck {
			return srcAttribution
		}

		// Does any nil check test another source on the error branch?
		otherCheck := a.checksOtherSourceOnErrorBranch(condVS, edge.SuccIndex, returnBlock)
		a.debugw("SCCP: CDG checksOtherSourceOnErrorBranch",
			"fn", a.fn.Name(), "controller", edge.Controller.Index,
			"result", otherCheck)
		if otherCheck {
			return otherAttribution
		}

		// Stop walking past the block that defines Src
		if a.hasSourceGeneratingCall(edge.Controller, a.sources.srcID()) {
			break
		}
	}
	return noAttribution
}

// terminatingIf returns the If instruction at the end of a block, if any.
func (a *analyzer) terminatingIf(block *ssa.BasicBlock) (*ssa.If, bool) {
	if len(block.Instrs) == 0 {
		return nil, false
	}
	ifInstr, ok := block.Instrs[len(block.Instrs)-1].(*ssa.If)
	return ifInstr, ok
}

// checksSourceOnErrorBranch reports whether any nil check in condVS tests the
// given source (directly or by derivation) on the error branch.
func (a *analyzer) checksSourceOnErrorBranch(condVS *valState, succIndex int, src sourceID) bool {
	for checkedVal, checkType := range condVS.nilInfo.checks {
		if !isErrorBranch(succIndex, checkType) {
			continue
		}
		if checkedVal == ssa.Value(src) {
			return true
		}
		if a.getValueState(checkedVal).dataSources.contains(src) {
			return true
		}
	}
	return false
}

// checksOtherSourceOnErrorBranch reports whether any nil check in condVS tests
// a non-Src source on the error branch. Sources proven nil at the return block
// are excluded (already ruled out by assertion facts).
// Also returns true when the checked value is error-typed with no tracked data
// sources and is not Src itself — this covers interface method calls (invoke)
// whose return errors are not tracked as data sources but still represent a
// different error check that should stop the CDG walk.
func (a *analyzer) checksOtherSourceOnErrorBranch(condVS *valState, succIndex int, returnBlock *ssa.BasicBlock) bool {
	for checkedVal, checkType := range condVS.nilInfo.checks {
		if !isErrorBranch(succIndex, checkType) {
			continue
		}
		checkedVS := a.getValueState(checkedVal)
		if checkedVS.dataSources.isEmpty() {
			// No tracked data sources, but if this is an error-typed value
			// that is not Src, it's a different error check that should block
			// the CDG walk from attributing to Src.
			if checkedVal != ssa.Value(a.sources.srcID()) && a.isErrorType(checkedVal.Type()) {
				return true
			}
			continue
		}
		for src := range checkedVS.dataSources {
			if src == a.sources.srcID() {
				continue
			}
			if a.getNilnessInBlock(src, returnBlock) == nlNil {
				continue
			}
			return true
		}
	}
	return false
}

// getReturnValue extracts the return value from a return instruction.
func (a *analyzer) getReturnValue(ret *ssa.Return) (ssa.Value, bool) {
	results := ret.Results
	if results == nil || a.errorRetIndex >= len(results) {
		return nil, false
	}

	return results[a.errorRetIndex], true
}

// checkPhiEdgeControlAttribution checks if all feasible phi edges come from
// blocks where Src's error is known NonNil (i.e., the error branch).
func (a *analyzer) checkPhiEdgeControlAttribution(retVal ssa.Value) bool {
	phi, ok := retVal.(*ssa.Phi)
	if !ok {
		return false
	}

	// Collect all feasible edges and check their provenance
	for i := range phi.Edges {
		pred := phi.Block().Preds[i]
		if !a.isEdgeFeasible(pred, phi.Block()) {
			continue
		}

		// Check if this predecessor has a NonNil assertion fact for the source.
		if !a.isSrcNonNilInBlock(pred) {
			return false
		}
	}

	// All feasible edges come from source's error path
	return true
}

// isSrcNonNilInBlock checks if a block has a NonNil assertion fact
// for srcValue, meaning it is only reached when the source error is non-nil.
func (a *analyzer) isSrcNonNilInBlock(block *ssa.BasicBlock) bool {
	bs := a.getBlockState(block)
	if bs.nilFacts == nil {
		return false
	}
	nilness, ok := bs.nilFacts[a.sources.srcVal()]
	return ok && a.isNonNil(nilness)
}

// ensureInverseCDG lazily builds the inverse CDG.
func (a *analyzer) ensureInverseCDG() {
	if a.inverseCDG != nil {
		return
	}
	builder := cdg.NewCDGBuilder()
	a.inverseCDG = cdg.NewInverseCDG(builder.BuildCDG(a.fn))
}

// hasSourceGeneratingCall checks if a block contains the instruction that produces
// the given source's error value.
func (a *analyzer) hasSourceGeneratingCall(block *ssa.BasicBlock, src sourceID) bool {
	if instr, ok := src.(ssa.Instruction); ok {
		return instr.Block() == block
	}
	return false
}

// =============================================================================
// Helper Functions
// =============================================================================

// isNilConst checks if a value is the nil constant.
func (a *analyzer) isNilConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	return ok && c.IsNil()
}

// isBoolType checks if a type is the boolean type.
func (a *analyzer) isBoolType(t types.Type) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

// isNillableType checks if a type can be nil.
// Nillable types: pointers, slices, maps, channels, functions, interfaces.
func (a *analyzer) isNillableType(t types.Type) bool {
	if t == nil {
		return false
	}
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Slice, *types.Map, *types.Chan, *types.Signature, *types.Interface:
		return true
	default:
		return false
	}
}

// isNonNilCreator checks if a function always returns a non-nil error.
// Examples: errors.New, fmt.Errorf, yarpcerrors.*Errorf
func (a *analyzer) isNonNilCreator(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	name := fn.String()
	switch name {
	case "errors.New":
		return true
	}
	// yarpcerrors.*Errorf functions always return non-nil errors.
	if strings.HasPrefix(name, "go.uber.org/yarpc/yarpcerrors.") && strings.HasSuffix(name, "Errorf") {
		return true
	}
	return false
}

// isWrapLike checks if a function wraps or propagates errors from arguments.
// Examples: fmt.Errorf, errors.Wrap, errors.WithMessage
// Generic heuristic: any function whose last return is an error implementor
// and that takes one or more error implementor parameters.
func (a *analyzer) isWrapLike(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	switch fn.String() {
	case "fmt.Errorf",
		"github.com/pkg/errors.Wrap",
		"github.com/pkg/errors.Wrapf",
		"github.com/pkg/errors.WithMessage",
		"github.com/pkg/errors.WithMessagef",
		"github.com/pkg/errors.WithStack":
		return true
	}

	// Generic: function with error param whose last return is error.
	sig := fn.Signature
	if sig == nil {
		return false
	}
	results := sig.Results()
	if results.Len() == 0 {
		return false
	}
	if !a.isErrorType(results.At(results.Len() - 1).Type()) {
		return false
	}
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		if a.isErrorType(params.At(i).Type()) {
			return true
		}
	}

	return false
}

// isErrorType checks if a type implements the error interface.
func (a *analyzer) isErrorType(t types.Type) bool {
	if t == nil {
		return false
	}
	return types.Implements(t, a.errorIface)
}

// returnsError checks if a function has at least one error-typed return value.
func (a *analyzer) returnsError(fn *ssa.Function) bool {
	if fn == nil || fn.Signature == nil {
		return false
	}
	results := fn.Signature.Results()
	for i := 0; i < results.Len(); i++ {
		if a.isErrorType(results.At(i).Type()) {
			return true
		}
	}
	return false
}

// methodReturnsError checks if an interface method's signature returns an error.
func (a *analyzer) methodReturnsError(method *types.Func) bool {
	sig, ok := method.Type().(*types.Signature)
	if !ok {
		return false
	}
	results := sig.Results()
	for i := 0; i < results.Len(); i++ {
		if a.isErrorType(results.At(i).Type()) {
			return true
		}
	}
	return false
}

// methodIsWrapLike checks if an interface method's signature looks like an error
// wrapper: returns a single error and accepts an error-typed parameter.
func (a *analyzer) methodIsWrapLike(method *types.Func) bool {
	sig, ok := method.Type().(*types.Signature)
	if !ok {
		return false
	}
	results := sig.Results()
	if results.Len() != 1 {
		return false
	}
	if !a.isErrorType(results.At(0).Type()) {
		return false
	}
	params := sig.Params()
	for i := 0; i < params.Len(); i++ {
		if a.isErrorType(params.At(i).Type()) {
			return true
		}
	}
	return false
}

// =============================================================================
// Main Analysis Entry Point
// =============================================================================

// analyze runs the three-phase forward analysis.
// Returns true if at least one return satisfies non-suppression and attribution.
// When ForwardPathCheck is enabled, only considers returns reachable from Src.
func (a *analyzer) analyze() bool {
	a.runSCCP()

	// Log SSA dump at debug level for debugging.
	if a.log != nil {
		var buf bytes.Buffer
		a.fn.WriteTo(&buf)
		a.debugw("SCCP: SSA dump", "fn", a.fn.Name(), "ssa", buf.String())
	}

	var reachableFromSrc map[*ssa.BasicBlock]bool
	if a.opts.ForwardPathCheck {
		reachableFromSrc = a.getReachableBlocks(a.getSrcBlock())
	}

	for _, b := range a.fn.Blocks {
		bs := a.getBlockState(b)
		if !bs.executable {
			a.debugw("SCCP: block skipped (not executable)", "fn", a.fn.Name(), "block", b.Index)
			continue
		}
		if a.opts.ForwardPathCheck && !reachableFromSrc[b] {
			a.infow("SCCP: return block not reachable from src",
				"fn", a.fn.Name(), "block", b.Index, "step", "path_feasibility", "pass", false)
			continue
		}

		retIns, retVal, ok := a.getRetInsAndValueFromBlock(b)
		if !ok {
			continue
		}
		a.opts.Metrics.IncCFGPathsAnalyzed()

		retVS := a.getValueState(retVal)
		blockNilness := a.getNilnessInBlock(retVal, b)
		a.infow("SCCP: evaluating return block",
			"fn", a.fn.Name(),
			"block", b.Index,
			"retVal", describeValue(retVal),
			"retValNilness", retVS.getNilness(),
			"blockNilness", blockNilness,
			"numDataSources", retVS.dataSources.len(),
			"hasSrc", retVS.dataSources.contains(a.sources.srcID()),
		)

		// Phase 2: Non-suppression.
		a.opts.Metrics.IncNonSuppressionReached()
		nonSupp := a.checkNonSuppression(retIns, retVal)
		a.infow("SCCP: non-suppression check",
			"fn", a.fn.Name(), "block", b.Index, "step", "non_suppression", "pass", nonSupp)
		if !nonSupp {
			a.opts.Metrics.IncNonSuppressionFail()
			continue
		}
		a.opts.Metrics.IncNonSuppressionPass()

		// Phase 3: Attribution.
		a.opts.Metrics.IncAttributionReached()
		attr := a.checkAttribution(retIns, retVal)
		a.infow("SCCP: attribution check",
			"fn", a.fn.Name(), "block", b.Index, "step", "attribution", "pass", attr)
		if !attr {
			a.opts.Metrics.IncAttributionFail()
			continue
		}
		a.opts.Metrics.IncAttributionPass()

		// Both checks passed for this return.
		a.infow("SCCP: return block passed all checks",
			"fn", a.fn.Name(), "block", b.Index, "step", "forward_result", "pass", true)
		return true
	}

	return false
}

// checkInverseAnalysis runs SCCP with Src=Nil and checks whether at least one
// return reachable from Src via feasible edges has MaybeNil (not proven NonNil).
// If all reachable returns are NonNil even with Src=Nil, then Src does not
// truly control the error flow and the function fails regardless.
func (a *analyzer) checkInverseAnalysis() bool {
	a.runSCCP()

	// Find Src's block and verify it's executable
	srcBlock := a.getSrcBlock()
	if srcBlock == nil || !a.getBlockState(srcBlock).executable {
		a.infow("SCCP inverse: srcBlock nil or not executable",
			"fn", a.fn.Name(), "srcBlock", srcBlock)
		return false
	}

	reachableFromSrc := a.getReachableBlocks(srcBlock)

	a.infow("SCCP inverse: reachable blocks from src",
		"fn", a.fn.Name(),
		"srcBlock", srcBlock.Index,
		"numReachable", len(reachableFromSrc))

	returnBlockCount := 0
	for block := range reachableFromSrc {
		if _, retValue, ok := a.getRetInsAndValueFromBlock(block); ok {
			returnBlockCount++
			retVS := a.getValueState(retValue)
			nilness := retVS.getNilness()
			maybeNil := a.isMaybeNil(nilness)
			a.infow("SCCP inverse: checking return block",
				"fn", a.fn.Name(),
				"block", block.Index,
				"retValue", retValue.Name(),
				"nilness", nilness,
				"maybeNil", maybeNil)
			if maybeNil {
				return true
			}
		}
	}

	a.infow("SCCP inverse: no maybe-nil returns found",
		"fn", a.fn.Name(),
		"returnBlockCount", returnBlockCount,
		"numReachable", len(reachableFromSrc))

	// If no return blocks are reachable at all (e.g., Src=Nil causes an infinite
	// loop because the only loop exits are guarded by err!=nil), the function never
	// returns an error from this path when Src is nil → Src controls the error → pass.
	if returnBlockCount == 0 {
		return true
	}

	// All reachable returns are NonNil even with Src=Nil: Src doesn't control flow
	return false
}

// getRetInsAndValueFromBlock finds the Return instruction and its error value
// in a block, if present.
func (a *analyzer) getRetInsAndValueFromBlock(block *ssa.BasicBlock) (*ssa.Return, ssa.Value, bool) {
	for _, instr := range block.Instrs {
		ret, _ := instr.(*ssa.Return)
		if ret == nil {
			continue
		}
		if retVal, ok := a.getReturnValue(ret); ok {
			return ret, retVal, true
		}
	}
	return nil, nil, false
}

// getSrcBlock returns the basic block containing the Src instruction.
func (a *analyzer) getSrcBlock() *ssa.BasicBlock {
	return a.sources.srcBlock()
}

// =============================================================================
// Public API
// =============================================================================

// AnalyzeCallBySCCP performs fail-close analysis using SCCP with default options.
func AnalyzeCallBySCCP(f *ssa.Function, call ssa.CallInstruction) (constant.Failness, error) {
	return AnalyzeCallBySCCPWithOptions(f, call, DefaultSCCPOptions())
}

// AnalyzeCallBySCCPWithOptions performs fail-close analysis with the given options.
// Runs forward analysis (Src=NonNil) and inverse analysis (Src=Nil) when InverseCheck is set.
func AnalyzeCallBySCCPWithOptions(f *ssa.Function, call ssa.CallInstruction, opts SCCPOptions) (constant.Failness, error) {
	log := opts.Logger
	// Metrics invariant: TotalInvocations == FailClose + FailOpen + FailUnknown
	// (including invalid-input invocations that return FailUnknown with error)
	opts.Metrics.IncTotalInvocations()
	if err := validateInput(f, call); err != nil {
		opts.Metrics.IncFailUnknown()
		return constant.FailUnknown, err
	}

	errorRetIndex, err := getErrorReturnIndex(f)
	if err != nil {
		if err == errNoErrorReturn {
			if log != nil {
				log.Debugw("SCCP: caller has no error return → FailOpen", "fn", f.Name())
			}
			opts.Metrics.IncFailOpen()
			return constant.FailOpen, nil
		}
		opts.Metrics.IncFailUnknown()
		return constant.FailUnknown, err
	}

	srcValue, _, err := getErrorValue(call)
	if err != nil {
		if err == errErrorNotExtracted || err == errNotErrorType || err == errNoErrorReturn {
			if log != nil {
				log.Debugw("SCCP: callee error not extractable → FailOpen", "fn", f.Name(), "err", err)
			}
			opts.Metrics.IncFailOpen()
			return constant.FailOpen, nil
		}
		if err == errMultipleErrorReturns {
			// Proceed with the last error return value.
		} else {
			opts.Metrics.IncFailUnknown()
			return constant.FailUnknown, err
		}
	}

	if log != nil {
		log.Debugw("SCCP: starting analysis",
			"fn", f.Name(),
			"callee", call.Common().StaticCallee(),
			"srcValue", describeValue(srcValue),
			"errorRetIndex", errorRetIndex,
		)
	}

	src := sourceID(srcValue)

	// Forward analysis: Src is NonNil
	forwardAnalyzer := newAnalyzer(f, src, call, opts, false, errorRetIndex, nil)
	forwardPass := forwardAnalyzer.analyze()
	if log != nil {
		log.Infow("SCCP: forward analysis result",
			"fn", f.Name(), "step", "forward", "pass", forwardPass)
	}

	if !forwardPass {
		opts.Metrics.IncFailOpen()
		return constant.FailOpen, nil
	}

	// Phase 4: Inverse analysis (Src = Nil)
	if opts.InverseCheck {
		opts.Metrics.IncInverseReached()
		inverseAnalyzer := newAnalyzer(f, src, call, opts, true, errorRetIndex, forwardAnalyzer)
		inversePass := inverseAnalyzer.checkInverseAnalysis()
		if log != nil {
			log.Infow("SCCP: inverse analysis result",
				"fn", f.Name(), "step", "inverse", "pass", inversePass)
		}
		if inversePass {
			opts.Metrics.IncInversePass()
		} else {
			opts.Metrics.IncInverseFail()
		}
		if !inversePass {
			opts.Metrics.IncFailOpen()
			return constant.FailOpen, nil
		}
	}

	if log != nil {
		log.Infow("SCCP: final result",
			"fn", f.Name(), "step", "final", "result", "FailClose")
	}
	opts.Metrics.IncFailClose()
	return constant.FailClose, nil
}
