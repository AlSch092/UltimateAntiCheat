/* Third Alloy Model */

// open properties for temporal logic inside the model
open util/ordering[State]
open util/boolean

// 1. SIGNATURES: Define the "Things" in our system
sig State {
    // ----- Memory Status -----
    // checks if protected section has been modified
    protectedSectionModified: one Bool,
    // checks if protected section is writable
    protectedSectionWritable: one Bool,
    // ----- Detection Status -----
    detectionFlagRaised: one Bool,
    enforcementActionTaken: one Bool
}

// 2. INITIAL STATE
// puts all variables in a known starting configuration.
// They will be set to false, ensuring no tampering has happened yet.
// in the transition predicates, we will change some to true and see how the system responds.
pred init [s1: State] {
    // starting state all to False.
    s1.protectedSectionModified = False
    s1.protectedSectionWritable = False
    s1.detectionFlagRaised = False
    s1.enforcementActionTaken = False
}

// 3. TRANSITIONS: Actions that change the state
// Attacker Action: Modifies the .text section
pred tamperMemory [s1, s2: State] {
    // sets the protected section as modified (true)
    s2.protectedSectionModified = True
    // For simplicity, we assume the attacker can only modify the protected section if it's writable
    s2.protectedSectionWritable = s1.protectedSectionWritable // Status carries over
    // detection flag is raised if the protected section is modified
    s2.detectionFlagRaised = s1.detectionFlagRaised
    // enforcement action is taken if the detection flag is raised
    s2.enforcementActionTaken = s1.enforcementActionTaken

    // it is basically a tree, if one thing happens,
    // the next state will reflect that change, and we can check if the system responds correctly.
}

// Anti-Cheat Action: Scans and detects modifications
// This is where the magic happens, 
// we check if the system correctly raises the detection flag and takes enforcement action when tampering is detected.
pred runIntegrityCheck [s1, s2: State] {
    // *** s1 is the current state, s2 is the next state after running the integrity check.

    // if the protected section is modified, the detection flag should be raised
    s1.protectedSectionModified = True => s2.detectionFlagRaised = True 
    // if not, the detection flag should remain unchanged
    else s2.detectionFlagRaised = s1.detectionFlagRaised
    
    // s2 == s1 for modified status
    s2.protectedSectionModified = s1.protectedSectionModified
    // s2 enforcement action is taken if the detection flag is raised, otherwise it remains unchanged
    s2.enforcementActionTaken = (s2.detectionFlagRaised = True implies True else False)}

// Sanity Check: Stutter predicate
// Allows a state to transition to itself without any changes.
// This is critical for temporal logic verification - without it, the model can produce false counterexamples.
// The stutter ensures that not every state transition must involve an action; the system can "wait" without changing.
pred stutter [s1, s2: State] {
    // All properties remain unchanged
    s2.protectedSectionModified = s1.protectedSectionModified
    s2.protectedSectionWritable = s1.protectedSectionWritable
    s2.detectionFlagRaised = s1.detectionFlagRaised
    s2.enforcementActionTaken = s1.enforcementActionTaken
}

// 4. SYSTEM DYNAMICS: Defining how states can evolve
// fact ensures that the system can only transition according to the defined actions (tampering, integrity check, or stutter)
fact Transitions {
    // For every state s1 and its next state s2, either tampering occurs, an integrity check is run, or the system stutters (no change).
    all s1: State, s2: s1.next | 
        tamperMemory [s1, s2] or runIntegrityCheck [s1, s2] or stutter [s1, s2]
}

// 5. SECURITY PROPERTY: If memory is tampered with, will it ALWAYS be detected? IMPORTANTTTTTT!
assert IntegrityGuaranteed {
    // if the protected section is modified,
    // then eventually the detection flag should be raised in some future state.
    // this is the core of temporal logic, we want to ensure that if tampering happens, the system will eventually detect it.
    all s1: State | s1.protectedSectionModified = True => 
        eventually (some s2: s1.nexts | s2.detectionFlagRaised = True)
}

// 6. RUN COMMAND: Tell Alloy to check for counterexamples within a scope
check IntegrityGuaranteed for 5 State