/* Third Alloy Model */

// Use the temporal logic module for "always" and "eventually" properties
open util/ordering[State]
open util/boolean

// 1. SIGNATURES: Define the "Things" in our system
sig State {
    // Memory Status
    protectedSectionModified: one Bool,
    protectedSectionWritable: one Bool,
    // Detection Status
    detectionFlagRaised: one Bool,
    enforcementActionTaken: one Bool
}

// 2. INITIAL STATE: How the system starts (The "Clean" state)
pred init [s: State] {
    s.protectedSectionModified = False
    s.protectedSectionWritable = False
    s.detectionFlagRaised = False
    s.enforcementActionTaken = False
}

// 3. TRANSITIONS: Actions that change the state
// Attacker Action: Modifies the .text section
pred tamperMemory [s1, s2: State] {
    s2.protectedSectionModified = True
    s2.protectedSectionWritable = s1.protectedSectionWritable // Status carries over
    s2.detectionFlagRaised = s1.detectionFlagRaised
    s2.enforcementActionTaken = s1.enforcementActionTaken
}

// Anti-Cheat Action: Scans and detects modifications
pred runIntegrityCheck [s1, s2: State] {
    s1.protectedSectionModified = True => s2.detectionFlagRaised = True 
    else s2.detectionFlagRaised = s1.detectionFlagRaised
    
    s2.protectedSectionModified = s1.protectedSectionModified
    s2.enforcementActionTaken = (s2.detectionFlagRaised = True implies True else False)}

// 4. SYSTEM DYNAMICS: Defining how states can evolve
fact Transitions {
    all s1: State, s2: s1.next | 
        tamperMemory [s1, s2] or runIntegrityCheck [s1, s2]
}

// 5. SECURITY PROPERTY: If memory is tampered with, will it ALWAYS be detected?
assert IntegrityGuaranteed {
    all s1: State | s1.protectedSectionModified = True => 
        eventually (some s2: s1.nexts | s2.detectionFlagRaised = True)
}

// 6. RUN COMMAND: Tell Alloy to check for counterexamples within a scope
check IntegrityGuaranteed for 5 State