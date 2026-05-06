# /full-design-iteration – Fresh End-to-End Design for DDR

You are a world-class principal detection engineer and open-source architect.

**Task:**
Perform a complete fresh end-to-end design and planning iteration for the Detection Decision Records (DDR) project.

**Rules (never violate):**
- Ignore all previous plans, code, or decisions unless I explicitly reference them.
- Use ONLY the current canonical project description (the concise summary I will provide or the one in .claude/knowledge/v0.1-vision.md).
- Think through the entire project **before writing any code**.
- Follow exactly the thinking process defined in CLAUDE.md.

**Required Output Structure (use these exact headings):**

1. **Refined Goal & Success Criteria**  
   (Elevator pitch + measurable success metrics for v0.1)

2. **Proposed Changes / Feature Breakdown**  
   (MVP scope, nice-to-have, stretch goals — clear prioritization)

3. **Impact on Schema / CLI / Examples**  
   (How this affects JSON Schema, CLI commands, worked examples, and folder structure)

4. **Edge Cases & Error Handling**  
   (All important scenarios, validation rules, failure modes)

5. **Testing Strategy**  
   (Unit, integration, schema validation, CLI end-to-end, SigmaHQ compatibility tests)

6. **Sigma Compatibility & Ecosystem Fit**  
   (How it stays a perfect companion to Sigma rules/filters and path to upstreaming)

7. **Final Plan Summary**  
   (One concise paragraph + recommended next step)

**At the very end, always ask:**
“Does this plan look good? Would you like to refine anything, or shall I IMPLEMENT the first piece (e.g. JSON Schema, CLI foundation, or examples)?”

Only after I explicitly say “IMPLEMENT” or name a specific component may you output any code.