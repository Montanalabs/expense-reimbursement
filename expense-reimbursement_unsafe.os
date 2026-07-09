#! VULNERABLE expense-reimbursement — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant reimburse irreversible

let raw = fetch<web>
commit { reimburse(raw) }  # tainted -> tool: REJECTED
