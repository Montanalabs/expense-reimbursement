#! Expense reimbursement — untrusted a receipt OCR can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires reimburse — the expense reimbursement sink
#! @effect io
#! @irreversible
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant reimburse irreversible

type Category = Travel | Meals | Lodging
type Decision = Reimburse(Category) | Deny

let raw = fetch<web>  # UNTRUSTED a receipt OCR — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
commit { reimburse(d) }  # act on the trusted decision only
