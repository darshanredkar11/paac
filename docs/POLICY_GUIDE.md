# PAAC Policy Authoring & Cedar DSL Guide

PAAC uses a human-readable DSL that compiles directly into AWS Cedar policies (`cedar-policy` v4). This document explains the policy syntax, precedence rules, and resource mapping patterns.

---

## PAAC Policy DSL Syntax

Policies are defined in `.dsl` files stored in `data/policies/`.

### Anatomy of a Policy

```text
policy "<policy_id>"
[when role == <ROLE_NAME> | when role in [<ROLE_1>, <ROLE_2>]]
<allow | deny> <ACTION> <RESOURCE_KIND>
[where subject == SELF]
[where subject in <GROUP_NAME>]
[where subject in DIRECT_REPORTS]
[unless role in [<ROLE_1>, <ROLE_2>]]
```

---

## Example Policies

### 1. Self Profile Access Rule
Allows any employee to view their own profile:
```text
policy "allow_self_profile"
when role in [HR_HEAD, ENGINEER, FINANCE_ANALYST, CFO, CEO, EMPLOYEE]
allow READ EMPLOYEE_PROFILE
where subject == SELF
```

### 2. Hierarchical Expense Rule (Direct Reports)
Allows HR Managers to read travel expenses for themselves or their direct reports:
```text
policy "hr_team_expense_read"
when role == HR_HEAD
allow READ TRAVEL_EXPENSE
where subject == SELF
or subject in DIRECT_REPORTS
```

### 3. Executive Data Protection (Forbid Rule)
Denies access to executive travel expenses unless the requester is the CFO or CEO:
```text
policy "executive_expense"
deny READ TRAVEL_EXPENSE
where subject in EXECUTIVE_GROUP
unless role in [CFO, CEO]
```

### 4. Database Tool Access Control
Restricts SQL query tools to HR and Finance teams, explicitly blocking Engineers:
```text
policy "hr_tool_sql_allow"
when role == HR_HEAD
allow TOOL_INVOKE DB_TABLE

policy "engineer_no_db_tools"
deny TOOL_INVOKE DB_TABLE
when role == ENGINEER
```

---

## Policy Evaluation Precedence

Cedar follows a strict evaluation logic:
1. **Deny-by-Default**: If no policy matches, the decision is **DENY**.
2. **Explicit Forbid Wins**: If an explicit `deny` policy matches, the decision is **DENY**, even if one or more `allow` policies also match.
3. **Explicit Permit**: A request is **ALLOW** if and only if at least one `allow` policy matches AND zero `deny` policies match.

---

## Policy Management Lifecycle

Use the `authz` CLI to manage policies through their lifecycle:

```bash
# 1. Validate DSL syntax
cargo run -p authz-cli -- policy validate

# 2. Commit DSL changes
cargo run -p authz-cli -- policy commit -m "Update DB table access rules"

# 3. Cryptographically sign bundle
cargo run -p authz-cli -- policy sign

# 4. Deploy active bundle to hot cache
cargo run -p authz-cli -- policy deploy
```
