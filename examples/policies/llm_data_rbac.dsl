# Company LLM + production data RBAC (v1)
# Engine is deny-by-default: only explicit allows grant access; forbids always win.

# --- Profiles ---
policy "allow_self_profile"
when role in [HR_HEAD, ENGINEER, FINANCE_ANALYST, CFO, CEO, PAYROLL_ADMIN, EMPLOYEE]
allow READ EMPLOYEE_PROFILE
where subject == SELF

# --- Travel / executive expense (CEO demo) ---
policy "hr_team_expense_read"
when role == HR_HEAD
allow READ TRAVEL_EXPENSE
where subject == SELF
or subject in DIRECT_REPORTS

policy "executive_expense"
deny READ TRAVEL_EXPENSE
where subject in EXECUTIVE_GROUP
unless role in [CFO, CEO]

# --- Payroll export ---
policy "salary_export"
deny EXPORT SALARY
unless role == PAYROLL_ADMIN

# Allow payroll admin export
policy "payroll_export_allow"
when role == PAYROLL_ADMIN
allow EXPORT SALARY

# --- Tool invoke least privilege (DB tables) ---
policy "hr_tool_sql_allow"
when role == HR_HEAD
allow TOOL_INVOKE DB_TABLE

policy "finance_tool_sql_allow"
when role in [FINANCE_ANALYST, CFO, CEO]
allow TOOL_INVOKE DB_TABLE

# Explicit deny: engineers may not invoke DB tools
policy "engineer_no_db_tools"
deny TOOL_INVOKE DB_TABLE
when role == ENGINEER

# --- RAG / vector collections ---
policy "hr_vector_read"
when role in [HR_HEAD, EMPLOYEE, ENGINEER]
allow READ VECTOR_COLLECTION

policy "finance_vector_read"
when role in [FINANCE_ANALYST, CFO, CEO]
allow READ VECTOR_COLLECTION

# --- Unknown tools always denied (no permit) ---
# deny-by-default covers TOOL_UNKNOWN; explicit forbid for clarity:
policy "block_unknown_tool"
deny TOOL_INVOKE TOOL_UNKNOWN
