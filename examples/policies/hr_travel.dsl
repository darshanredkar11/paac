# HR may read travel expenses for self or direct reports
policy "hr_team_expense_read"
when role == HR_HEAD
allow READ TRAVEL_EXPENSE
where subject == SELF
or subject in DIRECT_REPORTS

# Nobody except CFO/CEO may read executive travel expenses
policy "executive_expense"
deny READ TRAVEL_EXPENSE
where subject in EXECUTIVE_GROUP
unless role in [CFO, CEO]

# Salary export locked to payroll admins
policy "salary_export"
deny EXPORT SALARY
unless role == PAYROLL_ADMIN
