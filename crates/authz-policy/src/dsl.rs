use crate::error::PolicyError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DslEffect {
    Allow,
    Deny,
    Review,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DslPolicy {
    pub id: String,
    pub effect: DslEffect,
    pub action: String,
    pub resource: String,
    /// Roles that must match (any). Empty = any role.
    pub when_roles: Vec<String>,
    /// Subject constraints: SELF, DIRECT_REPORTS, group names, or literal ids.
    pub where_subjects: Vec<String>,
    /// Unless roles that override a deny.
    pub unless_roles: Vec<String>,
    /// Subject must be in these groups (for deny executive patterns).
    pub where_subject_groups: Vec<String>,
    pub raw: String,
}

/// Parse the small PAAC human DSL into structured policies.
///
/// Example:
/// ```text
/// policy "hr_team_expense_read"
/// when role == HR_HEAD
/// allow READ TRAVEL_EXPENSE
/// where subject == SELF
/// or subject in DIRECT_REPORTS
///
/// policy "executive_expense"
/// deny READ TRAVEL_EXPENSE
/// where subject in EXECUTIVE_GROUP
/// unless role in [CFO, CEO]
/// ```
pub fn parse_dsl(input: &str) -> Result<Vec<DslPolicy>, PolicyError> {
    let mut policies = Vec::new();
    let mut current: Option<Partial> = None;

    for (lineno, raw_line) in input.lines().enumerate() {
        let line = strip_comment(raw_line).trim().to_string();
        if line.is_empty() {
            continue;
        }
        let loc = lineno + 1;

        if let Some(rest) = line.strip_prefix("policy ") {
            if let Some(p) = current.take() {
                policies.push(p.finish()?);
            }
            let id = parse_quoted_name(rest)
                .ok_or_else(|| PolicyError::Parse(format!("line {loc}: expected policy \"name\"")))?;
            current = Some(Partial::new(id, raw_line.to_string()));
            continue;
        }

        let partial = current
            .as_mut()
            .ok_or_else(|| PolicyError::Parse(format!("line {loc}: statement outside policy")))?;
        partial.raw.push('\n');
        partial.raw.push_str(raw_line);

        if let Some(rest) = line.strip_prefix("when ") {
            parse_when(rest, partial, loc)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("allow ") {
            partial.effect = Some(DslEffect::Allow);
            parse_action_resource(rest, partial, loc)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("deny ") {
            partial.effect = Some(DslEffect::Deny);
            parse_action_resource(rest, partial, loc)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("review ") {
            partial.effect = Some(DslEffect::Review);
            parse_action_resource(rest, partial, loc)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("where ") {
            parse_where(rest, partial, loc)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("or ") {
            parse_where(rest, partial, loc)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("unless ") {
            parse_unless(rest, partial, loc)?;
            continue;
        }
        return Err(PolicyError::Parse(format!("line {loc}: unknown statement: {line}")));
    }

    if let Some(p) = current.take() {
        policies.push(p.finish()?);
    }
    Ok(policies)
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#')
        .map(|(a, _)| a)
        .unwrap_or(line)
}

fn parse_quoted_name(s: &str) -> Option<String> {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        return Some(inner.to_string());
    }
    // bare identifier
    let ident = s.split_whitespace().next()?;
    Some(ident.to_string())
}

#[derive(Debug)]
struct Partial {
    id: String,
    effect: Option<DslEffect>,
    action: Option<String>,
    resource: Option<String>,
    when_roles: Vec<String>,
    where_subjects: Vec<String>,
    where_subject_groups: Vec<String>,
    unless_roles: Vec<String>,
    raw: String,
}

impl Partial {
    fn new(id: String, raw: String) -> Self {
        Self {
            id,
            effect: None,
            action: None,
            resource: None,
            when_roles: Vec::new(),
            where_subjects: Vec::new(),
            where_subject_groups: Vec::new(),
            unless_roles: Vec::new(),
            raw,
        }
    }

    fn finish(self) -> Result<DslPolicy, PolicyError> {
        let effect = self
            .effect
            .ok_or_else(|| PolicyError::Parse(format!("policy {}: missing allow/deny/review", self.id)))?;
        let action = self
            .action
            .ok_or_else(|| PolicyError::Parse(format!("policy {}: missing action", self.id)))?;
        let resource = self
            .resource
            .ok_or_else(|| PolicyError::Parse(format!("policy {}: missing resource", self.id)))?;
        Ok(DslPolicy {
            id: self.id,
            effect,
            action,
            resource,
            when_roles: self.when_roles,
            where_subjects: self.where_subjects,
            unless_roles: self.unless_roles,
            where_subject_groups: self.where_subject_groups,
            raw: self.raw,
        })
    }
}

fn parse_when(rest: &str, p: &mut Partial, loc: usize) -> Result<(), PolicyError> {
    // role == HR_HEAD  |  role in [A, B]
    let rest = rest.trim();
    if let Some(r) = rest.strip_prefix("role ==") {
        p.when_roles.push(r.trim().to_string());
        return Ok(());
    }
    if let Some(r) = rest.strip_prefix("role in ") {
        p.when_roles.extend(parse_list(r));
        return Ok(());
    }
    Err(PolicyError::Parse(format!("line {loc}: unsupported when: {rest}")))
}

fn parse_action_resource(rest: &str, p: &mut Partial, loc: usize) -> Result<(), PolicyError> {
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(PolicyError::Parse(format!(
            "line {loc}: expected ACTION RESOURCE"
        )));
    }
    p.action = Some(parts[0].to_ascii_uppercase());
    p.resource = Some(parts[1].to_ascii_uppercase());
    Ok(())
}

fn parse_where(rest: &str, p: &mut Partial, loc: usize) -> Result<(), PolicyError> {
    let rest = rest.trim();
    if rest == "subject == SELF" || rest == "subject==SELF" {
        p.where_subjects.push("SELF".into());
        return Ok(());
    }
    if let Some(r) = rest.strip_prefix("subject in ") {
        let name = r.trim();
        if name == "DIRECT_REPORTS" {
            p.where_subjects.push("DIRECT_REPORTS".into());
        } else if name.ends_with("_GROUP") || name == "EXECUTIVE_GROUP" || name.contains("GROUP") {
            // subject in EXECUTIVE_GROUP → group EXECUTIVE
            let g = name.trim_end_matches("_GROUP");
            p.where_subject_groups.push(g.to_string());
        } else {
            p.where_subject_groups.push(name.to_string());
        }
        return Ok(());
    }
    if let Some(r) = rest.strip_prefix("subject == ") {
        p.where_subjects.push(r.trim().to_string());
        return Ok(());
    }
    Err(PolicyError::Parse(format!("line {loc}: unsupported where: {rest}")))
}

fn parse_unless(rest: &str, p: &mut Partial, loc: usize) -> Result<(), PolicyError> {
    let rest = rest.trim();
    if let Some(r) = rest.strip_prefix("role ==") {
        p.unless_roles.push(r.trim().to_string());
        return Ok(());
    }
    if let Some(r) = rest.strip_prefix("role in ") {
        p.unless_roles.extend(parse_list(r));
        return Ok(());
    }
    Err(PolicyError::Parse(format!("line {loc}: unsupported unless: {rest}")))
}

fn parse_list(s: &str) -> Vec<String> {
    s.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hr_and_executive_policies() {
        let src = r#"
policy "hr_team_expense_read"
when role == HR_HEAD
allow READ TRAVEL_EXPENSE
where subject == SELF
or subject in DIRECT_REPORTS

policy "executive_expense"
deny READ TRAVEL_EXPENSE
where subject in EXECUTIVE_GROUP
unless role in [CFO, CEO]

policy "salary_export"
deny EXPORT SALARY
unless role == PAYROLL_ADMIN
"#;
        let policies = parse_dsl(src).unwrap();
        assert_eq!(policies.len(), 3);
        assert_eq!(policies[0].id, "hr_team_expense_read");
        assert_eq!(policies[0].effect, DslEffect::Allow);
        assert!(policies[0].where_subjects.contains(&"SELF".into()));
        assert_eq!(policies[1].effect, DslEffect::Deny);
        assert!(policies[1].where_subject_groups.iter().any(|g| g == "EXECUTIVE"));
        assert!(policies[1].unless_roles.contains(&"CFO".into()));
        assert_eq!(policies[2].action, "EXPORT");
    }
}
