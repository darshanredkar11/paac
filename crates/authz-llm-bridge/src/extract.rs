use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::BridgeError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NlExtraction {
    pub utterance: String,
    pub action: String,
    pub resource_kind: String,
    pub resource_id: Option<String>,
    pub subject_id: Option<String>,
    pub subject_groups: Vec<String>,
    pub direct_reports: Vec<String>,
    pub confidence: f32,
}

pub struct StructuredExtractor;

pub fn extract_structured(utterance: &str) -> Result<NlExtraction, BridgeError> {
    let lower = utterance.to_ascii_lowercase();

    // CEO / executive expense or compensation
    if (lower.contains("ceo") || lower.contains("executive"))
        && (lower.contains("spend")
            || lower.contains("expense")
            || lower.contains("trip")
            || lower.contains("travel")
            || lower.contains("compensation")
            || lower.contains("salary"))
    {
        return Ok(NlExtraction {
            utterance: utterance.to_string(),
            action: "READ".into(),
            resource_kind: "TRAVEL_EXPENSE".into(),
            resource_id: Some("db.hr.travel_expenses".into()),
            subject_id: Some("employee:CEO".into()),
            subject_groups: vec!["EXECUTIVE".into()],
            direct_reports: vec!["employee:alice".into()],
            confidence: 0.95,
        });
    }

    // Tool / SQL
    if lower.contains("sql_query") || lower.contains("run sql") || lower.contains("query table") {
        let table_re = Regex::new(r"(db\.[a-z0-9_.]+)").unwrap();
        let resource_id = table_re
            .captures(&lower)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        return Ok(NlExtraction {
            utterance: utterance.to_string(),
            action: "TOOL_INVOKE".into(),
            resource_kind: "DB_TABLE".into(),
            resource_id,
            subject_id: None,
            subject_groups: vec![],
            direct_reports: vec![],
            confidence: 0.85,
        });
    }

    // Export payroll
    if lower.contains("export") && (lower.contains("payroll") || lower.contains("salary")) {
        return Ok(NlExtraction {
            utterance: utterance.to_string(),
            action: "EXPORT".into(),
            resource_kind: "SALARY".into(),
            resource_id: Some("api.export.payroll".into()),
            subject_id: None,
            subject_groups: vec![],
            direct_reports: vec![],
            confidence: 0.9,
        });
    }

    // RAG / retrieve
    if lower.contains("retrieve") || lower.contains("search documents") || lower.contains("vector") {
        let coll_re = Regex::new(r"(vec\.[a-z0-9_.]+)").unwrap();
        let resource_id = coll_re
            .captures(&lower)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        return Ok(NlExtraction {
            utterance: utterance.to_string(),
            action: "READ".into(),
            resource_kind: "VECTOR_COLLECTION".into(),
            resource_id,
            subject_id: None,
            subject_groups: vec![],
            direct_reports: vec![],
            confidence: 0.8,
        });
    }

    // Self profile
    if lower.contains("my profile") || lower.contains("my employee record") {
        return Ok(NlExtraction {
            utterance: utterance.to_string(),
            action: "READ".into(),
            resource_kind: "EMPLOYEE_PROFILE".into(),
            resource_id: Some("employee.self_profile".into()),
            subject_id: None, // caller should set SELF
            subject_groups: vec![],
            direct_reports: vec![],
            confidence: 0.75,
        });
    }

    // Alice travel (direct report pattern)
    if lower.contains("alice") && (lower.contains("expense") || lower.contains("travel")) {
        return Ok(NlExtraction {
            utterance: utterance.to_string(),
            action: "READ".into(),
            resource_kind: "TRAVEL_EXPENSE".into(),
            resource_id: Some("db.hr.travel_expenses".into()),
            subject_id: Some("employee:alice".into()),
            subject_groups: vec!["ENGINEERING".into()],
            direct_reports: vec!["employee:alice".into()],
            confidence: 0.9,
        });
    }

    Err(BridgeError::Msg(format!(
        "could not extract structured AuthzRequest from: {utterance}"
    )))
}
