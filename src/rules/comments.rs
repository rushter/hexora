use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use memchr::memmem;
use once_cell::sync::Lazy;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SuspiciousComment {
    pub name: &'static str,
    pub description: &'static str,
    pub rule: Rule,
    confidence: AuditConfidence,
}
#[rustfmt::skip]
static COMMENTS: Lazy<Vec<SuspiciousComment>> = Lazy::new(|| {
    let rules = vec![
    SuspiciousComment{
        name:"BlankOBF",
        description:"BlankOBF is a code obfuscation tool that can be used to hide malicious code.",
        rule:Rule::SuspiciousComment,
        confidence:AuditConfidence::Medium
    }];
    rules
});

pub fn check_comments(checker: &mut Checker) {
    for comment in checker.indexer.comments.iter() {
        let comment_str = checker.locator.slice(comment);
        for comment_rule in COMMENTS.iter() {
            if memmem::find(comment_str.as_bytes(), comment_rule.name.as_bytes()).is_some() {
                checker.audit_results.push(AuditItem {
                    label: comment_rule.name.to_string(),
                    rule: comment_rule.rule.clone(),
                    description: comment_rule.description.to_string(),
                    confidence: comment_rule.confidence,
                    location: Some(*comment),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("comments_01.py", Rule::SuspiciousComment, vec!["BlankOBF", "BlankOBF"])]
    fn test_comment(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
