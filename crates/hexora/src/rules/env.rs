use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::resolver::string_from_expr;

use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use std::collections::HashSet;

static ENV_VARS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_PASSWORD",
        "AZURE_STORAGE_CONNECTION_STRING",
        "AZURE_STORAGE_KEY",
        "AZURE_USERNAME",
        "binance_api",
        "binance_secret",
        "BITTREX_API_KEY",
        "BITTREX_SECRET_KEY",
        "CI_DEPLOY_PASSWORD",
        "CONSUMER_SECRET",
        "DIGITALOCEAN_ACCESS_TOKEN",
        "DOCKER_PASSWORD",
        "DOCKER_USERNAME",
        "FACEBOOK_APP_SECRET",
        "GCP_PROJECT",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITLAB_TOKEN",
        "GOOGLE_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "HEROKU_API_KEY",
        "HEROKU_API_USER",
        "MAILGUN_API_KEY",
        "NGROK_TOKEN",
        "NPM_AUTH_TOKEN",
        "NPM_TOKEN",
        "OKTA_CLIENT_TOKEN",
        "OPENAI_API_KEY",
        "POSTGRES_PASSWORD",
        "SENTRY_AUTH_TOKEN",
        "SLACK_TOKEN",
        "TELEGRAM_BOT_TOKEN",
        "VAULT_TOKEN",
    ])
});

pub fn env_access(checker: &mut Checker, call: &ast::ExprCall) {
    let is_env_access = checker
        .indexer
        .resolve_qualified_name(&call.func)
        .is_some_and(|qualified_name| qualified_name.is_env_access());
    if !is_env_access {
        return;
    }

    let mut candidate: Option<String> = None;
    if let Some(first) = call.arguments.args.first()
        && let ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. }) = first
    {
        candidate = Some(value.to_string());
    }

    if candidate.is_none() {
        for kw in &*call.arguments.keywords {
            if let ast::Keyword {
                arg: Some(name),
                value,
                ..
            } = kw
                && name.id == "key"
                && let ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. }) = value
            {
                candidate = Some(value.to_string());
                break;
            }
        }
    }

    if let Some(var_name) = candidate
        && ENV_VARS.contains(var_name.as_str())
    {
        checker.audit_results.push(AuditItem {
            label: var_name,
            rule: Rule::EnvAccess,
            description: "Access to sensitive environment variable".to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(call.range),
        });
    }
}

pub fn env_access_subscript(checker: &mut Checker, subscript: &ast::ExprSubscript) {
    let is_env_access = checker
        .indexer
        .resolve_qualified_name(&subscript.value)
        .is_some_and(|qualified_name| qualified_name.is_exact(&["os", "environ"]));
    if !is_env_access {
        return;
    }

    let Some(var_name) = string_from_expr(&subscript.slice, &checker.indexer) else {
        return;
    };

    if ENV_VARS.contains(var_name.as_str()) {
        checker.audit_results.push(AuditItem {
            label: var_name,
            rule: Rule::EnvAccess,
            description: "Access to sensitive environment variable".to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(subscript.range),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("env_01.py", Rule::EnvAccess, vec!["AWS_ACCESS_KEY_ID", "FACEBOOK_APP_SECRET"])]
    fn test_env(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test]
    fn test_env_string_expression() {
        let source = r#"import os
os.getenv("AWS_" + "ACCESS_KEY_ID")
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::EnvAccess)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["AWS_ACCESS_KEY_ID"]);
    }

    #[test]
    fn test_env_subscript_expression() {
        let source = r#"import os
os.environ["AWS_ACCESS_KEY_ID"]
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::EnvAccess)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["AWS_ACCESS_KEY_ID"]);
    }
}
