use crate::checker::Checker;
use crate::result::{AuditConfidence, AuditItem, Rule};
use hexora_semantic::resolver::string_from_expr;

use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use std::collections::HashSet;

static ENV_VARS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    HashSet::from([
        "ACCESS_TOKEN",
        "ALCHEMY_API_KEY",
        "ANTHROPIC_API_KEY",
        "API_KEY",
        "AUTH_TOKEN",
        "AWS_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SECRET_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_PASSWORD",
        "AZURE_STORAGE_CONNECTION_STRING",
        "AZURE_STORAGE_KEY",
        "AZURE_USERNAME",
        "binance_api",
        "binance_secret",
        "BITCOIN_PRIVATE_KEY",
        "BITTREX_API_KEY",
        "BITTREX_SECRET_KEY",
        "BOT_TOKEN",
        "BSC_PRIVATE_KEY",
        "CI_DEPLOY_PASSWORD",
        "CI_JOB_TOKEN",
        "CIRCLE_TOKEN",
        "CLOUDFLARE_API_TOKEN",
        "CODECOV_TOKEN",
        "CONSUMER_SECRET",
        "DATABASE_URL",
        "DB_PASSWORD",
        "DIGITALOCEAN_ACCESS_TOKEN",
        "DOCKER_PASSWORD",
        "DOCKER_USERNAME",
        "ETHEREUM_PRIVATE_KEY",
        "FACEBOOK_APP_SECRET",
        "GCP_PROJECT",
        "GEMINI_API_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITLAB_TOKEN",
        "GOOGLE_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_SECRET",
        "HELIUS_API_KEY",
        "HEROKU_API_KEY",
        "HEROKU_API_USER",
        "HUGGINGFACE_TOKEN",
        "INFURA_API_KEY",
        "JENKINS_TOKEN",
        "JWT_SECRET",
        "KUBERNETES_SERVICE_ACCOUNT_TOKEN",
        "MAILGUN_API_KEY",
        "MNEMONIC",
        "NETLIFY_AUTH_TOKEN",
        "NGROK_TOKEN",
        "NODE_AUTH_TOKEN",
        "NPM_AUTH_TOKEN",
        "NPM_TOKEN",
        "OKTA_CLIENT_TOKEN",
        "OPENAI_API_KEY",
        "POSTGRES_PASSWORD",
        "PRIVATE_KEY",
        "PYPI_PASSWORD",
        "PYPI_TOKEN",
        "QUICKNODE_API_KEY",
        "SECRET_KEY",
        "SEED_PHRASE",
        "SENTRY_AUTH_TOKEN",
        "SESSION_TOKEN",
        "SLACK_BOT_TOKEN",
        "SLACK_TOKEN",
        "SOLANA_PRIVATE_KEY",
        "SSH_KEY",
        "SSH_PRIVATE_KEY",
        "STRIPE_SECRET_KEY",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_TOKEN",
        "TRON_PRIVATE_KEY",
        "TWINE_PASSWORD",
        "TWINE_USERNAME",
        "VAULT_TOKEN",
        "VERCEL_TOKEN",
        "WALLET_PRIVATE_KEY",
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
    if let Some(first) = call.arguments.args.first() {
        candidate = string_from_expr(first, &checker.indexer);
    }

    if candidate.is_none() {
        for kw in &*call.arguments.keywords {
            if let ast::Keyword {
                arg: Some(name),
                value,
                ..
            } = kw
                && name.id == "key"
            {
                candidate = string_from_expr(value, &checker.indexer);
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
    use crate::result::Rule;
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
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::EnvAccess)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["AWS_ACCESS_KEY_ID"]);
    }

    #[test]
    fn test_env_new_sensitive_keys() {
        let source = r#"import os
os.getenv("PYPI_TOKEN")
os.getenv("MNEMONIC")
os.getenv("SEED_PHRASE")
os.getenv("ETHEREUM_PRIVATE_KEY")
os.getenv("NODE_AUTH_TOKEN")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::EnvAccess)
            .map(|item| item.label)
            .collect();
        assert_eq!(
            matches,
            vec![
                "PYPI_TOKEN",
                "MNEMONIC",
                "SEED_PHRASE",
                "ETHEREUM_PRIVATE_KEY",
                "NODE_AUTH_TOKEN"
            ]
        );
    }

    #[test]
    fn test_env_subscript_expression() {
        let source = r#"import os
os.environ["AWS_ACCESS_KEY_ID"]
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::EnvAccess)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["AWS_ACCESS_KEY_ID"]);
    }

    #[test]
    fn test_env_variable_key() {
        let source = r#"import os
k = "AWS_ACCESS_KEY_ID"
os.getenv(k)
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::EnvAccess)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["AWS_ACCESS_KEY_ID"]);
    }

    #[test]
    fn test_env_keyword_key() {
        let source = r#"import os
os.getenv(key="FACEBOOK_APP_SECRET")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::EnvAccess)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["FACEBOOK_APP_SECRET"]);
    }

    #[test]
    fn test_env_unresolved_key_not_flagged() {
        let source = r#"import os
os.getenv(some_dynamic_key)
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::EnvAccess)
            .collect();
        assert!(matches.is_empty());
    }
}
