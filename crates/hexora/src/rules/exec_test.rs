use crate::audit::result::{AuditConfidence, Rule};
use crate::rules::test::*;
use test_case::test_case;

#[test_case(
    "exec_01.py",
    Rule::ShellExec,
    vec![
        ("subprocess.call", AuditConfidence::Medium),
        ("os.popen", AuditConfidence::Medium),
        ("subprocess.check_output", AuditConfidence::Medium),
    ]
)]
#[test_case(
    "exec_02.py",
    Rule::CodeExec,
    vec![
        ("eval", AuditConfidence::Medium),
        ("builtins.exec", AuditConfidence::High),
        ("exec", AuditConfidence::Medium),
        ("eval", AuditConfidence::High),
        ("exec", AuditConfidence::High),
        ("eval", AuditConfidence::High),
        ("exec", AuditConfidence::High),
    ]
)]
#[test_case(
    "exec_03.py",
    Rule::ObfuscatedCodeExec,
    vec![
        ("builtins.exec", AuditConfidence::VeryHigh),
        ("builtins.exec", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_03.py",
    Rule::ObfuscatedShellExec,
    vec![
        ("os.system", AuditConfidence::VeryHigh),
        ("os.system", AuditConfidence::VeryHigh),
        ("subprocess.run", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_04.py",
    Rule::ObfuscatedShellExec,
    vec![
        ("os.system", AuditConfidence::VeryHigh),
        ("subprocess.Popen", AuditConfidence::VeryHigh),
        ("subprocess.check_output", AuditConfidence::VeryHigh),
        ("commands.getstatusoutput", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_05.py",
    Rule::ObfuscatedShellExec,
    vec![
        ("commands.getstatusoutput", AuditConfidence::VeryHigh),
        ("commands.getstatusoutput", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_06.py",
    Rule::DangerousExec,
    vec![
        ("subprocess.run", AuditConfidence::High),
        ("os.system", AuditConfidence::High),
    ]
)]
#[test_case(
    "exec_07.py",
    Rule::ObfuscatedCodeExec,
    vec![
        ("exec", AuditConfidence::VeryHigh),
        ("builtins.exec", AuditConfidence::VeryHigh),
        ("exec", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_08.py",
    Rule::ShellExec,
    vec![("subprocess.call", AuditConfidence::Medium)]
)]
#[test_case(
    "exec_09.py",
    Rule::ObfuscatedCodeExec,
    vec![("__builtins__.eval", AuditConfidence::VeryHigh)]
)]
#[test_case(
    "exec_10.py",
    Rule::ObfuscatedCodeExec,
    vec![("eval", AuditConfidence::VeryHigh)]
)]
#[test_case(
    "exec_11.py",
    Rule::ObfuscatedCodeExec,
    vec![
        ("exec", AuditConfidence::VeryHigh),
        ("exec", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_12.py",
    Rule::ObfuscatedCodeExec,
    vec![("exec", AuditConfidence::VeryHigh)]
)]
#[test_case(
    "exec_14.py",
    Rule::ShellExec,
    vec![("subprocess.Popen", AuditConfidence::Medium)]
)]
#[test_case(
    "exec_15.py",
    Rule::ObfuscatedShellExec,
    vec![("os.system", AuditConfidence::Medium)]
)]
#[test_case(
    "exec_15.py",
    Rule::ShellExec,
    vec![("os.system", AuditConfidence::Medium)]
)]
#[test_case(
    "exec_16.py",
    Rule::DangerousExec,
    vec![
        ("os.system", AuditConfidence::High),
        ("subprocess.run", AuditConfidence::High),
    ]
)]
#[test_case(
    "exec_17.py",
    Rule::ObfuscatedShellExec,
    vec![("os.system", AuditConfidence::VeryHigh)]
)]
#[test_case(
    "exec_19.py",
    Rule::ObfuscatedCodeExec,
    vec![("exec", AuditConfidence::VeryHigh)]
)]
#[test_case(
    "exec_20.py",
    Rule::ObfuscatedCodeExec,
    vec![("exec", AuditConfidence::VeryHigh)]
)]
#[test_case(
    "exec_21.py",
    Rule::ObfuscatedShellExec,
    vec![
        ("os.system", AuditConfidence::VeryHigh),
        ("os.system", AuditConfidence::VeryHigh),
        ("os.system", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_21.py",
    Rule::DangerousExec,
    vec![("os.posix_spawn", AuditConfidence::High)]
)]
#[test_case(
    "exec_21.py",
    Rule::ShellExec,
    vec![("os.system", AuditConfidence::VeryHigh)]
)]
#[test_case(
    "exec_22.py",
    Rule::DangerousExec,
    vec![
        ("os.system", AuditConfidence::High),
        ("os.system", AuditConfidence::High),
    ]
)]
#[test_case(
    "exec_23.py",
    Rule::ShellExec,
    vec![("subprocess.Popen", AuditConfidence::Medium)]
)]
#[test_case(
    "exec_24.py",
    Rule::CodeExec,
    vec![("subprocess.Popen", AuditConfidence::High)]
)]
#[test_case(
    "exec_24.py",
    Rule::ObfuscatedCodeExec,
    vec![
        ("exec", AuditConfidence::VeryHigh),
        ("subprocess.run", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_25.py",
    Rule::CodeExec,
    vec![("exec", AuditConfidence::Medium)]
)]
#[test_case(
    "exec_25.py",
    Rule::ObfuscatedCodeExec,
    vec![("exec", AuditConfidence::VeryHigh)]
)]
#[test_case(
    "exec_26.py",
    Rule::ShellExec,
    vec![("execfile", AuditConfidence::Medium)]
)]
#[test_case(
    "exec_27.py",
    Rule::ObfuscatedCodeExec,
    vec![
        ("exec", AuditConfidence::VeryHigh),
        ("subprocess.run", AuditConfidence::VeryHigh),
        ("exec", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_28.py",
    Rule::CodeExec,
    vec![
        ("exec", AuditConfidence::Medium),
        ("eval", AuditConfidence::Medium),
        ("exec", AuditConfidence::Medium),
        ("exec", AuditConfidence::Medium),
        ("exec", AuditConfidence::Medium),
        ("exec", AuditConfidence::Medium),
        ("exec", AuditConfidence::Medium),
        ("builtins.exec", AuditConfidence::High),
    ]
)]
#[test_case(
    "exec_28.py",
    Rule::ObfuscatedCodeExec,
    vec![
        ("exec", AuditConfidence::VeryHigh),
        ("builtins.exec", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(
    "exec_29.py",
    Rule::ShellExec,
    vec![
        ("subprocess.run", AuditConfidence::Medium),
        ("worker", AuditConfidence::High),
        ("run", AuditConfidence::High),
    ]
)]
fn test_exec(path: &str, rule: Rule, expected: Vec<(&str, AuditConfidence)>) {
    assert_audit_results(path, rule, expected);
}

#[test]
fn test_suspicious_exec_confidence() {
    let result = test_path("exec_18.py").unwrap();
    let suspicious_items: Vec<_> = result
        .items
        .iter()
        .filter(|item| {
            matches!(
                item.rule,
                Rule::ShellExec
                    | Rule::CodeExec
                    | Rule::ObfuscatedShellExec
                    | Rule::ObfuscatedCodeExec
            )
        })
        .map(|item| (item.label.clone(), item.rule, item.confidence))
        .collect();

    let expected = vec![
        (
            "os.system".to_string(),
            Rule::ObfuscatedShellExec,
            AuditConfidence::VeryHigh,
        ),
        (
            "exec".to_string(),
            Rule::ObfuscatedCodeExec,
            AuditConfidence::VeryHigh,
        ),
        ("exec".to_string(), Rule::CodeExec, AuditConfidence::Medium),
        ("eval".to_string(), Rule::CodeExec, AuditConfidence::Medium),
    ];

    assert_eq!(suspicious_items, expected);
}

#[test]
fn test_exec_13() {
    match test_path("exec_13.py") {
        Ok(result) => {
            let actual = result
                .items
                .iter()
                .map(|r| (r.label.clone(), r.rule))
                .collect::<Vec<(String, Rule)>>();
            let expected = vec![
                ("subprocess.run".to_string(), Rule::ShellExec),
                ("subprocess.run".to_string(), Rule::DangerousExec),
            ];
            assert_eq!(actual, expected);
        }
        Err(e) => {
            panic!("test failed: {:?}", e);
        }
    }
}

#[test_case(
    Rule::DangerousExec,
    vec![("os.system", AuditConfidence::High)]
)]
#[test_case(
    Rule::ShellExec,
    vec![
        ("os.system", AuditConfidence::VeryHigh),
        ("subprocess.call", AuditConfidence::VeryHigh),
    ]
)]
#[test_case(Rule::CodeExec, vec![("eval", AuditConfidence::Medium)])]
#[test_case(
    Rule::ObfuscatedShellExec,
    vec![
        ("os.system", AuditConfidence::VeryHigh),
        ("os.system", AuditConfidence::VeryHigh),
        ("os.system", AuditConfidence::VeryHigh),
    ]
)]
fn test_bypasses(rule: Rule, expected: Vec<(&str, AuditConfidence)>) {
    assert_audit_results("exec_bypass.py", rule, expected);
}

#[test]
fn test_dangerous_exec_ignores_plain_argument_mentions() {
    let source = r#"import subprocess
subprocess.run(["echo", "base64"])
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();
    let matches: Vec<_> = result
        .into_iter()
        .filter(|item| item.rule == Rule::DangerousExec)
        .map(|item| item.label)
        .collect();
    assert!(matches.is_empty());
}

#[test]
fn test_vars_dict_shell_exec() {
    let source = r#"import os
vars(os)["system"]("whoami")
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();
    let matches: Vec<_> = result
        .into_iter()
        .filter(|item| item.rule == Rule::ObfuscatedShellExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(matches.contains(&"os.system".to_string()));
}

#[test]
fn test_asyncio_create_subprocess_shell() {
    let source = r#"import asyncio
asyncio.create_subprocess_shell("whoami")
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();
    let matches: Vec<_> = result
        .into_iter()
        .filter(|item| item.rule == Rule::ShellExec || item.rule == Rule::DangerousExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(matches.contains(&"asyncio.create_subprocess_shell".to_string()));
}

#[test]
fn test_asyncio_create_subprocess_exec() {
    let source = r#"import asyncio
asyncio.create_subprocess_exec("ls", "-la")
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();
    let matches: Vec<_> = result
        .into_iter()
        .filter(|item| item.rule == Rule::ShellExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(matches.contains(&"asyncio.create_subprocess_exec".to_string()));
}

#[test]
fn test_asyncio_from_import_subprocess() {
    let source = r#"from asyncio import create_subprocess_shell as start_proc
start_proc("whoami")
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();
    let matches: Vec<_> = result
        .into_iter()
        .filter(|item| item.rule == Rule::ShellExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(matches.contains(&"asyncio.create_subprocess_shell".to_string()));
}

#[test]
fn test_subprocess_input_does_not_count_as_exec_obfuscation() {
    let source = r#"import os
import subprocess

def run_fix_iteration(scorecard):
    cmd = ["claude", "-p"]
    if os.environ.get("ANTHROPIC_API_KEY"):
        cmd.append("--bare")
    prompt = open("fixer.md").read().replace("{scorecard}", str(scorecard))
    subprocess.run(cmd, input=prompt, text=True, check=False)

run_fix_iteration({"status": "FAIL"})
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();

    let obfuscated_shell_exec: Vec<_> = result
        .iter()
        .filter(|item| item.rule == Rule::ObfuscatedShellExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(obfuscated_shell_exec.is_empty());

    let shell_exec: Vec<_> = result
        .iter()
        .filter(|item| item.rule == Rule::ShellExec)
        .map(|item| (item.label.clone(), item.confidence))
        .collect();
    assert_eq!(
        shell_exec,
        vec![("subprocess.run".to_string(), AuditConfidence::Medium)]
    );
}

#[test]
fn test_wrapper_prompt_argument_does_not_leak_as_shell_command() {
    let source = r#"import subprocess

def run_fix_iteration(scorecard):
    prompt = "fix " + str(scorecard)
    cmd = ["claude", "-p", prompt, "--dangerously-skip-permissions"]
    subprocess.run(cmd, text=True, check=False)

run_fix_iteration({"status": "FAIL"})
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();

    let obfuscated_shell_exec: Vec<_> = result
        .iter()
        .filter(|item| item.rule == Rule::ObfuscatedShellExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(obfuscated_shell_exec.is_empty());
}

#[test]
fn test_execvpe_with_fixed_argv_variable_is_not_obfuscated() {
    let source = r#"import os
import sys

def preview(name):
    env = {**os.environ, "APP_THEME": name}
    cmd = [sys.executable, "-m", "dazzle", "serve", "--local"]
    os.execvpe(cmd[0], cmd, env)
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();

    let obfuscated_shell_exec: Vec<_> = result
        .iter()
        .filter(|item| item.rule == Rule::ObfuscatedShellExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(obfuscated_shell_exec.is_empty());

    let shell_exec: Vec<_> = result
        .iter()
        .filter(|item| item.rule == Rule::ShellExec)
        .map(|item| (item.label.clone(), item.confidence))
        .collect();
    assert_eq!(
        shell_exec,
        vec![("os.execvpe".to_string(), AuditConfidence::Medium)]
    );
}

#[test]
fn test_popen_with_fixed_argv_variable_is_not_obfuscated() {
    let source = r#"import subprocess

def open_folder(project_wdir):
    cmd = ["open"]
    cmd.append(project_wdir)
    subprocess.Popen(cmd, cwd=project_wdir)
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();

    let obfuscated_shell_exec: Vec<_> = result
        .iter()
        .filter(|item| item.rule == Rule::ObfuscatedShellExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(obfuscated_shell_exec.is_empty());

    let shell_exec: Vec<_> = result
        .iter()
        .filter(|item| item.rule == Rule::ShellExec)
        .map(|item| (item.label.clone(), item.confidence))
        .collect();
    assert_eq!(
        shell_exec,
        vec![("subprocess.Popen".to_string(), AuditConfidence::Medium)]
    );
}

#[test]
fn test_wrapper_passthrough_run_stays_high_not_very_high() {
    let source = r#"import subprocess

original_run = __import__("subprocess").run

def mock_run(args, **kwargs):
    if args[0] == "git" and args[1] == "push":
        class Result:
            returncode = 1
            stderr = "No remote"
        return Result()
    return original_run(args, **kwargs)

mock_run(["git", "status"])
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();

    let leaked_exec: Vec<_> = result
        .iter()
        .filter(|item| {
            item.description
                .contains("via local function mock_run leaking to subprocess.run")
        })
        .map(|item| (item.rule.clone(), item.confidence))
        .collect();

    assert_eq!(leaked_exec, vec![(Rule::ShellExec, AuditConfidence::High)]);
}

#[test]
fn test_deobfuscated_shell_alias_with_plain_argv_stays_high() {
    let source = r#"import subprocess

original_run = __import__("subprocess").run
original_run(["git", "status"], check=False)
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();

    let direct_exec: Vec<_> = result
        .iter()
        .filter(|item| item.label == "subprocess.run")
        .map(|item| (item.rule.clone(), item.confidence))
        .collect();

    assert_eq!(
        direct_exec,
        vec![(Rule::ObfuscatedShellExec, AuditConfidence::High)]
    );
}

#[test]
fn test_inline_deobfuscated_subprocess_run_with_plain_argv_stays_high() {
    let source = r#"import sys

__import__("subprocess").run([sys.executable, "-m", "cli.main", "--help"], check=False)
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();

    let direct_exec: Vec<_> = result
        .iter()
        .filter(|item| item.label == "subprocess.run")
        .map(|item| (item.rule.clone(), item.confidence))
        .collect();

    assert_eq!(
        direct_exec,
        vec![(Rule::ObfuscatedShellExec, AuditConfidence::High)]
    );
}

#[test]
fn test_inline_deobfuscated_subprocess_popen_with_plain_argv_stays_high() {
    let source = r#"__import__("subprocess").Popen(["git", "status"])
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();

    let direct_exec: Vec<_> = result
        .iter()
        .filter(|item| item.label == "subprocess.Popen")
        .map(|item| (item.rule.clone(), item.confidence))
        .collect();

    assert_eq!(
        direct_exec,
        vec![(Rule::ObfuscatedShellExec, AuditConfidence::High)]
    );
}

#[test]
fn test_vars_dict_with_no_args() {
    let source = r#"import os
vars()["os"].system("whoami")
"#;
    let result = crate::audit::parse::audit_source(source, None).unwrap();
    let matches: Vec<_> = result
        .into_iter()
        .filter(|item| item.rule == Rule::ObfuscatedShellExec)
        .map(|item| item.label.clone())
        .collect();
    assert!(matches.contains(&"os.system".to_string()));
}
