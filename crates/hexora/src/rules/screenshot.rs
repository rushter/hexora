use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;

use ruff_python_ast as ast;

pub fn screenshot_capture(checker: &mut Checker, call: &ast::ExprCall) {
    let screenshot_name = checker
        .indexer
        .resolve_qualified_name(&call.func)
        .filter(|qualified_name| qualified_name.is_screenshot_capture());

    if let Some(screenshot_name) = screenshot_name {
        checker.audit_results.push(AuditItem {
            label: screenshot_name.as_str(),
            rule: Rule::ScreenshotCapture,
            description:
                "Capturing screenshots can be used to steal sensitive information shown on screen."
                    .to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(call.range),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("screenshot_01.py", Rule::ScreenshotCapture, vec![
        "PIL.ImageGrab.grab",
        "PIL.ImageGrab.grab",
        "pyscreenshot.grab",
        "pyautogui.screenshot",
        "mss.mss.grab",
        "d3dshot.create.screenshot",
    ])]
    fn test_screenshot(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
