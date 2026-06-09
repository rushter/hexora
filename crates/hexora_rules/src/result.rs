use ruff_text_size::TextRange;
use serde::{Serialize, Serializer};
use std::path::PathBuf;
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, EnumIter, Hash)]
pub enum AuditConfidence {
    #[serde(rename = "very_low")]
    VeryLow = 1,
    #[serde(rename = "low")]
    Low = 2,
    #[serde(rename = "medium")]
    Medium = 3,
    #[serde(rename = "high")]
    High = 4,
    #[serde(rename = "very_high")]
    VeryHigh = 5,
}

impl FromStr for AuditConfidence {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "very_low" | "verylow" => Ok(AuditConfidence::VeryLow),
            "low" => Ok(AuditConfidence::Low),
            "medium" | "med" | "mid" => Ok(AuditConfidence::Medium),
            "high" => Ok(AuditConfidence::High),
            "very_high" | "veryhigh" => Ok(AuditConfidence::VeryHigh),
            _ => Err(format!("invalid confidence level: {}", s)),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, EnumIter, Hash, Copy)]
pub enum Rule {
    // Enumeration
    AppEnumeration,
    BrowserEnumeration,
    PathEnumeration,
    OSFingerprint,

    // Access
    ClipboardRead,
    EnvAccess,
    ScreenshotCapture,

    // Execution
    CodeExec,
    ShellExec,
    DLLInjection,
    DangerousExec,
    SuspiciousCall,

    // Obfuscation/Execution
    ObfuscatedShellExec,
    ObfuscatedCodeExec,

    // Imports
    DunderImport,
    SuspiciousImport,
    CtypesImport,
    PickleImport,
    StructImport,
    SocketImport,
    MarshalImport,

    // Literals and data blobs
    Base64String,
    HexedLiterals,
    HexedString,
    IntLiterals,
    CVEInLiteral,
    SuspiciousLiteral,
    PathTraversal,
    BrowserExtension,
    WebHook,

    // Variables and Parameters
    SuspiciousFunctionName,
    SuspiciousParameterName,
    SuspiciousVariable,

    // Exfiltration
    DataExfiltration,

    // Other
    BinaryDownload,
    BuiltinsVariable,
    SuspiciousComment,
    SuspiciousWrite,
}
// Serialize the enum as its code string
impl Serialize for Rule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.code())
    }
}

impl Rule {
    pub fn iter() -> impl Iterator<Item = Rule> {
        <Self as IntoEnumIterator>::iter()
    }

    pub fn code(&self) -> &'static str {
        match self {
            // Enumeration: HX1000
            Rule::AppEnumeration => "HX1000",
            Rule::BrowserEnumeration => "HX1010",
            Rule::PathEnumeration => "HX1020",
            Rule::OSFingerprint => "HX1030",

            // Access: HX2000
            Rule::ClipboardRead => "HX2000",
            Rule::EnvAccess => "HX2010",
            Rule::ScreenshotCapture => "HX2020",

            // Execution: HX3000
            Rule::CodeExec => "HX3000",
            Rule::ShellExec => "HX3010",
            Rule::DLLInjection => "HX3040",
            Rule::DangerousExec => "HX3050",
            Rule::SuspiciousCall => "HX3060",

            // Obfuscation/Execution: HX4000
            Rule::ObfuscatedShellExec => "HX4000",
            Rule::ObfuscatedCodeExec => "HX4010",

            // Imports: HX5000
            Rule::DunderImport => "HX5000",
            Rule::SuspiciousImport => "HX5010",
            Rule::CtypesImport => "HX5020",
            Rule::PickleImport => "HX5030",
            Rule::StructImport => "HX5040",
            Rule::SocketImport => "HX5050",
            Rule::MarshalImport => "HX5060",

            // Literals and data blobs: HX6000
            Rule::Base64String => "HX6000",
            Rule::HexedLiterals => "HX6010",
            Rule::HexedString => "HX6020",
            Rule::IntLiterals => "HX6030",
            Rule::CVEInLiteral => "HX6040",
            Rule::SuspiciousLiteral => "HX6050",
            Rule::PathTraversal => "HX6060",
            Rule::BrowserExtension => "HX6070",
            Rule::WebHook => "HX6080",

            // Variables and Parameters: HX7000
            Rule::SuspiciousFunctionName => "HX7000",
            Rule::SuspiciousParameterName => "HX7010",
            Rule::SuspiciousVariable => "HX7020",

            // Other: HX8000
            Rule::BinaryDownload => "HX8000",
            Rule::BuiltinsVariable => "HX8010",
            Rule::SuspiciousComment => "HX8020",
            Rule::SuspiciousWrite => "HX8030",

            // Exfiltration: HX9000
            Rule::DataExfiltration => "HX9000",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Rule::AppEnumeration => "Suspicious application enumeration.",
            Rule::BrowserEnumeration => {
                "Suspicious browser enumeration (apps, cookies, history, etc.)."
            }
            Rule::PathEnumeration => "Suspicious path enumeration.",
            Rule::OSFingerprint => "Suspicious OS fingerprinting.",

            Rule::ClipboardRead => "Reading from the clipboard.",
            Rule::EnvAccess => "Access to a sensitive environment variable.",
            Rule::ScreenshotCapture => "Capturing screenshots from the display.",

            Rule::CodeExec => "Possible code execution.",
            Rule::ShellExec => "Execution of a shell command.",
            Rule::DLLInjection => "Possible DLL injection.",
            Rule::DangerousExec => {
                "Execution of potentially dangerous command inside a shell command."
            }
            Rule::SuspiciousCall => "Suspicious function call.",

            Rule::ObfuscatedShellExec => "Execution of possibly obfuscated shell command.",
            Rule::ObfuscatedCodeExec => "Execution of possibly obfuscated code.",

            Rule::DunderImport => "Suspicious use of `__import__`.",
            Rule::SuspiciousImport => "Suspicious import.",
            Rule::CtypesImport => "Suspicious ctypes import.",
            Rule::PickleImport => "Suspicious pickle import.",
            Rule::StructImport => "Suspicious struct import.",
            Rule::SocketImport => "Suspicious socket import.",
            Rule::MarshalImport => "Suspicious marshal import.",

            Rule::Base64String => "Long Base64-encoded string detected; possible code obfuscation.",
            Rule::HexedLiterals => "List of hex-encoded literals detected; possible payload.",
            Rule::HexedString => "Long hex-encoded string detected; possible payload.",
            Rule::IntLiterals => {
                "Large list of integer literals detected; possible code obfuscation."
            }
            Rule::CVEInLiteral => "Literal contains a CVE identifier.",
            Rule::SuspiciousLiteral => "Suspicious literal detected; possible data enumeration.",
            Rule::PathTraversal => "Suspicious path traversal.",
            Rule::BrowserExtension => "Enumeration of sensitive browser extensions.",
            Rule::WebHook => "Suspicious webhook detected. Possible data exfiltration.",

            Rule::SuspiciousFunctionName => "Suspicious function name.",
            Rule::SuspiciousParameterName => "Suspicious parameter name.",
            Rule::SuspiciousVariable => "Suspicious variable name.",

            Rule::DataExfiltration => "Potential data exfiltration.",

            Rule::BinaryDownload => "Suspicious binary download.",
            Rule::SuspiciousWrite => "Suspicious write to the filesystem.",
            Rule::BuiltinsVariable => "Suspicious builtin variable usage.",
            Rule::SuspiciousComment => "Suspicious comment.",
        }
    }
    pub fn help(&self) -> Option<&str> {
        match self {
            Rule::ClipboardRead => Some(
                "Clipboard access can be used to exfiltrate sensitive data such as passwords and keys.",
            ),
            Rule::EnvAccess => {
                Some("Access to sensitive environment variables can be used to exfiltrate data.")
            }
            Rule::ScreenshotCapture => Some(
                "Screenshot capture can be used to steal sensitive information shown on screen.",
            ),

            Rule::OSFingerprint => Some(
                "OS fingerprinting can be used to identify the target system and its vulnerabilities.",
            ),

            Rule::ObfuscatedShellExec => {
                Some("Obfuscated shell commands can be used to bypass detection.")
            }
            Rule::ObfuscatedCodeExec => {
                Some("Obfuscated code exec can be used to bypass detection.")
            }

            Rule::CtypesImport => {
                Some("`ctypes` module can be used to import DLLs and memory manipulation.")
            }
            Rule::StructImport => {
                Some("`struct` module can be used to craft malicious payloads or shellcode.")
            }
            Rule::PickleImport => Some(
                "`pickle` module can be used to execute arbitrary code when the data is deserialized.",
            ),
            Rule::SocketImport => {
                Some("`socket` module can be used to create malicious packets or exfiltrate data.")
            }
            Rule::MarshalImport => {
                Some("`marshal` module can be used to obfuscate data or execute arbitrary code.")
            }
            Rule::DunderImport => Some(
                "``__import__`` can be used to used to avoid detection of imports and code execution.",
            ),
            Rule::DangerousExec => {
                Some("Dangerous commands can be used to download and execute malicious scripts.")
            }
            Rule::SuspiciousCall => Some("Suspicious function call detected."),

            Rule::Base64String => {
                Some("Base64-encoded strings can be used to obfuscate code or data.")
            }
            Rule::HexedLiterals => {
                Some("Hex-encoded literals can be used to craft malicious payloads or shellcode.")
            }
            Rule::HexedString => {
                Some("Hex-encoded strings can be used to craft malicious payloads or shellcode.")
            }
            Rule::IntLiterals => Some(
                "Large lists of integer literals can be used to obfuscate code, craft malicious payloads or shellcode.",
            ),
            Rule::CVEInLiteral => {
                Some("CVE mentioned. This code may implement an exploit for this particular CVE.")
            }
            Rule::BrowserExtension => Some(
                "Enumeration of sensitive browser extensions. Usually used to steal credentials.",
            ),
            Rule::WebHook => Some("Webhooks are often used to exfiltrate (upload) collected data."),
            Rule::DataExfiltration => {
                Some("Data exfiltration is the unauthorized transfer of data from a computer.")
            }
            Rule::SuspiciousWrite => Some(
                "Writing to files with to suspicious extensions (.exe, .py) can be used to store malicious payloads.",
            ),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditItem {
    pub label: String,
    pub rule: Rule,
    pub description: String,
    pub confidence: AuditConfidence,
    #[serde(serialize_with = "serialize_text_range")]
    pub location: Option<TextRange>,
}

fn serialize_text_range<S>(range: &Option<TextRange>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match range {
        Some(range) => {
            let start: u32 = range.start().into();
            let end: u32 = range.end().into();
            serializer.serialize_some(&(start, end))
        }
        None => serializer.serialize_none(),
    }
}

pub struct AuditResult {
    pub items: Vec<AuditItem>,
    pub path: PathBuf,
    pub archive_path: Option<PathBuf>,
    pub source_code: String,
}
