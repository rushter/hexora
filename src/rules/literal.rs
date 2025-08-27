use crate::audit::helpers::ListLike;
use crate::audit::helpers::raw_string_from_expr;
use crate::audit::parse::Checker;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::macros::encrypt;

use memchr::memmem;
use once_cell::sync::Lazy;
use regex::Regex;
use ruff_python_ast as ast;
use ruff_text_size::Ranged;
use serde::Serialize;

const MAX_PREVIEW_LENGTH: usize = 16;
const LITERALS_PREVIEW_MAX_COUNT: usize = 5;
const MIN_HEXED_STRING_LENGTH: usize = 100;
const MIN_BASE64_STRING_LENGTH: usize = 100;
const MIN_HEXED_LITERALS: u16 = 10;
const MIN_INT_LITERALS: u16 = 20;
const MIN_LITERAL_LENGTH: usize = 8;
const MAX_LITERAL_LENGTH: usize = 512;

static HEXED_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(\\x[0-9a-fA-F]{2})+$").expect("Invalid hex regex"));

static BASE64_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$")
        .expect("Invalid base64 regex")
});

#[derive(Debug, Serialize)]
pub struct SuspiciousLiteral {
    pattern: String,
    description: String,
    confidence: AuditConfidence,
    rule: Rule,
}

#[rustfmt::skip]
static SUSPICIOUS_LITERALS: Lazy<Vec<SuspiciousLiteral>> = Lazy::new(|| {
    let apps = [
        ("1Password", AuditConfidence::Medium),
        ("Armory", AuditConfidence::Low),
        ("binance", AuditConfidence::Low),
        ("Bitcoin", AuditConfidence::Low),
        ("Bitwarden", AuditConfidence::Low),
        ("Coinbase", AuditConfidence::Low),
        ("Discord", AuditConfidence::Low),
        ("Electrum", AuditConfidence::Low),
        ("exodus.wallet", AuditConfidence::Medium),
        ("Guarda", AuditConfidence::Low),
        ("Jaxx", AuditConfidence::Low),
        ("KeePass", AuditConfidence::Low),
        ("LastPass", AuditConfidence::Low),
        ("Ledger", AuditConfidence::Low),
        ("Metamask", AuditConfidence::Low),
        ("Telegram", AuditConfidence::Low),
        ("TREZOR", AuditConfidence::Low),
    ];
    let paths = [
        ("/etc/passwd", AuditConfidence::Low),
        ("/etc/shadow", AuditConfidence::Low),
        ("/etc/group", AuditConfidence::Low),
        ("/.ssh/id_rsa", AuditConfidence::Low),
        ("/.ssh/authorized_keys", AuditConfidence::Low),
        (".bitcoin/", AuditConfidence::Low),
        (".ethereum", AuditConfidence::Low),
        ("/proc/", AuditConfidence::Low),
        ("/.aws/", AuditConfidence::Low),
        (".netrc", AuditConfidence::Low),
    ];
    let browser_path = [
        ("Opera Software", AuditConfidence::High),
        ("Google/Chrome", AuditConfidence::High),
        ("Chromium/User Data/", AuditConfidence::High),
        ("BraveSoftware/Brave-Browser", AuditConfidence::High),
        ("Yandex/YandexBrowser", AuditConfidence::High),
        ("Vivaldi/User Data", AuditConfidence::High),
        ("Application Support/Vivaldi/", AuditConfidence::High),
        ("Microsoft/Edge", AuditConfidence::High),
        ("Mozilla/Firefox", AuditConfidence::High),
        ("Cookies/Cookies", AuditConfidence::High),
        ("Default/Extensions", AuditConfidence::High),
        ("Default/Network/Cookies", AuditConfidence::High),
        ("Default/Cookies", AuditConfidence::High),
        ("Default/History", AuditConfidence::High),
        ("Login Data/", AuditConfidence::High),
        ("Web Data/", AuditConfidence::High),
        ("Local State/", AuditConfidence::High),
        ("Bookmarks/", AuditConfidence::High),
        ("cookies.sqlite", AuditConfidence::High),
        ("Local Storage/leveldb", AuditConfidence::High),
        ("Discord/Local Storage/leveldb", AuditConfidence::High),
        ("Safari/LocalStorage/", AuditConfidence::High),
        ("Library/Safari", AuditConfidence::High),
        ("Application Support/Chromium/", AuditConfidence::High),
    ];

    let browser_extensions = [
        ("Authenticator", encrypt!("bhghoamapcdpbohphigoooaddinpkbai"), AuditConfidence::High),
        ("Binance", encrypt!("fhbohimaelbohpjbbldcngcnapndodjp"), AuditConfidence::High),
        ("Bitapp", encrypt!("fihkakfobkmkjojpchpfgcmhfjnmnfpi"), AuditConfidence::High),
        ("BoltX", encrypt!("aodkkagnadcbobfpggfnjeongemjbjca"), AuditConfidence::High),
        ("Coin98", encrypt!("aeachknmefphepccionboohckonoeemg"), AuditConfidence::High),
        ("Coinbase", encrypt!("hnfanknocfeofbddgcijnmhnfnkdnaad"), AuditConfidence::High),
        ("Core", encrypt!("agoakfejjabomempkjlepdflaleeobhb"), AuditConfidence::High),
        ("Crocobit", encrypt!("pnlfjmlcjdjgkddecgincndfgegkecke"), AuditConfidence::High),
        ("Equal", encrypt!("blnieiiffboillknjnepogjhkgnoapac"), AuditConfidence::High),
        ("Ever", encrypt!("cgeeodpfagjceefieflmdfphplkenlfk"), AuditConfidence::High),
        ("ExodusWeb3", encrypt!("aholpfdialjgjfhomihkjbmgjidlcdno"), AuditConfidence::High),
        ("Fewcha", encrypt!("ebfidpplhabeedpnhjnobghokpiioolj"), AuditConfidence::High),
        ("Finnie", encrypt!("cjmkndjhnagcfbpiemnkdpomccnjblmj"), AuditConfidence::High),
        ("Guarda", encrypt!("hpglfhgfnhbgpjdenjgmdgoeiappafln"), AuditConfidence::High),
        ("Guild", encrypt!("nanjmdknhkinifnkgdcggcfnhdaammmj"), AuditConfidence::High),
        ("HarmonyOutdated", encrypt!("fnnegphlobjdpkhecapkijjdkgcjhkib"), AuditConfidence::High),
        ("Iconex", encrypt!("flpiciilemghbmfalicajoolhkkenfel"), AuditConfidence::High),
        ("Jaxx Liberty", encrypt!("cjelfplplebdjjenllpjcblmjkfcffne"), AuditConfidence::High),
        ("Kaikas", encrypt!("jblndlipeogpafnldhgmapagcccfchpi"), AuditConfidence::High),
        ("KardiaChain", encrypt!("pdadjkfkgcafgbceimcpbkalnfnepbnk"), AuditConfidence::High),
        ("Keplr", encrypt!("dmkamcknogkgcdfhhbddcghachkejeap"), AuditConfidence::High),
        ("Liquality", encrypt!("kpfopkelmapcoipemfendmdcghnegimn"), AuditConfidence::High),
        ("MEWCX", encrypt!("nlbmnnijcnlegkjjpcfjclmcfggfefdm"), AuditConfidence::High),
        ("MaiarDEFI", encrypt!("dngmlblcodfobpdpecaadgfbcggfjfnm"), AuditConfidence::High),
        ("Martian", encrypt!("efbglgofoippbgcjepnhiblaibcnclgk"), AuditConfidence::High),
        ("Math", encrypt!("afbcbjpbpfadlkmhmclhkeeodmamcflc"), AuditConfidence::High),
        ("Metamask", encrypt!("nkbihfbeogaeaoehlefnkodbefgpgknn"), AuditConfidence::High),
        ("Metamask2", encrypt!("ejbalbakoplchlghecdalmeeeajnimhm"), AuditConfidence::High),
        ("Mobox", encrypt!("fcckkdbjnoikooededlapcalpionmalo"), AuditConfidence::High),
        ("Nami", encrypt!("lpfcbjknijpeeillifnkikgncikgfhdo"), AuditConfidence::High),
        ("Nifty", encrypt!("jbdaocneiiinmjbjlgalhcelgbejmnid"), AuditConfidence::High),
        ("Oxygen", encrypt!("fhilaheimglignddkjgofkcbgekhenbh"), AuditConfidence::High),
        ("PaliWallet", encrypt!("mgffkfbidihjpoaomajlbgchddlicgpn"), AuditConfidence::High),
        ("Petra", encrypt!("ejjladinnckdgjemekebdpeokbikhfci"), AuditConfidence::High),
        ("Phantom", encrypt!("bfnaelmomeimhlpmgjnjophhpkkoljpa"), AuditConfidence::High),
        ("Pontem", encrypt!("phkbamefinggmakgklpkljjmgibohnba"), AuditConfidence::High),
        ("Ronin", encrypt!("fnjhmkhhmkbjkkabndcnnogagogbneec"), AuditConfidence::High),
        ("Safepal", encrypt!("lgmpcpglpngdoalbgeoldeajfclnhafa"), AuditConfidence::High),
        ("Saturn", encrypt!("nkddgncdjgjfcddamfgcmfnlhccnimig"), AuditConfidence::High),
        ("Slope", encrypt!("pocmplpaccanhmnllbbkpgfliimjljgo"), AuditConfidence::High),
        ("Solfare", encrypt!("bhhhlbepdkbapadjdnnojkbgioiodbic"), AuditConfidence::High),
        ("Sollet", encrypt!("fhmfendgdocmcbmfikdcogofphimnkno"), AuditConfidence::High),
        ("Starcoin", encrypt!("mfhbebgoclkghebffdldpobeajmbecfk"), AuditConfidence::High),
        ("Swash", encrypt!("cmndjbecilbocjfkibfbifhngkdmjgog"), AuditConfidence::High),
        ("TempleTezos", encrypt!("ookjlbkiijinhpmnjffcofjonbfbgaoc"), AuditConfidence::High),
        ("TerraStation", encrypt!("aiifbnbfobpmeekipheeijimdpnlpgpp"), AuditConfidence::High),
        ("Tokenpocket", encrypt!("mfgccjchihfkkindfppnaooecgfneiii"), AuditConfidence::High),
        ("Ton", encrypt!("nphplpgoakhhjchkkhmiggakijnkhfnd"), AuditConfidence::High),
        ("Tron", encrypt!("ibnejdfjmmkpcnlpebklmnkoeoihofec"), AuditConfidence::High),
        ("Trust Wallet", encrypt!("egjidjbpglichdcondbcbdnbeeppgdph"), AuditConfidence::High),
        ("Wombat", encrypt!("amkmjjmmflddogmhpjloimipbofnfjih"), AuditConfidence::High),
        ("XDEFI", encrypt!("hmeobnfnfcmdkdcmlblgagmfpfboieaf"), AuditConfidence::High),
        ("XMR.PT", encrypt!("eigblbgjknlfbajkfhopmcojidlgcehm"), AuditConfidence::High),
        ("XinPay", encrypt!("bocpokimicclpaiekenaeelehdjllofo"), AuditConfidence::High),
        ("Yoroi", encrypt!("ffnbelfdoeiohenkjibnmadjiehjhajb"), AuditConfidence::High),
        ("iWallet", encrypt!("kncchdigobghenbbaddojjnnaogfppfj"), AuditConfidence::High),
    ];

    let suspicious_keywords = [
        ("shellcode", AuditConfidence::Medium),
        ("webshell", AuditConfidence::Medium),
    ];

    let mut m = vec![
        SuspiciousLiteral {
            pattern: "POST / HTTP/1".to_string(),
            description: "Suspicious raw POST request. Potential exploitation.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::SuspiciousLiteral,
        },
        SuspiciousLiteral {
            pattern: "GET / HTTP/1.".to_string(),
            description: "Suspicious raw GET request. Potential exploitation.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::SuspiciousLiteral,
        },
        SuspiciousLiteral {
            pattern: "uname -a".to_string(),
            description: "Suspicious command. Reconnaissance checks.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::SuspiciousLiteral,
        },
        SuspiciousLiteral {
            pattern: "/bin/sh".to_string(),
            description: "Suspicious command. Potential exploitation.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::SuspiciousLiteral,
        },
        SuspiciousLiteral {
            pattern: "CVE-".to_string(),
            description: "Literal mentions CVE. Potential exploitation.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::CVEInLiteral,
        },
        SuspiciousLiteral {
            pattern: "../../..".to_string(),
            description: "Path traversal".to_string(),
            confidence: AuditConfidence::Low,
            rule: Rule::PathTraversal,
        },
    ];
    for (path, confidence) in browser_path {
        m.push(SuspiciousLiteral {
            pattern: path.to_string(),
            description: format!("Potential enumeration of {} browser path.", path),
            confidence,
            rule: Rule::BrowserEnumeration,
        });
    }
    for (app, confidence) in apps {
        m.push(SuspiciousLiteral {
            pattern: app.to_string(),
            description: format!("Potential enumeration of {} app", app),
            confidence,
            rule: Rule::AppEnumeration,
        });
    }
    for (path, confidence) in paths {
        m.push(SuspiciousLiteral {
            pattern: path.to_string(),
            description: format!("Potential enumeration of {} on file system.", path),
            confidence,
            rule: Rule::PathEnumeration,
        });
    }
    for (keyword, confidence) in suspicious_keywords {
        m.push(SuspiciousLiteral {
            pattern: keyword.to_string(),
            description: format!("Suspicious keyword {} found.", keyword),
            confidence,
            rule: Rule::SuspiciousLiteral,
        });
    }
    for (name, pattern, confidence) in browser_extensions {
        m.push(SuspiciousLiteral {
            pattern: pattern.to_string(),
            description: format!("Enumeration of {} browser extension .", name),
            confidence,
            rule: Rule::BrowserExtension,
        });
    }
    m
});

fn is_hexed_string(literal: &str) -> bool {
    if !literal.starts_with('\\') {
        return false;
    }

    if literal.len() < MIN_HEXED_STRING_LENGTH {
        return false;
    };
    HEXED_REGEX.is_match(literal)
}

fn is_base64_string(literal: &str) -> bool {
    if literal.len() < MIN_BASE64_STRING_LENGTH {
        return false;
    };
    BASE64_REGEX.is_match(literal)
}

fn literal_preview(value: &str, max_length: usize) -> String {
    if value.len() > max_length {
        format!(
            "{}...{}",
            &value[..max_length / 2],
            &value[value.len() - max_length / 2..]
        )
    } else {
        value.to_string()
    }
}

pub fn check_literal(checker: &mut Checker, expr: &ast::Expr) {
    if let Some(literal) = raw_string_from_expr(expr, checker) {
        if is_hexed_string(&literal) {
            checker.audit_results.push(AuditItem {
                label: literal_preview(&literal, MAX_PREVIEW_LENGTH),
                rule: Rule::HexedString,
                description: "Hexed string found, potentially dangerous payload/shellcode."
                    .to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(expr.range()),
            });
            return;
        }
        if is_base64_string(&literal) {
            checker.audit_results.push(AuditItem {
                label: literal_preview(&literal, MAX_PREVIEW_LENGTH),
                rule: Rule::Base64String,
                description: "Base64 encoded string found, potentially obfuscated code."
                    .to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(expr.range()),
            });
            return;
        }
        check_suspicious_literal(checker, &literal, expr);
    }
}

pub fn check_int_literals<T>(checker: &mut Checker, list: &T)
where
    T: ListLike,
{
    let mut num_hex_literals: u16 = 0;
    let mut preview_literals: Vec<&str> = Vec::new();
    let mut num_int_literals: u16 = 0;
    let mut is_hex_literal: bool = false;

    for element in list.elements() {
        match element {
            ast::Expr::NumberLiteral(number) => {
                let raw_value = checker.locator.slice(number.range);
                if raw_value.starts_with("0x") {
                    if !is_hex_literal {
                        is_hex_literal = true;
                    }
                    num_hex_literals += 1;
                    if preview_literals.len() < LITERALS_PREVIEW_MAX_COUNT {
                        preview_literals.push(raw_value);
                    }
                } else {
                    if is_hex_literal {
                        break;
                    }
                    num_int_literals += 1;
                    if preview_literals.len() < LITERALS_PREVIEW_MAX_COUNT {
                        preview_literals.push(raw_value);
                    }
                }
            }
            _ => break,
        }
        if num_hex_literals > MIN_HEXED_LITERALS {
            checker.audit_results.push(AuditItem {
                label: format!("[{}, ... ]", preview_literals.join(", ")),
                rule: Rule::HexedLiterals,
                description:
                    "Sequence hex literals found, potentially dangerous payload/shellcode."
                        .to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(list.range()),
            });
            return;
        }
        if num_int_literals > MIN_INT_LITERALS {
            checker.audit_results.push(AuditItem {
                label: format!("[{}, ... ]", preview_literals.join(", ")),
                rule: Rule::IntLiterals,
                description: "Sequence of int literals found, potentially obfuscated code."
                    .to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(list.range()),
            });
            return;
        };
    }
}

fn normalize_literal(literal: &str) -> String {
    literal.replace("\\\\", "/").replace('\\', "/")
}

pub fn check_suspicious_literal(checker: &mut Checker, literal: &str, expr: &ast::Expr) {
    let normalized_literal = normalize_literal(literal);
    if normalized_literal.len() < MIN_LITERAL_LENGTH
        || normalized_literal.len() > MAX_LITERAL_LENGTH
    {
        return;
    }
    for suspicious_literal in SUSPICIOUS_LITERALS.iter() {
        let name = &suspicious_literal.pattern;
        if memmem::find(normalized_literal.as_bytes(), name.as_bytes()).is_some() {
            checker.audit_results.push(AuditItem {
                label: suspicious_literal.pattern.clone(),
                rule: suspicious_literal.rule.clone(),
                description: suspicious_literal.description.clone(),
                confidence: suspicious_literal.confidence,
                location: Some(expr.range()),
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::literal::normalize_literal;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("literal_01.py", Rule::HexedString, vec!["\\x31\\xc0...\\x80\\x00", "\\xeb\\x0d...\\xd4\\x99"])]
    #[test_case("literal_02.py", Rule::Base64String, vec!["dHJ5Ogog...NTMiKSk="])]
    #[test_case("literal_03.py", Rule::HexedLiterals, vec!["[0x00, 0x00, 0x00, 0x18, 0x66, ... ]", "[0x00, 0x1A, 0x63, 0x6C, 0x69, ... ]"])]
    #[test_case("literal_03.py", Rule::IntLiterals, vec!["[40, 65, 122, 63, 77, ... ]"])]
    #[test_case("literal_04.py", Rule::BrowserEnumeration, vec!["BraveSoftware/Brave-Browser", "Opera Software"])]
    #[test_case("literal_04.py", Rule::AppEnumeration, vec!["1Password", "KeePass"])]
    #[test_case("literal_04.py", Rule::PathEnumeration, vec!["/etc/passwd"])]
    #[test_case("literal_04.py", Rule::SuspiciousLiteral, vec!["uname -a"])]
    fn test_literal(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test]
    fn test_literal_normalization() {
        assert_eq!(
            normalize_literal("C:\\Users\\admin\\Desktop\\test.txt"),
            "C:/Users/admin/Desktop/test.txt"
        );
        assert_eq!(
            normalize_literal("C:\\\\Users\\\\admin\\\\Desktop\\\\test.txt"),
            "C:/Users/admin/Desktop/test.txt"
        );
    }
}
