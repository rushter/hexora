use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedName {
    segments: Arc<[String]>,
}

impl QualifiedName {
    pub fn new<S: Into<String>>(qualified_name: S) -> Self {
        let s = qualified_name.into();
        let segments: Vec<String> = if s.is_empty() {
            Vec::new()
        } else {
            s.split('.').map(|s| s.to_string()).collect()
        };
        Self {
            segments: Arc::from(segments),
        }
    }

    pub fn from_segments(segments: Vec<String>) -> Self {
        Self {
            segments: Arc::from(segments),
        }
    }

    #[inline]
    pub fn segments_slice(&self) -> &[String] {
        &self.segments
    }

    #[inline]
    pub fn segments(&self) -> Vec<&str> {
        self.segments.iter().map(|s| s.as_str()).collect()
    }

    #[inline]
    pub fn is_exact(&self, parts: &[&str]) -> bool {
        self.segments.len() == parts.len() && self.segments.iter().zip(parts).all(|(a, b)| a == b)
    }

    #[inline]
    pub fn starts_with(&self, parts: &[&str]) -> bool {
        self.segments.len() >= parts.len() && self.segments.iter().zip(parts).all(|(a, b)| a == b)
    }

    #[inline]
    pub fn first(&self) -> Option<&str> {
        self.segments.first().map(|s| s.as_str())
    }

    #[inline]
    pub fn last(&self) -> Option<&str> {
        self.segments.last().map(|s| s.as_str())
    }

    #[inline]
    pub fn as_str(&self) -> String {
        self.segments.join(".")
    }

    #[inline]
    pub fn is_shell_command(&self) -> bool {
        match self.segments_slice() {
            [os, submodule] if os == "os" => matches!(
                submodule.as_str(),
                "execl"
                    | "execle"
                    | "execlp"
                    | "execlpe"
                    | "execv"
                    | "execve"
                    | "execvp"
                    | "execvpe"
                    | "spawnl"
                    | "spawnle"
                    | "spawnlp"
                    | "spawnlpe"
                    | "spawnv"
                    | "spawnve"
                    | "spawnvp"
                    | "spawnvpe"
                    | "startfile"
                    | "system"
                    | "popen"
                    | "popen2"
                    | "popen3"
                    | "popen4"
                    | "posix_spawn"
                    | "posix_spawnp"
            ),
            [subprocess, submodule] if subprocess == "subprocess" => matches!(
                submodule.as_str(),
                "Popen"
                    | "call"
                    | "check_call"
                    | "check_output"
                    | "run"
                    | "getoutput"
                    | "getstatusoutput"
            ),
            [popen2, submodule] if popen2 == "popen2" => matches!(
                submodule.as_str(),
                "popen2" | "popen3" | "popen4" | "Popen3" | "Popen4"
            ),
            [commands, submodule] if commands == "commands" => {
                matches!(submodule.as_str(), "getoutput" | "getstatusoutput")
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_code_exec(&self) -> bool {
        match self.segments_slice() {
            [only] => matches!(only.as_str(), "exec" | "eval"),
            [prefix, submodule]
                if prefix == "builtins" || prefix == "__builtins__" || prefix.is_empty() =>
            {
                matches!(submodule.as_str(), "exec" | "eval")
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_indirect_exec(&self) -> bool {
        match self.segments_slice() {
            [module, class] => {
                (module == "threading" && class == "Thread")
                    || (module == "multiprocessing" && class == "Process")
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_exfiltration_sink(&self) -> bool {
        let s = self.segments_slice();
        if s.starts_with(&["urllib".to_string()])
            && (s.ends_with(&["urlopen".to_string()]) || s.ends_with(&["Request".to_string()]))
        {
            return true;
        }

        match s {
            [requests, submodule] if requests == "requests" => matches!(
                submodule.as_str(),
                "get" | "post" | "request" | "put" | "patch" | "delete"
            ),
            [http, client, connection, request]
                if http == "http"
                    && client == "client"
                    && (connection == "HTTPConnection" || connection == "HTTPSConnection")
                    && request == "request" =>
            {
                true
            }
            [socket, socket_cls, send]
                if socket == "socket"
                    && socket_cls == "socket"
                    && (send == "send" || send == "sendall" || send == "sendto") =>
            {
                true
            }
            [smtplib, smtp, send]
                if smtplib == "smtplib"
                    && (smtp == "SMTP" || smtp == "SMTP_SSL")
                    && (send == "sendmail" || send == "send_message") =>
            {
                true
            }
            [ftplib, ftp, stor]
                if ftplib == "ftplib"
                    && (ftp == "FTP" || ftp == "FTP_TLS")
                    && (stor == "storbinary" || stor == "storlines") =>
            {
                true
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_download_request(&self) -> bool {
        match self.segments_slice() {
            [module, submodule] => match module.as_str() {
                "requests" => matches!(submodule.as_str(), "get" | "post" | "request"),
                "urllib" | "urllib2" => matches!(submodule.as_str(), "urlopen"),
                _ => false,
            },
            [urllib, request, submodule] if urllib == "urllib" && request == "request" => {
                matches!(submodule.as_str(), "urlopen")
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_os_fingerprint(&self) -> bool {
        match self.segments_slice() {
            [os, uname] if os == "os" && uname == "uname" => true,
            [getpass, getuser] if getpass == "getpass" && getuser == "getuser" => true,
            [os, getlogin] if os == "os" && getlogin == "getlogin" => true,
            [platform, func] if platform == "platform" => matches!(
                func.as_str(),
                "system"
                    | "platform"
                    | "version"
                    | "release"
                    | "node"
                    | "processor"
                    | "machine"
                    | "architecture"
                    | "uname"
            ),
            [socket, gethostname] if socket == "socket" && gethostname == "gethostname" => true,
            [socket, getfqdn] if socket == "socket" && getfqdn == "getfqdn" => true,
            [os, environ, copy] if os == "os" && environ == "environ" && copy == "copy" => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_clipboard_read(&self) -> bool {
        match self.segments_slice() {
            [pyperclip, paste] if pyperclip == "pyperclip" && paste == "paste" => true,
            [win32clipboard, get]
                if win32clipboard == "win32clipboard" && get == "GetClipboardData" =>
            {
                true
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_env_access(&self) -> bool {
        match self.segments_slice() {
            [os, environ, get] if os == "os" && environ == "environ" && get == "get" => true,
            [os, getenv] if os == "os" && getenv == "getenv" => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_dll_injection(&self) -> bool {
        let s = self.segments_slice();
        if self.is_exact(&["ctypes", "CDLL"]) {
            return true;
        }

        let is_windll = (s.len() >= 4 && self.starts_with(&["ctypes", "windll"]))
            || (s.len() >= 3 && self.starts_with(&["windll"]));

        if is_windll {
            if let Some(last) = self.last() {
                return matches!(
                    last,
                    "OpenProcess"
                        | "CreateRemoteThread"
                        | "CreateProcessW"
                        | "CreateProcessA"
                        | "LoadLibraryA"
                        | "VirtualAllocEx"
                        | "WriteProcessMemory"
                        | "RtlMoveMemory"
                        | "ShellExecuteW"
                        | "ShellExecuteA"
                        | "WinExec"
                );
            }
        }
        false
    }

    #[inline]
    pub fn is_pathlib_write(&self) -> bool {
        matches!(self.segments_slice(), [pathlib, path, write]
                if pathlib == "pathlib"
                    && path == "Path"
                    && (write == "write_text" || write == "write_bytes"))
    }

    #[inline]
    pub fn is_import_call(&self) -> bool {
        match self.segments_slice() {
            [only] if only == "__import__" => true,
            [prefix, name]
                if (prefix == "builtins" || prefix == "__builtins__") && name == "__import__" =>
            {
                true
            }
            [importlib, import_module]
                if importlib == "importlib" && import_module == "import_module" =>
            {
                true
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_getattr(&self) -> bool {
        match self.segments_slice() {
            [only] if only == "getattr" => true,
            [prefix, name]
                if (prefix == "builtins" || prefix == "__builtins__") && name == "getattr" =>
            {
                true
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_eval(&self) -> bool {
        match self.segments_slice() {
            [only] if only == "eval" => true,
            [prefix, name]
                if (prefix == "builtins" || prefix == "__builtins__") && name == "eval" =>
            {
                true
            }
            _ => false,
        }
    }

    #[inline]
    pub fn is_module_registry(&self) -> bool {
        match self.segments_slice() {
            [name]
                if matches!(
                    name.as_str(),
                    "globals" | "locals" | "vars" | "builtins" | "__builtins__"
                ) =>
            {
                true
            }
            [sys, modules] if sys == "sys" && modules == "modules" => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_io_resource_constructor(&self) -> bool {
        match self.segments_slice() {
            [name] if name == "Path" => true,
            [pathlib, path] if pathlib == "pathlib" && path == "Path" => true,
            [socket, socket_cls] if socket == "socket" && socket_cls == "socket" => true,
            [smtplib, smtp] if smtplib == "smtplib" && (smtp == "SMTP" || smtp == "SMTP_SSL") => {
                true
            }
            [ftplib, ftp] if ftplib == "ftplib" && (ftp == "FTP" || ftp == "FTP_TLS") => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_vars_function(&self) -> bool {
        match self.segments_slice() {
            [name] => matches!(name.as_str(), "globals" | "locals" | "vars"),
            _ => false,
        }
    }

    #[inline]
    pub fn is_suspicious_builtin(&self) -> bool {
        let sus = [
            "__import__",
            "compile",
            "getattr",
            "globals",
            "locals",
            "vars",
            "eval",
            "exec",
        ];
        match self.segments_slice() {
            [name] if sus.contains(&name.as_str()) => true,
            [prefix, name]
                if (prefix == "builtins" || prefix == "__builtins__")
                    && sus.contains(&name.as_str()) =>
            {
                true
            }
            _ => false,
        }
    }
}

impl From<String> for QualifiedName {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for QualifiedName {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl std::fmt::Display for QualifiedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let qn = QualifiedName::new("os.path.join");
        assert_eq!(qn.segments(), vec!["os", "path", "join"]);
        assert_eq!(qn.as_str(), "os.path.join");

        let qn_empty = QualifiedName::new("");
        assert!(qn_empty.segments().is_empty());
    }

    #[test]
    fn test_is_exact() {
        let qn = QualifiedName::new("os.path.join");
        assert!(qn.is_exact(&["os", "path", "join"]));
        assert!(!qn.is_exact(&["os", "path"]));
        assert!(!qn.is_exact(&["os", "path", "join", "extra"]));
    }

    #[test]
    fn test_starts_with() {
        let qn = QualifiedName::new("os.path.join");
        assert!(qn.starts_with(&["os"]));
        assert!(qn.starts_with(&["os", "path"]));
        assert!(qn.starts_with(&["os", "path", "join"]));
        assert!(!qn.starts_with(&["os", "join"]));
    }

    #[test]
    fn test_first_last() {
        let qn = QualifiedName::new("os.path.join");
        assert_eq!(qn.first(), Some("os"));
        assert_eq!(qn.last(), Some("join"));

        let qn_empty = QualifiedName::new("");
        assert_eq!(qn_empty.first(), None);
        assert_eq!(qn_empty.last(), None);
    }

    #[test]
    fn test_is_shell_command() {
        assert!(QualifiedName::new("os.system").is_shell_command());
        assert!(QualifiedName::new("subprocess.run").is_shell_command());
        assert!(QualifiedName::new("commands.getoutput").is_shell_command());
        assert!(QualifiedName::new("popen2.popen2").is_shell_command());
        assert!(!QualifiedName::new("os.path.join").is_shell_command());
    }

    #[test]
    fn test_is_code_exec() {
        assert!(QualifiedName::new("eval").is_code_exec());
        assert!(QualifiedName::new("exec").is_code_exec());
        assert!(QualifiedName::new("builtins.eval").is_code_exec());
        assert!(QualifiedName::new("__builtins__.exec").is_code_exec());
        assert!(!QualifiedName::new("os.system").is_code_exec());
    }

    #[test]
    fn test_is_exfiltration_sink() {
        assert!(QualifiedName::new("requests.post").is_exfiltration_sink());
        assert!(QualifiedName::new("urllib.request.urlopen").is_exfiltration_sink());
        assert!(QualifiedName::new("socket.socket.send").is_exfiltration_sink());
        assert!(QualifiedName::new("smtplib.SMTP.sendmail").is_exfiltration_sink());
        assert!(!QualifiedName::new("os.system").is_exfiltration_sink());
    }

    #[test]
    fn test_is_os_fingerprint() {
        assert!(QualifiedName::new("os.uname").is_os_fingerprint());
        assert!(QualifiedName::new("platform.system").is_os_fingerprint());
        assert!(QualifiedName::new("getpass.getuser").is_os_fingerprint());
        assert!(QualifiedName::new("os.environ.copy").is_os_fingerprint());
        assert!(!QualifiedName::new("os.system").is_os_fingerprint());
    }

    #[test]
    fn test_is_suspicious_builtin() {
        assert!(QualifiedName::new("eval").is_suspicious_builtin());
        assert!(QualifiedName::new("getattr").is_suspicious_builtin());
        assert!(QualifiedName::new("__import__").is_suspicious_builtin());
        assert!(QualifiedName::new("builtins.compile").is_suspicious_builtin());
        assert!(!QualifiedName::new("os.system").is_suspicious_builtin());
    }

    #[test]
    fn test_is_import_call() {
        assert!(QualifiedName::new("__import__").is_import_call());
        assert!(QualifiedName::new("builtins.__import__").is_import_call());
        assert!(QualifiedName::new("importlib.import_module").is_import_call());
        assert!(!QualifiedName::new("os.system").is_import_call());
    }

    #[test]
    fn test_is_getattr() {
        assert!(QualifiedName::new("getattr").is_getattr());
        assert!(QualifiedName::new("builtins.getattr").is_getattr());
        assert!(!QualifiedName::new("os.system").is_getattr());
    }

    #[test]
    fn test_is_module_registry() {
        assert!(QualifiedName::new("globals").is_module_registry());
        assert!(QualifiedName::new("sys.modules").is_module_registry());
        assert!(QualifiedName::new("builtins").is_module_registry());
        assert!(!QualifiedName::new("os.path").is_module_registry());
    }

    #[test]
    fn test_is_io_resource_constructor() {
        assert!(QualifiedName::new("Path").is_io_resource_constructor());
        assert!(QualifiedName::new("pathlib.Path").is_io_resource_constructor());
        assert!(QualifiedName::new("socket.socket").is_io_resource_constructor());
        assert!(QualifiedName::new("smtplib.SMTP").is_io_resource_constructor());
        assert!(!QualifiedName::new("os.system").is_io_resource_constructor());
    }

    #[test]
    fn test_is_dll_injection() {
        assert!(QualifiedName::new("ctypes.CDLL").is_dll_injection());
        assert!(QualifiedName::new("ctypes.windll.kernel32.OpenProcess").is_dll_injection());
        assert!(QualifiedName::new("windll.kernel32.WinExec").is_dll_injection());
        assert!(!QualifiedName::new("ctypes.Structure").is_dll_injection());
    }
}
