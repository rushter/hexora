#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedName {
    segments: Vec<String>,
}

impl QualifiedName {
    pub fn new<S: Into<String>>(qualified_name: S) -> Self {
        let s = qualified_name.into();
        let segments = if s.is_empty() {
            Vec::new()
        } else {
            s.split('.').map(|s| s.to_string()).collect()
        };
        Self { segments }
    }

    pub fn from_segments(segments: Vec<String>) -> Self {
        Self { segments }
    }

    pub fn segments(&self) -> Vec<&str> {
        self.segments.iter().map(|s| s.as_str()).collect()
    }

    pub fn is_exact(&self, parts: &[&str]) -> bool {
        self.segments.len() == parts.len() && self.segments.iter().zip(parts).all(|(a, b)| a == b)
    }

    pub fn first(&self) -> Option<&str> {
        self.segments.first().map(|s| s.as_str())
    }

    pub fn last(&self) -> Option<&str> {
        self.segments.last().map(|s| s.as_str())
    }

    pub fn as_str(&self) -> String {
        self.segments.join(".")
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
