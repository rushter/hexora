/// Encrypts strings to avoid false positive detections by antivirus software.
/// They scan binaries for strings and some of them trigger detection.
macro_rules! es {
    ($s:expr) => {{
        const KEY: u8 = 0xDE;
        const LEN: usize = $s.len();

        const fn encode() -> [u8; LEN] {
            let bytes = $s.as_bytes();
            let mut out = [0u8; LEN];
            let mut i = 0;
            while i < LEN {
                out[i] = bytes[i] ^ KEY;
                i += 1;
            }
            out
        }

        static OBF: [u8; LEN] = encode();

        {
            let mut buf = Vec::with_capacity(LEN);
            for &b in OBF.iter() {
                buf.push(b ^ KEY);
            }
            String::from_utf8(buf).unwrap()
        }
    }};
}

pub(crate) use es;
