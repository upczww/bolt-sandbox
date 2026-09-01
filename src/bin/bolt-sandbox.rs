fn main() {}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf, time::Duration};

    use super::*;

    #[test]
    fn cli_001_run_parser_preserves_native_program_arguments() {
        let parsed = parse_run_arguments(vec![
            OsString::from("run"),
            OsString::from("--component-root"),
            OsString::from(r"C:\components"),
            OsString::from("--cwd"),
            OsString::from(r"C:\work"),
            OsString::from("--timeout-ms"),
            OsString::from("2500"),
            OsString::from("--"),
            OsString::from(r"C:\Program Files\tool.exe"),
            OsString::from(""),
            OsString::from("空 格"),
        ])
        .expect("valid run arguments must parse");

        assert_eq!(parsed.component_root, PathBuf::from(r"C:\components"));
        assert_eq!(parsed.cwd, PathBuf::from(r"C:\work"));
        assert_eq!(parsed.timeout, Some(Duration::from_millis(2_500)));
        assert_eq!(parsed.program, PathBuf::from(r"C:\Program Files\tool.exe"));
        assert_eq!(parsed.arguments, [OsString::from(""), OsString::from("空 格")]);
    }

    #[test]
    fn cli_002_parser_rejects_missing_separator_value_and_program() {
        for arguments in [
            vec![OsString::from("run")],
            vec![
                OsString::from("run"),
                OsString::from("--component-root"),
            ],
            vec![
                OsString::from("run"),
                OsString::from("--component-root"),
                OsString::from(r"C:\components"),
                OsString::from("--cwd"),
                OsString::from(r"C:\work"),
                OsString::from(r"C:\tool.exe"),
            ],
        ] {
            assert!(parse_run_arguments(arguments).is_err());
        }
    }
}
