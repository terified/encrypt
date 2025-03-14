extern crate regex;
use regex::Regex;

pub fn validate_input(input: &str, pattern: &str) -> Result<(), &str> {
    let re = Regex::new(pattern).map_err(|_| "Invalid regex pattern")?;
    if re.is_match(input) {
        Ok(())
    } else {
        Err("Input does not match the required pattern")
    }
}

pub fn escape_html(input: &str) -> String {
    input.replace("<", "&lt;").replace(">", "&gt;")
}

pub fn generate_csrf_token() -> String {
    use rand::{distributions::Alphanumeric, Rng};
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_input() {
        assert!(validate_input("test@example.com", r"^[^\s@]+@[^\s@]+\.[^\s@]+$").is_ok());
        assert!(validate_input("invalid-email", r"^[^\s@]+@[^\s@]+\.[^\s@]+$").is_err());
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
    }

    #[test]
    fn test_generate_csrf_token() {
        let token1 = generate_csrf_token();
        let token2 = generate_csrf_token();
        assert_eq!(token1.len(), 32);
        assert_eq!(token2.len(), 32);
        assert_ne!(token1, token2);
    }
}