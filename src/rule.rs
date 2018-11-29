lalrpop_mod!(yara);

bitflags! {
    // We use the same values as those defined in yara/types.h.
    pub struct StringModifiers: u32 {
        const NONE     = 0b000000000000;
        const NOCASE   = 0b000000000100;
        const ASCII    = 0b000000001000;
        const WIDE     = 0b000000010000;
        const FULLWORD = 0b000010000000;
        const XOR      = 0b100000000000;
    }
}

pub struct Rule {
    identifier: String,
    global: bool,
    private: bool,
    tags: Vec<String>,
    meta: Vec<(String, String)>,
    strings: Vec<(String, String, StringModifiers)>,
}

impl Rule {
    pub fn new(
        identifier: &str,
        modifiers: (bool, bool),
        tags: Vec<String>,
        meta: Vec<(String, String)>,
        strings: Vec<(String, String, StringModifiers)>,
    ) -> Rule {
        Rule {
            identifier: identifier.to_string(),
            global: modifiers.0,
            private: modifiers.1,
            tags,
            meta,
            strings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{yara, StringModifiers};

    #[test]
    fn rule_meta() {
        let rule = yara::RulesParser::new()
            .parse(
                r#"
rule test
{
    meta:
        meta0 = "Hello"
        meta1 = "World"
    condition:
        true
}
"#,
            ).unwrap();
        assert_eq!(rule[0].meta[0].0.as_str(), "meta0");
        assert_eq!(rule[0].meta[0].1.as_str(), "Hello");
        assert_eq!(rule[0].meta[1].0.as_str(), "meta1");
        assert_eq!(rule[0].meta[1].1.as_str(), "World");
    }

    #[test]
    fn rule_modifiers() {
        let rule = yara::RulesParser::new()
            .parse(
                r#"
rule test0
{
    condition:
        true
}

global rule test1
{
    condition:
        true
}

private rule test1
{
    condition:
        true
}

global private rule test1
{
    condition:
        true
}
"#,
            ).unwrap();
        assert!(!rule[0].global);
        assert!(!rule[0].private);
        assert!(rule[1].global);
        assert!(!rule[1].private);
        assert!(!rule[2].global);
        assert!(rule[2].private);
        assert!(rule[3].global);
        assert!(rule[3].private);
    }

    #[test]
    fn rule_strings() {
        let rule = yara::RulesParser::new()
            .parse(
                r#"
rule test
{
    strings:
        $hello = "Hello"
        $world = "World"
    condition:
        true
}
"#,
            ).unwrap();
        assert_eq!(rule[0].strings[0].0.as_str(), "$hello");
        assert_eq!(rule[0].strings[0].1.as_str(), "Hello");
        assert_eq!(rule[0].strings[1].0.as_str(), "$world");
        assert_eq!(rule[0].strings[1].1.as_str(), "World");
    }

    #[test]
    fn rule_tag() {
        let rule = yara::RulesParser::new()
            .parse(
                r#"
rule test : Hello World
{
    condition:
        true
}
"#,
            ).unwrap();
        assert_eq!(rule[0].tags[0].as_str(), "Hello");
        assert_eq!(rule[0].tags[1].as_str(), "World");
    }

    #[test]
    fn string_modifiers() {
        let rule = yara::RulesParser::new()
            .parse(
                r#"
rule test
{
    strings:
        $hello = "Hello" nocase wide
    condition:
        true
}
"#,
            ).unwrap();
        assert_eq!(
            rule[0].strings[0].2,
            StringModifiers::NOCASE | StringModifiers::WIDE
        );
    }
}
