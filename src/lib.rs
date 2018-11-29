#[macro_use]
extern crate lalrpop_util;

lalrpop_mod!(pub yara);

#[cfg(test)]
mod tests {
    use super::yara;

    #[test]
    fn empty() {
        assert!(yara::RulesParser::new().parse("").is_ok());
    }

    #[test]
    fn minimal_rule() {
        assert!(
            yara::RulesParser::new()
                .parse("rule dummy { condition: true }")
                .is_ok()
        );
    }

    #[test]
    fn multiple_rules() {
        let rules = yara::RulesParser::new()
            .parse(
                "
rule r1 { condition: true }
rule r2 { condition: false }
rule r3 { condition: true }
",
            ).unwrap();
        assert_eq!(rules.len(), 3);
    }
}
