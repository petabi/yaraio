lalrpop_mod!(yara);

#[cfg(test)]
mod tests {
    use super::yara;

    #[test]
    fn text_string() {
        assert!(
            yara::RulesParser::new()
                .parse(
                    r#"
rule test
{
    strings:
        $hello = "Hello"
    condition:
        true
}
"#
                ).is_ok()
        );
    }
}
