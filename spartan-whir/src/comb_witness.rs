//! Preserve the generated comb lookup while representing its constants as data.
//!
//! Circom emits millions of scalar copies to reconstruct its literal table.
//! The R1CS uses the original Circom expressions; only the generated native
//! function that materializes the same table is replaced by a copy loop.

use std::{fmt::Write as _, fs, path::Path};

use anyhow::{Context, Result, bail, ensure};

const CURVES: usize = 2;
const WINDOWS: usize = 22;
const ROWS: usize = 2048;
const LIMBS: usize = 44;
const TABLE_SIZE: usize = ROWS * LIMBS;
const SIGNATURE: &str = "(Circom_CalcWit* ctx,FrElement lvar[],uint componentFather,FrElement& destination,int destination_size)";

/// Compact only the comb table's generated C++ function. The source is a fresh
/// output from the pinned KoalaBear compiler, in a temporary build directory.
pub(crate) fn compact(source_cpp: &Path) -> Result<()> {
    let constants =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("circuits/ecdsa/comb_constants.circom");
    compact_with_constants(source_cpp, &constants)
}

fn compact_with_constants(source_cpp: &Path, constants: &Path) -> Result<()> {
    let directory = source_cpp.parent().context("native C++ source directory")?;
    let field = fs::read_to_string(directory.join("fr.hpp"))?;
    ensure!(
        field
            .lines()
            .any(|line| line == "typedef uint32_t FrElement;")
            && field
                .lines()
                .any(|line| line == "#define Fr_prime 2130706433u"),
        "comb table compaction requires the pinned KoalaBear native representation"
    );
    let table_source = fs::read_to_string(constants)
        .with_context(|| format!("read comb constants {}", constants.display()))?;
    let values = parse_tables(&table_source, CURVES, WINDOWS, ROWS, LIMBS)?;
    let mut generated = fs::read_to_string(source_cpp)
        .with_context(|| format!("read native circuit {}", source_cpp.display()))?;
    let (start, end, name) = table_function(&generated)?;
    let body = &generated[start..end];
    ensure!(
        body.contains("std::string myTemplateName = \"kb_comb_table\";")
            && body.ends_with(
                "Fr_copyn(&destination,&lvar[2],std::min(90112,destination_size));\nreturn;\n}"
            ),
        "unexpected generated comb table function body"
    );
    let replacement = format!(
        "void {name}{SIGNATURE}{{\n\
         if (destination_size != {TABLE_SIZE} || lvar[0] >= {CURVES}u || lvar[1] >= {WINDOWS}u)\n\
         throw std::runtime_error(\"invalid comb table request\");\n\
         FrElement* output = &destination;\n\
         for (unsigned row = 0; row < {ROWS}u; row++)\n\
         for (unsigned limb = 0; limb < {LIMBS}u; limb++)\n\
         output[row*{LIMBS}u+limb] = kbCombConstants[lvar[0]][lvar[1]][row][limb];\n\
         }}"
    );
    generated.replace_range(start..end, &replacement);
    generated.insert_str(
        0,
        "#include \"comb_native_constants.hpp\"\n#include <stdexcept>\n",
    );
    fs::write(
        directory.join("comb_native_constants.hpp"),
        header(&values)?,
    )?;
    fs::write(source_cpp, generated)?;
    Ok(())
}

fn expect<'a>(lines: &mut impl Iterator<Item = &'a str>, expected: &str) -> Result<()> {
    let observed = lines.next().context("truncated comb constants")?;
    ensure!(
        observed == expected,
        "expected {expected:?}, found {observed:?}"
    );
    Ok(())
}

/// Accept only the literal array format emitted by `comb_generator.py`.
fn parse_tables(
    text: &str,
    curves: usize,
    windows: usize,
    rows: usize,
    limbs: usize,
) -> Result<Vec<u16>> {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    loop {
        let line = lines.next().context("missing comb table function")?;
        if line == "function kb_comb_table(p256, window) {" {
            break;
        }
        ensure!(
            line.starts_with("//") || line == "pragma circom 2.2.0;",
            "unexpected comb constants prefix {line:?}"
        );
    }
    expect(&mut lines, &format!("var out[{rows}][{limbs}];"))?;
    let mut values = Vec::with_capacity(curves * windows * rows * limbs);
    for curve in 0..curves {
        expect(&mut lines, &format!("if (p256 == {curve}) {{"))?;
        for window in 0..windows {
            expect(&mut lines, &format!("if (window == {window}) {{"))?;
            expect(&mut lines, "out = [")?;
            for row in 0..rows {
                let line = lines.next().context("truncated comb table row")?;
                let suffix = if row + 1 == rows { "]" } else { "]," };
                let contents = line
                    .strip_prefix('[')
                    .and_then(|line| line.strip_suffix(suffix))
                    .context("invalid comb table row delimiters")?;
                let mut count = 0;
                for value in contents.split(',') {
                    ensure!(
                        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
                        "comb coefficient must be a decimal integer literal"
                    );
                    let value: u16 = value.parse().context("comb coefficient exceeds u16")?;
                    ensure!(value < 4096, "comb coefficient exceeds a 12-bit limb");
                    values.push(value);
                    count += 1;
                }
                ensure!(
                    count == limbs,
                    "comb row has {count} limbs, expected {limbs}"
                );
            }
            expect(&mut lines, "];")?;
            expect(&mut lines, "}")?;
        }
        expect(&mut lines, "}")?;
    }
    expect(&mut lines, "return out;")?;
    expect(&mut lines, "}")?;
    ensure!(
        lines.next().is_none(),
        "unexpected content after comb table"
    );
    Ok(values)
}

fn header(values: &[u16]) -> Result<String> {
    ensure!(
        values.len() == CURVES * WINDOWS * TABLE_SIZE,
        "invalid comb table size"
    );
    let mut text = format!(
        "#ifndef CSP_KOALABEAR_COMB_CONSTANTS_HPP\n\
         #define CSP_KOALABEAR_COMB_CONSTANTS_HPP\n\
         #include <stdint.h>\n\
         static const uint16_t kbCombConstants[{CURVES}][{WINDOWS}][{ROWS}][{LIMBS}] = {{\n"
    );
    let mut rows = values.chunks_exact(LIMBS);
    for _ in 0..CURVES {
        text.push_str("{\n");
        for _ in 0..WINDOWS {
            text.push_str("{\n");
            for _ in 0..ROWS {
                text.push('{');
                for (i, value) in rows.next().unwrap().iter().enumerate() {
                    if i != 0 {
                        text.push(',');
                    }
                    write!(text, "{value}")?;
                }
                text.push_str("},\n");
            }
            text.push_str("},\n");
        }
        text.push_str("},\n");
    }
    text.push_str("};\n#endif\n");
    Ok(text)
}

/// Locate exactly one declaration and definition with the pinned ABI. A fresh
/// generated function has only brace-delimited C++ blocks and no brace-bearing
/// strings or block comments, so its body ends at the next function boundary.
fn table_function(text: &str) -> Result<(usize, usize, String)> {
    let prefix = "void kb_comb_table_";
    let mut name = None;
    let mut declaration = false;
    let mut definition = None;
    for (start, _) in text.match_indices(prefix) {
        ensure!(
            start == 0 || text.as_bytes()[start - 1] == b'\n',
            "unexpected comb declaration location"
        );
        let remainder = &text[start + "void ".len()..];
        let (function_name, suffix) = remainder
            .split_once('(')
            .context("invalid comb function name")?;
        let number = function_name.strip_prefix("kb_comb_table_").unwrap();
        ensure!(
            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid comb function number"
        );
        if let Some(previous) = &name {
            ensure!(
                previous == function_name,
                "multiple generated comb table functions"
            );
        } else {
            name = Some(function_name.to_owned());
        }
        let signature = &text[start + "void ".len() + function_name.len()..];
        let tail = signature
            .strip_prefix(SIGNATURE)
            .context("unexpected comb table native ABI")?;
        if tail.starts_with(';') {
            ensure!(!declaration, "duplicate comb declaration");
            declaration = true;
        } else if tail.starts_with('{') {
            ensure!(definition.is_none(), "duplicate comb definition");
            let body_start = start + "void ".len() + function_name.len() + SIGNATURE.len();
            let mut depth = 0usize;
            let mut end = None;
            for (offset, byte) in text.as_bytes()[body_start..].iter().enumerate() {
                match byte {
                    b'{' => depth += 1,
                    b'}' => {
                        depth = depth
                            .checked_sub(1)
                            .context("unbalanced comb function braces")?;
                        if depth == 0 {
                            end = Some(body_start + offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            definition = Some((start, end.context("unterminated comb function")?));
        } else {
            bail!("unexpected comb table function declaration");
        }
        // The signature is checked above in full; `suffix` establishes that
        // the first parenthesis belongs to this name rather than later text.
        let _ = suffix;
    }
    ensure!(declaration, "missing comb table declaration");
    let (start, end) = definition.context("missing comb table definition")?;
    Ok((start, end, name.context("missing comb table function")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_tables() -> String {
        let mut text =
            "pragma circom 2.2.0;\nfunction kb_comb_table(p256, window) {\nvar out[2][2];\n"
                .to_owned();
        for curve in 0..2 {
            writeln!(text, "if (p256 == {curve}) {{").unwrap();
            for window in 0..2 {
                writeln!(text, "if (window == {window}) {{\nout = [").unwrap();
                writeln!(
                    text,
                    "[{},{}],\n[{},{}]\n];\n}}",
                    curve,
                    window,
                    curve + 2,
                    window + 2
                )
                .unwrap();
            }
            text.push_str("}\n");
        }
        text.push_str("return out;\n}\n");
        text
    }

    #[test]
    fn literal_tables_preserve_order_and_reject_invalid_shapes() -> Result<()> {
        let tables = small_tables();
        assert_eq!(
            parse_tables(&tables, 2, 2, 2, 2)?,
            [0, 0, 2, 2, 0, 1, 2, 3, 1, 0, 3, 2, 1, 1, 3, 3]
        );
        for bad in [
            tables.replace("[0,0]", "[4096,0]"),
            tables.replace("[0,0]", "[1+1,0]"),
            tables.replace("[0,0]", "[0]"),
            tables.replacen("window == 0", "window == 1", 1),
            format!("{tables}function extra() {{}}"),
        ] {
            assert!(parse_tables(&bad, 2, 2, 2, 2).is_err());
        }
        Ok(())
    }

    #[test]
    fn generated_function_boundaries_and_abi_are_strict() -> Result<()> {
        let declaration = format!("void kb_comb_table_7{SIGNATURE};\n");
        let definition = format!("void kb_comb_table_7{SIGNATURE}{{\nif (1) {{}}\n}}\n");
        let text = format!("prefix\n{declaration}{definition}void next(){{}}\n");
        let (start, end, name) = table_function(&text)?;
        assert_eq!(name, "kb_comb_table_7");
        assert_eq!(&text[start..end], definition.trim_end());
        assert!(table_function(&definition).is_err());
        assert!(table_function(&text.replace("destination_size)", "wrong_size)")).is_err());
        assert!(table_function(&format!("{text}{definition}")).is_err());
        assert!(table_function(&text.replace("void next(){}", "void kb_comb_table_8();")).is_err());
        Ok(())
    }
}
