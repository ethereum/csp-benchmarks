// Auto-generated. Do not edit.

// BEGIN_DECL
declare_circuit!(SHA256Circuit{{LEN}} { input: [Variable; {{LEN}}], output: [PublicVariable; OUTPUT_LEN], });
impl Define<M31SingleConfig> for SHA256Circuit{{LEN}}<Variable> {
    fn define<Builder: RootAPI<M31SingleConfig>>(&self, api: &mut Builder) {
        let mut data = self.input.to_vec();
        data.extend(self.output.to_vec());
        api.memorized_simple_call(|api, data| check_sha256_var(api, data), &data);
    }
}
// END_DECL

{{CIRCUIT_DECLS}}

macro_rules! match_sha2_sizes {
    ($input_len:expr, $arm:ident) => { match $input_len {
{{MATCH_ARMS}}
        _ => panic!("unsupported input length: {}", $input_len),
    }};
}

// BEGIN_MATCH_ARM
        {{LEN}} => $arm!(SHA256Circuit{{LEN}}, {{LEN}}),
// END_MATCH_ARM

