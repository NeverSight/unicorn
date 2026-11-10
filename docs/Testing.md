# Testing in Unicorn

Unicorn focus on the testing to reduce bugs and ensure the expected behaviors. The `tests/` directory contains a few subdirectories for testing purposes.

- `unit/`: C unit tests since Unicorn 2.
- `regress/`: The regression tests written in Python and C, imported from Unicorn 1.
- `rust-tests/`: The tests written in rust.
- `fuzz/`: The fuzz drivers for OSS-Fuzz.
- `benchmarks/`: The benchmark suite imported from Unicorn 1.

## Contribution Guide

Generally, it is ideal to add new tests whenever a PR is made. `unit/` should be the first place for the new tests to go.
`test_mips_dsp_zero` checks MIPS32 packed DSP arithmetic, saturated absolute
values and left shifts with discarded or aliased GPR results in both byte orders.
Status.MX is enabled before comparing manual-derived DSPControl effects.
Separate disabled-DSP cases must still fault when the destination is `$zero`.
