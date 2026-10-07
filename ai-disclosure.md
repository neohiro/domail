# AI Disclosure

This project was built with assistance from AI coding tools. The following
disclosures are made in the spirit of transparency:

- **Code generation**: Significant portions of the source code were drafted
  with AI assistance and then reviewed, tested, and refined by hand.
- **Testing**: The test suite (`test/core.test.mjs`) was written to verify
  correctness of the mail engine. All tests pass.
- **Documentation**: This README and other docs were drafted with AI assistance.

## What this means

The code has been verified by an automated test suite (42 tests covering
RFC 5322 message building, MIME multipart handling, base64 encoding,
address parsing, storage, and the wipe guarantee). However, no formal
security audit has been conducted. Use in production environments at your
own discretion.

## Human review

All AI-generated code has been reviewed for:
- Correctness against RFC specifications
- Absence of telemetry or network calls
- Proper error handling
- Clean integration with the existing codebase
