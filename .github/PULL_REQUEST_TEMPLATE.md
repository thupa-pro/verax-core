## Description

<!-- Describe the change and why it's needed. Link to any related issues. -->

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactoring
- [ ] Security fix
- [ ] CI/Build change

## Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test --workspace` passes (all 89+ tests)
- [ ] PR uses conventional commit format (`feat:`, `fix:`, `docs:`, etc.)
- [ ] No `unsafe` code in `verax-core` crate
- [ ] No `unwrap()` or `expect()` in production code paths
- [ ] New public API has `///` doc comments
- [ ] `CHANGELOG.md` updated (if user-facing change)

## Security Considerations

<!-- If this change affects security properties (signing, verification, crypto, CT, shredding), describe the implications. -->

## Additional Context

<!-- Any other information reviewers should know. -->
