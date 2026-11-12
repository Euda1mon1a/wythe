# Contributing

Please read [SUPPORT.md](SUPPORT.md) first. Wythe is maintained for its author's own use and published **as is**.

- Issues and pull requests are not guaranteed a review, a reply, or a merge, and may be closed without discussion.
- Requests for new stacks, features, or fixes for a specific environment will usually not be acted on. Forking is the supported way to get a change you need.
- Backward compatibility is not promised between versions. Pin an exact version.

If you still want to send a change:

1. Keep it small and focused on one problem.
2. Include a regression test that fails without the change.
3. Run `make lint`, `make test`, and `make gate` (strict self-dogfood) before opening the pull request.
