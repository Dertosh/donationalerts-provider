# Contributing

[English](./CONTRIBUTING.md) | [Русский](./CONTRIBUTING.ru.md)

Thank you for helping improve DonationAlerts Provider. Contributions are welcome through GitHub issues and pull requests.

## Before opening an issue

- Search existing issues first.
- For bugs, include OBS and Windows versions, steps to reproduce, expected and actual behavior, and relevant sanitized OBS logs.
- Never post OAuth client secrets, access or refresh tokens, widget keys, authorization codes, donor names, or private donation messages. Remove them from screenshots and logs.
- Use an issue for discussion or a bug report; use a pull request for a proposed code or documentation change.

## Pull requests

1. Fork the repository and create a focused branch.
2. Keep changes scoped to one fix or feature and update directly related documentation.
3. Build and run the regression tests using the commands in the README. Include the results and any relevant OBS/Windows versions in the pull request.
4. Do not include credentials, generated build output, OBS SDK downloads, or unrelated formatting changes.
5. Link the related issue when applicable and describe behavior changes or manual test steps.

Please sign off each commit with the Developer Certificate of Origin (DCO), version 1.1. This certifies that you have the right to submit the contribution under the project's license; it does not transfer your copyright or require a separate CLA. Add the sign-off with:

```text
git commit -s
```

The resulting commit message includes a `Signed-off-by: Name <email>` line. The DCO text is available at <https://developercertificate.org/>.

By submitting a contribution, you agree that your contribution is made available under **GPL-2.0-or-later**, consistent with the project license. You retain copyright in your contribution.

## Local validation

From the repository root in PowerShell, you can run the provider-server regression tests without building the OBS SDK:

```powershell
cmake -S .\obs-plugin\tests -B .\build\provider-server-tests -G "Visual Studio 17 2022" -A x64
cmake --build .\build\provider-server-tests --config Release
ctest --test-dir .\build\provider-server-tests -C Release --output-on-failure
git diff --check
```

The same Windows x64 regression tests run automatically for pushes to `main` and pull requests. The full OBS plugin build still requires the OBS SDK setup described in the README.

If you change a widget, also test it in an OBS Browser Source and confirm that test controls remain hidden in stream/overlay mode.
