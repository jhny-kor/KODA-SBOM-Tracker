# Third-party notices

KODA SBOM Tracker includes or redistributes the following principal components.
The versions below match the pinned release configuration at the time of this
notice. Package-manager metadata and image manifests remain the authoritative
inventory for a specific build.

| Component | Version | License | Source |
| --- | --- | --- | --- |
| CEL Python runtime | 0.1.3 | Apache-2.0 | https://github.com/cel-expr/cel-python |
| Apache Maven ComparableVersion algorithm (adapted Python implementation) | 3.9.11 | Apache-2.0 | https://github.com/apache/maven/blob/maven-3.9.11/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java |
| Grype | 0.109.1 | Apache-2.0 | https://github.com/anchore/grype |
| CycloneDX CLI | 0.30.0 | Apache-2.0 | https://github.com/CycloneDX/cyclonedx-cli |
| React and React DOM | 19.2.3 | MIT | https://github.com/facebook/react |
| Scheduler | 0.27.0 | MIT | https://github.com/facebook/react |
| Vite | 7.3.6 | MIT and bundled third-party notices | https://github.com/vitejs/vite |
| Vite React plugin | 4.7.0 | MIT | https://github.com/vitejs/vite-plugin-react |
| Pretendard | 1.3.9 | SIL Open Font License 1.1 | https://github.com/orioncactus/pretendard |
| Inno Setup | 6.x build tool | Inno Setup License | https://jrsoftware.org/files/is/license.txt |

Apache-2.0 components use the license text in `LICENSE`. CycloneDX attribution
required by its NOTICE is reproduced in the root `NOTICE` file. Web builds and
the Dockerless Windows preview copy the web package license texts from the exact
installed packages into their `legal` directory. Python
packages and container base images retain license material supplied by their
package or image publishers.

## Presentation and documentation assets

The guide decks under `docs/presentations/` are single self-contained HTML files
intended for closed-network use, so they embed their fonts and libraries instead
of loading them from a CDN. The components below are redistributed inside those
files only; the Tracker, KODA, and web application builds do not include them.

| Component | Version | License | Embedded in |
| --- | --- | --- | --- |
| three.js | r128 | MIT | `KODA 사용자 가이드.html` |
| IBM Plex Sans KR | Google Fonts v11 | SIL Open Font License 1.1 | all guide decks |
| IBM Plex Mono | Google Fonts v20 | SIL Open Font License 1.1 | `KODA 사용자 가이드.html`, `koda-suite-user-briefing.html` |
| JetBrains Mono | Google Fonts v24 | SIL Open Font License 1.1 | `koda-flow.html` |

Only the glyph subsets a deck actually renders are embedded, not the complete
font families. The three.js copyright header and its `SPDX-License-Identifier:
MIT` line are retained verbatim in the embedded script. Sources:
https://github.com/mrdoob/three.js, https://github.com/IBM/plex,
https://github.com/JetBrains/JetBrainsMono

## Distribution boundary

The Dockerless Windows preview contains only the compiled web application and
may be distributed with its `legal` directory intact.

Bundles that redistribute third-party container images, including the air-gap,
offline, and full Windows packages, are **internal-only**. External distribution
to customers, partners, affiliates, or the public is unsupported until KODA has
approved a complete corresponding-source offer or bundle for every applicable
copyleft component and completed legal review. The build scripts reject an
external distribution scope so this boundary cannot be bypassed accidentally.

This notice is an engineering compliance record, not legal advice or a legal
certification.
