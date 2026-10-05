# Data set provenance manifest (template)

Copy this file beside each bundled or shipped scanner data set and fill every
field, per the [scanner data policy](scanner-data-policy.md). A data set is not
imported until its manifest is complete and the source review it records has
passed.

```yaml
manifest_version: 1

dataset:
  name: ""             # short identifier results can name, e.g. "port-catalog"
  kind: ""             # port | service | os | vendor
  version: ""          # this data set's own version, independent of the binary
                       # and the output contract
  packaged_as: ""      # bundled | separate-asset
  review_outcome: ""   # accepted | rejected | candidate-pending-terms-review

source:
  name: ""             # upstream project, standard, or fixture author
  locator: ""          # URL or other resolvable reference
  retrieved: ""        # ISO-8601 retrieval date of the source content
  upstream_version: "" # upstream release or revision, if any
  license: ""          # the source's license or terms, as identified at review
  license_rationale: |
    # Why redistribution of this source under or alongside AGPL-3.0-only is
    # sound — or why it was rejected. "The tool is open source" is not a
    # rationale. Cite the specific terms reviewed.

transforms:
  # Every step between the retrieved source and the shipped form, in order,
  # so a reviewer can reproduce the artifact. For original project-authored
  # fixtures, state "authored in repository; no transform".
  - step: ""
    detail: ""

maintenance:
  maintainer: ""       # named owner of this data set
  refresh: |
    # How upstream changes are pulled, re-reviewed, and re-tested, and which
    # refresh events require repeating the license review.

coverage:
  # What the data set covers, stated against declared fixtures — never
  # against another tool's database size.
  - fixture: ""
    covers: ""
```
