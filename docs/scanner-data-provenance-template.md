# Data set provenance manifest (template)

Copy beside each bundled/shipped dataset and fill all fields before import.
See [review policy](scanner-data-policy.md); accepted/candidate/rejected records
must cite the terms and rationale, not only an upstream license label.

```yaml
manifest_version: 1

dataset:
  name: ""             # identifier results publish
  kind: ""             # port | service | os | vendor
  version: ""          # independent of binary/output versions
  packaged_as: ""      # bundled | separate-asset
  review_outcome: ""   # accepted | rejected | candidate-pending-terms-review

source:
  name: ""             # project, standard, or fixture author
  locator: ""          # resolvable URL/path
  retrieved: ""        # ISO-8601 date
  upstream_version: ""
  license: ""
  license_rationale: |
    # Exact terms, compatibility reasoning, or rejection rationale.

transforms:
  # Ordered reproducible steps; originals: "authored in repository; no transform".
  - step: ""
    detail: ""

maintenance:
  maintainer: ""
  refresh: |
    # Pull/re-review/test procedure and events requiring renewed terms review.

coverage:
  # Declared fixtures, not another database's size.
  - fixture: ""
    covers: ""
```
