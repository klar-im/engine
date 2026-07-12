# Model licence (separate from the code)

The code in this repository is AGPLv3 (`LICENSE`). The model is licensed
separately, under **CC-BY-NC-4.0**.

## Production model: CC-BY-NC-4.0 (non-commercial)

The shipping classifier (the high-quality model the Klar apps use,
[`icosha/spam-xlmr-v1`](https://huggingface.co/icosha/spam-xlmr-v1)) is
published publicly under **CC-BY-NC-4.0**. It is **not** under the AGPL grant.

- **Non-commercial use is free**, with attribution to Klar: use it for personal
  self-hosting, research, and evaluation under the CC-BY-NC-4.0 terms.
- **Commercial use** (production filtering as a business, hosting a paid service,
  or any use primarily for commercial advantage) requires a separate paid
  licence. **Contact hello@klar.im** for commercial terms.
- The commercial relationship is also where any opt-in contribution arrangement
  (sharing anonymised correction signal to improve the shared model) is agreed;
  it is never automatic and never part of the free tier.

This split is intentional: the engine and milter are open source (AGPLv3); the
trained weights are free for non-commercial use and paid for commercial use.
