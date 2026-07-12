# Model licence (separate from the code)

The code in this repository is AGPLv3 (`LICENSE`). There are **two models**, under
**two different licences**, the open-core split:

| Model | Licence | What you get |
|---|---|---|
| **Demo (toy)** | **AGPLv3**, same as the code | A small, deliberately weak model so this repo builds and runs out of the box. Free to use, modify, redistribute under AGPLv3. |
| **Production** | **CC-BY-NC-4.0** (non-commercial) | The high-quality classifier the Klar apps use. Free for non-commercial use with attribution; commercial use needs a paid licence. |

## Demo model: AGPLv3, free

[`icosha/klar-spam-demo`](https://huggingface.co/icosha/klar-spam-demo) is a small,
deliberately weak distilled model published under **AGPLv3** so the engine builds
and runs without the commercial weights. It is a toy, not fit for real spam
filtering, but it is genuinely free: use, modify, and redistribute it under the
same AGPLv3 terms as the engine. The free OSS tier is the engine + this demo model,
fully open.

## Production model: CC-BY-NC-4.0 (non-commercial)

The shipping classifier (the high-quality model the Klar apps use) is published
publicly under **CC-BY-NC-4.0**. It is **not** under the AGPL grant.

- **Non-commercial use is free**, with attribution to Klar: use it for personal
  self-hosting, research, and evaluation under the CC-BY-NC-4.0 terms.
- **Commercial use** (production filtering as a business, hosting a paid service,
  or any use primarily for commercial advantage) requires a separate paid
  licence. **Contact hello@klar.im** for commercial terms.
- The commercial relationship is also where any opt-in contribution arrangement
  (sharing anonymised correction signal to improve the shared model) is agreed;
  it is never automatic and never part of the free tier.

This split is intentional: the engine, milter, and a working toy model are open
source (AGPLv3); the high-quality trained weights are free for non-commercial use
and paid for commercial use.
