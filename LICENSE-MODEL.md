# Model licence (separate from the code)

The code in this repository is AGPLv3 (`LICENSE`). The model is licensed
separately, under **CC-BY-NC-4.0**.

## Production model: CC-BY-NC-4.0 (non-commercial)

The shipping classifier (the model the Klar apps use, named by
`infra/released-model.env` in the private monorepo and pinned here as
`postfix/model/released-manifest.json`: today **gen3-v6**, Klar's own
fine-tune of the MIT-licensed `intfloat/multilingual-e5-base` encoder, fetched
by `fetch_model.sh` from Klar's download bucket) is distributed under
**CC-BY-NC-4.0**. It is **not** under the AGPL grant. Klar's first public
model, [`icosha/spam-xlmr-v1`](https://huggingface.co/icosha/spam-xlmr-v1)
(XLM-RoBERTa-large), carries the same terms.

- **Non-commercial use is free**, with attribution to Klar, under the
  CC-BY-NC-4.0 terms. For us that covers a personal or family home server, a
  hobby project, and academic research.
- **Commercial use** requires a separate paid licence: filtering mail for a
  company (its own staff included, a trial on real staff mail included),
  hosting a paid service, or any use primarily for commercial advantage.
  **Contact hello@klar.im** for commercial terms; a company trial is easy to
  agree in writing.
- **When in doubt, ask us at hello@klar.im before you deploy.** We answer in
  plain words, and a yes from us in writing is a permission you can keep.
- The commercial relationship is also where any opt-in contribution arrangement
  (sharing anonymised correction signal to improve the shared model) is agreed;
  it is never automatic and never part of the free tier.

This split is intentional: the engine and milter are open source (AGPLv3); the
trained weights are free for non-commercial use and paid for commercial use.
