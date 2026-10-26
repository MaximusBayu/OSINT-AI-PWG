# Colab: real PassLLM guessing (the guess layer)

The VPS runs collection + normalization + evaluation. **PassLLM itself is a 4B
model + LoRA weights and needs a GPU**, so it runs on Colab. This folder is the
Colab side: a patch to PassLLM's `app.py` and a self-contained matrix runner.

## What's here

- `app.py` / `app.py.orig` — patched vs. original PassLLM `app.py`.
- `passllm_app.patch` — the unified diff. Apply it to the cloned PassLLM repo.
- `run_matrix.py` — drives `app.py` across all 10 PassLLM conditions.
- `targets.template.json` — input format for `run_matrix.py`.

## The patch (passllm_app.patch)

Three fixes, all needed for the thesis conditions:

1. **`--base` flag** — runs the raw base model with no LoRA (condition C0b).
2. **Empty profile allowed** — the no-PII conditions (C0 empty prompt, C1 trawling)
   send `{}`; the stock `app.py` does `if not profile: sys.exit(1)`.
3. **`profile['name']` → `profile.get('name', ...)`** — the stock code crashes on an
   empty profile.

## Colab setup (once)

```
!git clone https://github.com/Tzohar/PassLLM.git
%cd PassLLM
!pip install -r requirements.txt
```

Download the weights (release v1.3.0 → saved as the filename `Config.WEIGHTS_FILE`
expects):

```
!curl -L "https://github.com/Tzohar/PassLLM/releases/download/v1.3.0/PassLLM-Qwen3-4B-v1.0.pth" \
       -o models/PassLLM_LoRA_Weights.pth
```

Apply the patch (upload `passllm_app.patch` + `run_matrix.py` into `PassLLM/`, or
copy the patched `app.py` over the clone):

```
!git apply passllm_app.patch      # or: replace app.py with the patched one
```

## Run the matrix

1. Write `targets.json` (see `targets.template.json`). For each target:
   - `osint_profile` — what the VPS collect+normalize layers recovered (9 fields).
   - `gt_profile` — the ground-truth PII (for condition C3).
   - `password` — the true password (for evaluating crack rate).
2. Run (start with `--mode fast`; use `--deep` on a high-end GPU):

```
!python run_matrix.py --targets targets.json --mode fast
```

To ship the real guesses back to the web UI in one shot, add `--post-url` (the VPS
is a public URL, so Colab can reach it directly):

```
!python run_matrix.py --targets targets.json --mode fast \
      --post-url https://pwg.maxflow.space/api/passllm/import
```

3. `matrix_results.json` records, per target × condition: `cracked`, `guess_number`,
   `num_guesses`, `top_10` (passwords), and `top_10_full` (with confidence).

4. On the VPS UI: open the target, hit **⇪ Load PassLLM results** to paste the JSON
   (if you didn't use `--post-url`), then re-run — the guess stage shows the real
   PassLLM guesses with confidence instead of the demo engine.

## Notes

- Conditions C6 (Hashcat) and C7 (random) are **not** PassLLM — they run on the
  VPS, no GPU needed.
- The profile keys map straight onto PassLLM's `schema_defaults` (name, username,
  email, birth_year/month/day, city, country, phone). No key translation needed.
- `--mode fast` fits a free Colab T4; `--deep` needs a bigger GPU (A100/L4) and is
  the mode the thesis config specifies.
