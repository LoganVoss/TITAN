# Benchmarks

| Path | Role |
| --- | --- |
| [`run_v12_campaign.py`](run_v12_campaign.py) | Flagship campaign runner |
| [`campaigns/titan-v12-gpt55-grok43/`](campaigns/titan-v12-gpt55-grok43/) | Sealed live campaign outputs |

```bash
python benchmarks/run_v12_campaign.py
# live: OPENAI_API_KEY + XAI_API_KEY
python benchmarks/run_v12_campaign.py --live --require-provider-cert
```

Evidence: [`docs/flagship/`](../docs/flagship/) · [`results/flagship/`](../results/flagship/)
