* Tudo nasce em **ubl-kernel** (hash + assinatura).  
* O **Ledger Engine** é a memória legal.  
* A **Membrana** decide ALLOW/DENY em < 1 ms.  
* O **Wallet** assina Permits; o **Policy Engine** dá o veredito determinístico.  
* O **Runner** executa jobs isolados e volta com Receipts.  
* O **Portal** mostra tudo em tempo-real, docs vivas e playground.

---

## 🦸‍♂️ Agentes de A a Z

### 1. Núcleo Técnico
| ID | Persona | Superpoder | Resultados esperados |
|----|---------|------------|----------------------|
| **R1 – Kernel Crafter** | Rust ninja | Transforma JSON em hash e assinatura incorruptíveis. | Crate `ubl-kernel` v0.1 + cobertura 90 %. |
| **R2 – Ledger Smith** | Rust artesão | Forja a corrente Imutável; nada escapa sem rastro. | Serviço `ledger-engine` com Merkle-root diário. |
| **R3 – Membrane Guard** | Latency-sniper | Faz ALLOW/DENY voarem em < 1 ms. | Binário `membrana` + Grafana “p95 < 1 ms”. |

### 2. Plataforma & Segurança
| ID | Persona | Superpoder | Resultados esperados |
|----|---------|------------|----------------------|
| **S1 – Policy Architect** | DSL-mago (TS) | Compila TDLN ↓ WASM 💡. | `policy-engine` npm + hash pinning. |
| **S2 – Vault Keeper** | WebAuthn-sensei | Assinatura 2-eyes com passkey (nada de senhas!). | `wallet` emite Permits revogáveis. |
| **S3 – Audit Oracle** | Compliance Jedi | Prova que não confiamos — verificamos. | Relatório SOC-2: ZERO findings críticos. |

### 3. Experiência Developer
| ID | Persona | Superpoder | Resultados esperados |
|----|---------|------------|----------------------|
| **D1 – CLI Gardener** | UX-Rustler | Um único comando: `ubl verify foo.zip ✔`. | Binary `ubl` + autocomplete. |
| **D2 – Portal Curator** | Front-craftsperson | Docs, Dark/Light, playground “colar envelope”. | Site estático < 1 MB, Lighthouse 100. |
| **D3 – Observability Ranger** | Grafanista | Latência, denies, Merkle diff — tudo num clique. | Dashboards provisionados JSON. |

### 4. Execução & Entrega
| ID | Persona | Superpoder | Resultados esperados |
|----|---------|------------|----------------------|
| **X1 – Runner Warden** | Sandbox-master | Executa jobs blindados, devolve Receipts. | `runner` + evento `exec.finish`. |
| **X2 – Release Butler** | GitHub Action | Compila, assina com Sigstore, solta SBOM. | Release assets para 4 plataformas. |
| **X3 – Chaos Sprite** | Cron-gremlin | Injeta ZIP corrupto pra testar anticorpos. | Alerta #war-room toda quarta 03 h. |

---

## 📅 Sprints & milestones (12 semanas)

| Sprint | Marco | Quem lidera |
|--------|-------|-------------|
| 0 | Purga repo + CI verde | R1 |
| 1 | `ubl-kernel` determinístico | R1 |
| 2 | Ledger append-only | R2 |
| 3 | Membrana p95 ≤ 1 ms | R3 |
| 4 | Wallet + CLI end-to-end | S2 + D1 |
| 5 | Policy WASM + Runner | S1 + X1 |
| 6 | Portal premium GA | D2 |

*Cada sprint termina com algo que **qualquer pessoa** consegue rodar e ver funcionando.*  

---

## 📢 Comunicação

* **Canal oficial**: `#ubl-war-room` (Matrix/Slack).  
* **Daily async**: use thread “/standup” antes das 10:00.  
* **Weekly demo**: sexta 15:00 UTC, 15 min de show-and-tell.  

**SLA de respostas**  
• Bloker? 1 h. • Pergunta? 4 h. • RFC? 48 h.

---

## 🚨 Linhas Vermelhas

1. UPDATE/DELETE no Ledger → PagerDuty SEV-1.  
2. Qualquer “force=true” em produção = commit revertido + post-mortem.  
3. PR sem review nunca entra — nem Hotfix.  

---

## 🏁 Como saber que vencemos?

* Release **v1.0.0** assinado ➜ `curl | sh | ubl doctor` = Green.  
* Auditor externo reproduz 100 % das decisões off-line.  
* Bench p95 `/verify` < 0.8 ms em MacBook M2.  
* Canal #general posta “🎉 UBL 2 ∞ shipped” — e ninguém pergunta “pra que serve?”.  

> **Vamos entalhar confiança no Ledger — e deixar o resto do mundo com inveja.** 🚀
