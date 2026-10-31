//! W4: replays the TS build's recorded answers (`rust/conformance/cases/w4/ai/recorded.json`,
//! written by `record.mts`) through this crate and reports how often the outcome agrees, per
//! provider: the same choice, the same score band (`severityOf`), the same side of 0.5 for a
//! boolean. Needs a live key, so it is ignored by default:
//!
//!   AI_GATEWAY_API_KEY=… cargo test -p cc-llm --test recorded_ai -- --ignored --nocapture

#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::Duration;

use cc_llm::{Answer, GatewayClient, Provider, Question, Questions, provider_options_for, structured};
use serde_json::{Map, Value};

const GATEWAY_V1: &str = "https://ai-gateway.vercel.sh/v1";

fn questions(raw: &Map<String, Value>) -> Questions {
    let mut q = Questions::new();
    for (id, v) in raw {
        let instructions = v["instructions"].clone();
        let question = match v["type"].as_str().unwrap() {
            "choice" => Question::Choice {
                instructions,
                criteria: v["criteria"].as_object().cloned().unwrap(),
            },
            "score" => Question::Score {
                instructions,
                criteria: v["criteria"].as_array().cloned().unwrap(),
            },
            _ => Question::Boolean {
                instructions,
                criteria: v.get("criteria").and_then(Value::as_object).cloned(),
            },
        };
        q = q.with(id, question);
    }
    q
}

/// The outcome a caller acts on.
fn outcome_of_recorded(a: &Value) -> String {
    match a["type"].as_str().unwrap() {
        "choice" => a["choice"].as_str().unwrap().to_string(),
        "score" => format!("band {}", a["score"].as_f64().unwrap().round()),
        _ => format!("{}", a["probability"].as_f64().unwrap() >= 0.5),
    }
}

fn outcome(a: &Answer) -> String {
    match a {
        Answer::Choice { choice, .. } => choice.clone(),
        Answer::Score { score, .. } => format!("band {}", score.round()),
        Answer::Boolean { probability } => format!("{}", *probability >= 0.5),
    }
}

#[tokio::test]
#[ignore = "calls real models; needs AI_GATEWAY_API_KEY"]
async fn recorded_answers_agree() {
    let key = std::env::var("AI_GATEWAY_API_KEY").expect("AI_GATEWAY_API_KEY");
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/cases/w4/ai/recorded.json"
    );
    let recorded: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let http = reqwest::Client::new();
    // provider/model → (questions asked, questions agreed, calls failed)
    let mut tally: BTreeMap<String, (u32, u32, u32)> = BTreeMap::new();
    for c in recorded["cases"].as_array().unwrap() {
        let Some(want) = c["answers"].as_object() else { continue };
        let provider = c["provider"].as_str().unwrap();
        let model = c["model"].as_str().unwrap();
        let q = questions(c["questions"].as_object().unwrap());
        let opts = provider_options_for(Provider::parse(provider).unwrap(), model);
        let got = match provider {
            "vercel_gateway" => {
                GatewayClient::with_client(http.clone(), &key)
                    .evaluate(model, &c["state"], &q, &opts, Duration::from_secs(60))
                    .await
            }
            p => {
                structured::evaluate(
                    &http,
                    Provider::parse(p).unwrap(),
                    &key,
                    model,
                    Some(GATEWAY_V1),
                    &c["state"],
                    &q,
                    &opts,
                    Duration::from_secs(60),
                )
                .await
            }
        };
        let t = tally.entry(format!("{provider} {model}")).or_default();
        match got {
            Ok(e) => {
                for (id, a) in want {
                    t.0 += 1;
                    let (w, g) = (outcome_of_recorded(a), e.answer(id).map(outcome).unwrap_or_default());
                    if w == g {
                        t.1 += 1;
                    } else {
                        println!(
                            "  differs: {model} {} {id}: ts {w}, rust {g}",
                            c["id"].as_str().unwrap()
                        );
                    }
                }
            }
            Err(e) => {
                t.2 += 1;
                println!("  failed: {model} {}: {e}", c["id"].as_str().unwrap());
            }
        }
    }
    println!("\nprovider model: agreed / questions (calls failed)");
    for (k, (n, ok, failed)) in &tally {
        println!(
            "{k}: {ok}/{n} ({:.0}%), {failed} failed",
            100.0 * f64::from(*ok) / f64::from((*n).max(1))
        );
    }
    assert!(tally.values().all(|(_, _, f)| *f == 0), "every call should answer");
}
