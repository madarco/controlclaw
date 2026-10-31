//! Typed questions and answers, as AI SDK v7 `experimental_evaluate` sends and checks them
//! (`validateEvaluationInput`, `validateEvaluationAnswers` in `ai/dist/index.js`).

use serde::de::Error as _;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::LlmError;

/// AI SDK's tolerance for sums and means.
const TOLERANCE: f64 = 1e-6;

/// One question. Field order on the wire is `type, instructions, criteria`, as `ai/questions.ts`
/// writes them.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Question {
    /// `criteria`: option id → description (or null), in order.
    Choice {
        instructions: Value,
        criteria: Map<String, Value>,
    },
    /// `criteria`: ordered levels, at least two; the answer is a score in `[0, len - 1]`.
    Score { instructions: Value, criteria: Vec<Value> },
    /// Optional `criteria` describing `true` and `false`; the answer is P(true).
    Boolean {
        instructions: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        criteria: Option<Map<String, Value>>,
    },
}

impl Question {
    fn kind(&self) -> &'static str {
        match self {
            Question::Choice { .. } => "choice",
            Question::Score { .. } => "score",
            Question::Boolean { .. } => "boolean",
        }
    }
}

/// The question map, in the order it was built (a JS object keeps insertion order).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Questions(pub Vec<(String, Question)>);

impl Questions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, id: &str, q: Question) -> Self {
        self.0.push((id.to_string(), q));
        self
    }

    pub fn get(&self, id: &str) -> Option<&Question> {
        self.0.iter().find(|(k, _)| k == id).map(|(_, q)| q)
    }
}

impl Serialize for Questions {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Answer {
    Choice {
        choice: String,
        #[serde(default)]
        probabilities: Option<Map<String, Value>>,
    },
    Score {
        score: f64,
        #[serde(default)]
        probabilities: Option<Map<String, Value>>,
    },
    Boolean {
        probability: f64,
    },
}

impl Answer {
    fn kind(&self) -> &'static str {
        match self {
            Answer::Choice { .. } => "choice",
            Answer::Score { .. } => "score",
            Answer::Boolean { .. } => "boolean",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rounding {
    #[serde(default)]
    pub probability_decimals: Option<f64>,
    #[serde(default)]
    pub score_decimals: Option<f64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    #[serde(default)]
    pub input_tokens: Option<u64>,
    #[serde(default)]
    pub output_tokens: Option<u64>,
}

/// The Gateway's answer (`gatewayEvaluationResponseSchema`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evaluation {
    #[serde(deserialize_with = "ordered_answers")]
    pub answers: Vec<(String, Answer)>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub rounding: Option<Rounding>,
    #[serde(default)]
    pub usage: Option<Usage>,
    #[serde(default)]
    pub warnings: Vec<Value>,
    #[serde(default)]
    pub provider_metadata: Option<Value>,
}

impl Evaluation {
    pub fn answer(&self, id: &str) -> Option<&Answer> {
        self.answers.iter().find(|(k, _)| k == id).map(|(_, a)| a)
    }
}

fn ordered_answers<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<(String, Answer)>, D::Error> {
    let m = Map::<String, Value>::deserialize(d)?;
    m.into_iter()
        .map(|(k, v)| Answer::deserialize(v).map(|a| (k, a)).map_err(D::Error::custom))
        .collect()
}

/// A string, object or array (`isInput` in the SDK).
fn is_input(v: &Value) -> bool {
    matches!(v, Value::String(_) | Value::Object(_) | Value::Array(_))
}

fn invalid_input(param: &str, message: &str) -> LlmError {
    LlmError::InvalidInput(format!("{param}: {message}"))
}

/// `validateEvaluationInput`.
pub fn validate_input(state: &Value, questions: &Questions) -> Result<(), LlmError> {
    if !is_input(state) {
        return Err(invalid_input(
            "state",
            "must be a JSON-compatible string, object, or array",
        ));
    }
    if questions.0.is_empty() {
        return Err(invalid_input("questions", "must be a nonempty question map"));
    }
    for (id, q) in &questions.0 {
        let param = format!("questions.{id}");
        let (instructions, criteria): (&Value, Vec<&Value>) = match q {
            Question::Choice { instructions, criteria } => {
                if criteria.is_empty() {
                    return Err(invalid_input(&param, "choice criteria must be a nonempty option map"));
                }
                (instructions, criteria.values().collect())
            }
            Question::Score { instructions, criteria } => {
                if criteria.len() < 2 {
                    return Err(invalid_input(
                        &param,
                        "score criteria must contain at least two ordered levels",
                    ));
                }
                (instructions, criteria.iter().collect())
            }
            Question::Boolean { instructions, criteria } => {
                if let Some(c) = criteria
                    && c.keys().any(|k| k != "true" && k != "false")
                {
                    return Err(invalid_input(
                        &param,
                        "boolean criteria may only describe true and false",
                    ));
                }
                (instructions, criteria.iter().flat_map(|c| c.values()).collect())
            }
        };
        if !is_input(instructions) {
            return Err(invalid_input(
                &param,
                "instructions must be a JSON-compatible string, object, or array",
            ));
        }
        if criteria.iter().any(|v| !v.is_null() && !is_input(v)) {
            return Err(invalid_input(
                &param,
                "criteria descriptions must be JSON-compatible strings, objects, arrays, or null",
            ));
        }
    }
    Ok(())
}

fn invalid_answer(message: String) -> LlmError {
    LlmError::InvalidAnswer(message)
}

fn rounding_error(decimals: Option<f64>) -> Result<f64, LlmError> {
    let Some(d) = decimals else { return Ok(0.0) };
    if d.fract() != 0.0 || !(0.0..=15.0).contains(&d) {
        return Err(invalid_answer(
            "Evaluation rounding decimals must be integers between 0 and 15.".into(),
        ));
    }
    Ok(0.5 * 10f64.powi(-(d as i32)))
}

fn is_probability(v: &Value) -> bool {
    v.as_f64().is_some_and(|p| p.is_finite() && (0.0..=1.0).contains(&p))
}

fn validate_distribution(p: &Map<String, Value>, keys: &[String], id: &str, err: f64) -> Result<(), LlmError> {
    let exact = p.len() == keys.len() && keys.iter().all(|k| p.contains_key(k));
    if !exact || !p.values().all(is_probability) {
        return Err(invalid_answer(format!(
            "Question \"{id}\" must have a complete distribution of finite probabilities in [0, 1]."
        )));
    }
    let sum: f64 = p.values().filter_map(Value::as_f64).sum();
    if (sum - 1.0).abs() > TOLERANCE + keys.len() as f64 * err {
        return Err(invalid_answer(format!(
            "Question \"{id}\" probabilities must sum to 1 within the declared rounding precision."
        )));
    }
    Ok(())
}

/// `validateEvaluationAnswers`: one answer of the right type for every question, and nothing else.
pub fn validate_answers(
    questions: &Questions,
    answers: &[(String, Answer)],
    rounding: Option<Rounding>,
) -> Result<(), LlmError> {
    let r = rounding.unwrap_or_default();
    let p_err = rounding_error(r.probability_decimals)?;
    let s_err = rounding_error(r.score_decimals)?;
    let exact =
        answers.len() == questions.0.len() && questions.0.iter().all(|(k, _)| answers.iter().any(|(a, _)| a == k));
    if !exact {
        return Err(invalid_answer(
            "Evaluation must return exactly one answer for every question.".into(),
        ));
    }
    for (id, q) in &questions.0 {
        let Some((_, a)) = answers.iter().find(|(k, _)| k == id) else {
            continue;
        };
        if a.kind() != q.kind() {
            return Err(invalid_answer(format!(
                "Question \"{id}\" returned an answer with the wrong type."
            )));
        }
        match (q, a) {
            (Question::Choice { criteria, .. }, Answer::Choice { choice, probabilities }) => {
                if !criteria.contains_key(choice) {
                    return Err(invalid_answer(format!("Question \"{id}\" selected an unknown option.")));
                }
                if let Some(p) = probabilities {
                    let keys: Vec<String> = criteria.keys().cloned().collect();
                    validate_distribution(p, &keys, id, p_err)?;
                    let selected = p.get(choice).and_then(Value::as_f64).unwrap_or(0.0);
                    if p.values().filter_map(Value::as_f64).any(|x| x > selected + TOLERANCE) {
                        return Err(invalid_answer(format!(
                            "Question \"{id}\" did not select a highest-probability option."
                        )));
                    }
                }
            }
            (Question::Score { criteria, .. }, Answer::Score { score, probabilities }) => {
                let top = criteria.len() as f64 - 1.0;
                if !score.is_finite() || *score < 0.0 || *score > top {
                    return Err(invalid_answer(format!(
                        "Question \"{id}\" score must be in [0, {}].",
                        criteria.len() - 1
                    )));
                }
                if let Some(p) = probabilities {
                    let keys: Vec<String> = (0..criteria.len()).map(|i| i.to_string()).collect();
                    validate_distribution(p, &keys, id, p_err)?;
                    let mean: f64 = p
                        .iter()
                        .map(|(k, v)| k.parse::<f64>().unwrap_or(0.0) * v.as_f64().unwrap_or(0.0))
                        .sum();
                    let mean_err: f64 = (0..criteria.len()).map(|i| i as f64 * p_err).sum();
                    if (mean - score).abs() > TOLERANCE + mean_err + s_err {
                        return Err(invalid_answer(format!(
                            "Question \"{id}\" score must equal the probability-weighted mean within the declared rounding precision."
                        )));
                    }
                }
            }
            (Question::Boolean { .. }, Answer::Boolean { probability })
                if !(probability.is_finite() && (0.0..=1.0).contains(probability)) =>
            {
                return Err(invalid_answer(format!(
                    "Question \"{id}\" must return P(true) as a finite probability in [0, 1]."
                )));
            }
            _ => {}
        }
    }
    Ok(())
}
