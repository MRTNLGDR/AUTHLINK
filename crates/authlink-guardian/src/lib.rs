use authlink_contracts::{GuardianDecision, GuardianSignals, RiskLevel};

pub fn evaluate(signals: &GuardianSignals) -> GuardianDecision {
    let positive = u16::from(signals.device_integrity_penalty)
        + u16::from(signals.network_penalty)
        + u16::from(signals.credential_exposure_penalty)
        + u16::from(signals.session_context_penalty)
        + u16::from(signals.anomaly_penalty);
    let raw = 10_i16 + positive as i16 - i16::from(signals.strong_auth_credit);
    let score = raw.clamp(0, 100) as u8;

    let (level, action, requires_step_up) = match score {
        0..=29 => (RiskLevel::Low, "allow", false),
        30..=54 => (RiskLevel::Medium, "notify", false),
        55..=79 => (RiskLevel::High, "step-up", true),
        _ => (RiskLevel::Critical, "block-and-recover", true),
    };

    let mut reasons = Vec::new();
    if signals.device_integrity_penalty > 0 {
        reasons.push("integridade do dispositivo".into());
    }
    if signals.network_penalty > 0 {
        reasons.push("postura de rede".into());
    }
    if signals.credential_exposure_penalty > 0 {
        reasons.push("exposição de credencial".into());
    }
    if signals.session_context_penalty > 0 {
        reasons.push("contexto de sessão".into());
    }
    if signals.anomaly_penalty > 0 {
        reasons.push("anomalia comportamental".into());
    }
    if signals.strong_auth_credit > 0 {
        reasons.push("crédito por autenticação forte".into());
    }
    if reasons.is_empty() {
        reasons.push("nenhum sinal de risco relevante".into());
    }

    GuardianDecision {
        score,
        level,
        action: action.into(),
        reasons,
        requires_step_up,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_auth_reduces_risk() {
        let decision = evaluate(&GuardianSignals {
            strong_auth_credit: 10,
            ..GuardianSignals::default()
        });
        assert_eq!(decision.score, 0);
        assert_eq!(decision.level, RiskLevel::Low);
        assert!(!decision.requires_step_up);
    }

    #[test]
    fn high_risk_requires_step_up() {
        let decision = evaluate(&GuardianSignals {
            device_integrity_penalty: 25,
            credential_exposure_penalty: 25,
            anomaly_penalty: 15,
            ..GuardianSignals::default()
        });
        assert_eq!(decision.level, RiskLevel::High);
        assert!(decision.requires_step_up);
        assert_eq!(decision.action, "step-up");
    }

    #[test]
    fn critical_risk_blocks() {
        let decision = evaluate(&GuardianSignals {
            device_integrity_penalty: 35,
            network_penalty: 20,
            credential_exposure_penalty: 30,
            anomaly_penalty: 20,
            ..GuardianSignals::default()
        });
        assert_eq!(decision.score, 100);
        assert_eq!(decision.level, RiskLevel::Critical);
        assert_eq!(decision.action, "block-and-recover");
    }
}
