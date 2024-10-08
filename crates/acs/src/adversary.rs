pub type AttackTypeIndex = u64;

#[derive(Debug, Clone)]
pub enum AttackType {
    Honest = 0, // behave honestly
    Inflation = 1,  // create blocks without voting for leader blocks
    Crash = 2,  // don't create blocks
    Byzantine = 3,  // create equivocated blocks
}

impl AttackType {
    pub fn from_index(index: AttackTypeIndex) -> Option<Self> {
        match index {
            0 => Some(AttackType::Honest),
            1 => Some(AttackType::Inflation),
            2 => Some(AttackType::Crash),
            3 => Some(AttackType::Byzantine),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            AttackType::Honest => "Honest",
            AttackType::Inflation => "Inflation",
            AttackType::Crash => "Crash",
            AttackType::Byzantine => "Byzantine",
        }
    }
}