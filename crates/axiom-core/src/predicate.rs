use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Predicate {
    Attests = 0,
    Authors = 1,
    DerivedFrom = 2,
    Supersedes = 3,
    Revokes = 4,
    Endorses = 5,
    Appends = 6,
    CompliesWith = 7,
    Recovers = 8,
}

pub const CORE_PREDICATES: &[Predicate] = &[
    Predicate::Attests,
    Predicate::Authors,
    Predicate::DerivedFrom,
    Predicate::Supersedes,
    Predicate::Revokes,
    Predicate::Endorses,
    Predicate::Appends,
    Predicate::CompliesWith,
    Predicate::Recovers,
];

impl Predicate {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Predicate::Attests),
            1 => Ok(Predicate::Authors),
            2 => Ok(Predicate::DerivedFrom),
            3 => Ok(Predicate::Supersedes),
            4 => Ok(Predicate::Revokes),
            5 => Ok(Predicate::Endorses),
            6 => Ok(Predicate::Appends),
            7 => Ok(Predicate::CompliesWith),
            8 => Ok(Predicate::Recovers),
            _ => Err(Error::InvalidField("predicate")),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn name(&self) -> &'static str {
        match self {
            Predicate::Attests => "ATTESTS",
            Predicate::Authors => "AUTHORS",
            Predicate::DerivedFrom => "DERIVED_FROM",
            Predicate::Supersedes => "SUPERSEDES",
            Predicate::Revokes => "REVOKES",
            Predicate::Endorses => "ENDORSES",
            Predicate::Appends => "APPENDS",
            Predicate::CompliesWith => "COMPLIES_WITH",
            Predicate::Recovers => "RECOVERS",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Predicate::Attests => "General claim of truth regarding the subject",
            Predicate::Authors => "Issuer created the subject Artifact",
            Predicate::DerivedFrom => "Subject Artifact was transformed from the Object Artifact",
            Predicate::Supersedes => "This Statement replaces the Object Statement",
            Predicate::Revokes => "This Statement invalidates the Object Statement or Artifact",
            Predicate::Endorses => "Countersignature or multi-party approval",
            Predicate::Appends => "Streaming chunk linkage (Subject is Chunk N, Object is Chunk N-1)",
            Predicate::CompliesWith => "Subject Artifact satisfies the policy defined in Object Artifact",
            Predicate::Recovers => "Guardian authorises replacement of a lost key",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_predicates_round_trip() {
        for p in CORE_PREDICATES {
            let v = p.to_u8();
            let back = Predicate::from_u8(v).unwrap();
            assert_eq!(*p, back);
        }
    }

    #[test]
    fn test_predicate_names() {
        assert_eq!(Predicate::Attests.name(), "ATTESTS");
        assert_eq!(Predicate::Revokes.name(), "REVOKES");
    }

    #[test]
    fn test_invalid_predicate() {
        assert!(Predicate::from_u8(255).is_err());
    }
}
