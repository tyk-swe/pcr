use crate::engine::request::TransmissionRequest;
pub use crate::network::io::sender::{
    validate_transmission_policy, SendControlError, TransmissionPolicy,
};

pub fn validate_unbounded_request_policy(
    request: &TransmissionRequest,
    policy: TransmissionPolicy,
) -> Result<(), SendControlError> {
    if matches!(request.count, Some(0)) {
        return Err(SendControlError::CountMustBePositive);
    }

    if request.loop_forever.unwrap_or(false)
        && request.count.is_none()
        && !policy.allow_unbounded_sends
    {
        return Err(SendControlError::LoopRequiresAllowUnbounded);
    }

    if request.flood.unwrap_or(false) && request.count.is_none() && !policy.allow_unbounded_sends {
        return Err(SendControlError::FloodRequiresCount);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_policy_rejects_unbounded_flood_without_opt_in() {
        let request = TransmissionRequest {
            flood: Some(true),
            count: None,
            ..Default::default()
        };

        assert_eq!(
            validate_unbounded_request_policy(&request, TransmissionPolicy::default()),
            Err(SendControlError::FloodRequiresCount)
        );
    }

    #[test]
    fn request_policy_allows_flood_with_count_for_later_validation() {
        let request = TransmissionRequest {
            flood: Some(true),
            count: Some(1),
            ..Default::default()
        };

        assert_eq!(
            validate_unbounded_request_policy(&request, TransmissionPolicy::default()),
            Ok(())
        );
    }

    #[test]
    fn request_policy_rejects_zero_count() {
        let request = TransmissionRequest {
            count: Some(0),
            ..Default::default()
        };

        assert_eq!(
            validate_unbounded_request_policy(&request, TransmissionPolicy::default()),
            Err(SendControlError::CountMustBePositive)
        );
    }

    #[test]
    fn request_policy_leaves_loop_with_count_to_spec_validation() {
        let request = TransmissionRequest {
            loop_forever: Some(true),
            count: Some(1),
            ..Default::default()
        };

        assert_eq!(
            validate_unbounded_request_policy(&request, TransmissionPolicy::default()),
            Ok(())
        );
    }
}
