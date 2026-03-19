/// ENet uses 32-bit millisecond timestamps that wrap at `u32::MAX`.
/// `TIME_OVERFLOW` (86,400,000 = 24 hours) is used as a comparison threshold by
/// `time_less`/`time_greater` to determine the forward direction of time: a
/// difference larger than `TIME_OVERFLOW` means the subtraction crossed the wrap
/// boundary, so the "lesser" timestamp is actually the one that appears numerically
/// larger.
const TIME_OVERFLOW: u32 = 86_400_000;

pub fn time_less(a: u32, b: u32) -> bool {
    a.wrapping_sub(b) >= TIME_OVERFLOW
}

pub fn time_greater(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) >= TIME_OVERFLOW
}

pub fn time_less_equal(a: u32, b: u32) -> bool {
    !time_greater(a, b)
}

pub fn time_greater_equal(a: u32, b: u32) -> bool {
    !time_less(a, b)
}

/// Directional elapsed time: returns `a - b` using wrapping arithmetic.
/// Callers must pass `(now, then)` so the result is the forward elapsed time.
/// This matches C ENet's `ENET_TIME_DIFFERENCE(a, b)` which is simply `a - b`.
pub fn time_difference(a: u32, b: u32) -> u32 {
    a.wrapping_sub(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_less() {
        assert!(time_less(1, 2));
        assert!(!time_less(2, 1));
        assert!(!time_less(1, 1));
    }

    #[test]
    fn test_time_greater() {
        assert!(time_greater(2, 1));
        assert!(!time_greater(1, 2));
        assert!(!time_greater(1, 1));
    }

    #[test]
    fn test_time_less_equal() {
        assert!(time_less_equal(1, 2));
        assert!(time_less_equal(1, 1));
        assert!(!time_less_equal(2, 1));
    }

    #[test]
    fn test_time_greater_equal() {
        assert!(time_greater_equal(2, 1));
        assert!(time_greater_equal(1, 1));
        assert!(!time_greater_equal(1, 2));
    }

    #[test]
    fn test_time_difference() {
        // Directional: time_difference(now, then) = now - then
        assert_eq!(time_difference(5, 3), 2);
        assert_eq!(time_difference(0, 0), 0);
        // Reversed order wraps around u32
        assert_eq!(time_difference(3, 5), u32::MAX - 1);
    }

    #[test]
    fn test_time_near_overflow() {
        // Time wrapping: 86_399_999 is just before overflow
        let a = TIME_OVERFLOW - 1;
        let b = 0;
        assert!(time_greater(a, b));
        assert!(time_less(b, a));
        assert_eq!(time_difference(a, b), a);
    }

    #[test]
    fn test_time_wrapping() {
        // ENet time wraps at u32::MAX, not at TIME_OVERFLOW.
        // TIME_OVERFLOW is just the threshold for direction detection.
        let b = u32::MAX - 99; // just before u32 overflow
        let a = 100; // just after u32 overflow
                     // a is 200ms "after" b in wrapped time
        assert!(time_greater(a, b));
        assert!(time_less(b, a));
        assert_eq!(time_difference(a, b), 200);
    }
}
