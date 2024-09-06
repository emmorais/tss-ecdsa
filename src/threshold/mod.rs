//! Auxiliary function for Lagrange interpolation

use k256::Scalar;

/// Compute the Lagrange coefficient evaluated at zero.
/// This is used to reconstruct the secret from the shares.
pub fn lagrange_coefficient_at_zero(my_point: &Scalar, other_points: &Vec<Scalar>) -> Scalar {
    let mut result = Scalar::ONE;
    for point in other_points {
        if point != my_point {
            let numerator = Scalar::ZERO - point;
            let denominator = my_point - point;
            let inv = denominator.invert().unwrap();
            result *= numerator * inv;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};
    use k256::elliptic_curve::Field;

    fn generate_polynomial<R: Rng>(t: usize, rng: &mut R) -> Vec<Scalar> {
        let mut coefficients = Vec::with_capacity(t);
        for _ in 0..t {
            coefficients.push(Scalar::random(&mut *rng));
        }
        coefficients
    }

    pub fn evaluate_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
        coefficients
            .iter()
            .rev()
            .fold(Scalar::ZERO, |acc, coef| acc * x + coef)
    }

    pub fn lagrange_coefficient(my_point: &Scalar, other_points: &Vec<Scalar>) -> Scalar {
        let mut result = Scalar::ONE;
        for point in other_points {
            if point != my_point {
                let denominator = my_point - point;
                let inv = denominator.invert().unwrap();
                result *= point * &inv;
            }
        }
        result
    }

    fn evaluate_at_points(coefficients: &[Scalar], points: &[Scalar]) -> Vec<Scalar> {
        points
            .iter()
            .map(|x| evaluate_polynomial(coefficients, x))
            .collect()
    }

    #[test]
    fn test_generate_and_evaluate_polynomial() {
        let mut rng = thread_rng();
        let t = 3;
        let coefficients = generate_polynomial(t, &mut rng);

        let x = Scalar::random(&mut rng);
        let value = evaluate_polynomial(&coefficients, &x);

        // Just to check if we got something
        // non-trivial
        assert!(!bool::from(value.is_zero()));
    }

    #[test]
    fn test_lagrange_coefficients() {
        let points: Vec<Scalar> = (1..=3).map(|i: u32| Scalar::from(i)).collect();
        // Next we represent the polynomial x^2 + x
        let evaluated_values = [
            points[0] * Scalar::from(2u32),
            points[1] * Scalar::from(3u32),
            points[2] * Scalar::from(4u32),
        ];

        let reconstructed_zero = evaluated_values
            .iter()
            .zip(&points)
            .map(|(value, point)| *value * lagrange_coefficient(point, &points))
            .fold(Scalar::ZERO, |acc, x| acc + x);

        // Check that reconstructed value
        // at X=0 is correct
        assert!(bool::from(reconstructed_zero.is_zero()));
    }

    #[test]
    fn test_evaluate_at_points() {
        let mut rng = thread_rng();
        let t = 3;
        let n = 5;
        let coefficients = generate_polynomial(t, &mut rng);

        let points: Vec<Scalar> = (1..=n).map(|i: u32| Scalar::from(i)).collect();
        let values = evaluate_at_points(&coefficients, &points);

        for (x, y) in points.iter().zip(values.iter()) {
            assert_eq!(evaluate_polynomial(&coefficients, x), *y);
        }
    }

    #[test]
    fn test_evaluate_points_at_zero() {
        let mut rng = thread_rng();
        let t: u32 = 3;
        let n: u32 = 7;
        let coefficients = generate_polynomial(t as usize, &mut rng);

        // test that reconstruction works as long as we have enough points
        for n in t..n {
            let points: Vec<Scalar> = (1..=n).map(|i: u32| Scalar::from(i)).collect();
            let values = evaluate_at_points(&coefficients, &points);

            let zero = Scalar::ZERO;
            let zero_value = evaluate_polynomial(&coefficients, &zero);

            let zero_value_reconstructed = values
                .iter()
                .zip(&points)
                .map(|(value, point)| *value * lagrange_coefficient_at_zero(point, &points))
                .fold(Scalar::ZERO, |acc, x| acc + x);

            assert_eq!(zero_value, zero_value_reconstructed);
        }
    }
}
