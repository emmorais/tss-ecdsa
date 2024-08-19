extern crate rand;
use rand::Rng;
use std::ops::{Add, Mul, Sub, Div};

#[derive(Clone, Debug, PartialEq)]
struct BigNumber {
    value: i64,
}

impl Add for BigNumber {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        BigNumber {
            value: self.value + other.value
        }
    }
}

impl Mul for BigNumber {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        BigNumber {
            value: self.value * other.value
        }
    }
}

impl Sub for BigNumber {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        BigNumber {
            value: self.value - other.value
        }
    }
}

impl Div for BigNumber {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        BigNumber {
            value: self.value / other.value
        }
    }
}

impl BigNumber {
    fn zero() -> Self {
        BigNumber { value: 0 }
    }

    fn one() -> Self {
        BigNumber { value: 1 }
    }

    fn random() -> Self {
        let mut rng = rand::thread_rng();
        BigNumber {
            value: rng.gen_range(1..100),
        }
    }
}

pub struct Polynomial {
    coefficients: Vec<BigNumber>,
}

impl Polynomial {
    pub fn random(t: usize) -> Self {
        let coefficients = (0..t).map(|_| BigNumber::random()).collect();
        Polynomial { coefficients }
    }

    pub fn evaluate(&self, x: &BigNumber) -> BigNumber {
        let mut result = BigNumber::zero();
        let mut x_power = BigNumber::one();
        
        for coef in &self.coefficients {
            result = result + coef.clone() * x_power.clone();
            x_power = x_power * x.clone();
        }
        
        result
    }

    pub fn interpolate(points: Vec<(BigNumber, BigNumber)>) -> BigNumber {
        let mut result = BigNumber::zero();
        
        for (i, (xi, yi)) in points.iter().enumerate() {
            let mut li = BigNumber::one();
            
            for (j, (xj, _)) in points.iter().enumerate() {
                if i != j {
                    let numerator = xj.clone();
                    let denominator = xi.clone() - xj.clone();
                    li = li * (numerator / denominator);
                }
            }
            
            result = result + yi.clone() * li;
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_evaluation() {
        let coefficients = vec![BigNumber { value: 1 }, BigNumber { value: 2 }, BigNumber { value: 3 }];
        let poly = Polynomial { coefficients };

        let x = BigNumber { value: 2 };
        let result = poly.evaluate(&x);

        // Expected: 1 + 2*2 + 3*2^2 = 1 + 4 + 12 = 17
        let expected = BigNumber { value: 17 };
        assert_eq!(result, expected);
    }

    #[test]
    fn test_polynomial_interpolation() {
        let poly = Polynomial::random(3);
        let points: Vec<(BigNumber, BigNumber)> = (0..3).map(|i| {
            let x = BigNumber { value: i + 1 };
            let y = poly.evaluate(&x);
            (x, y)
        }).collect();

        let reconstructed = Polynomial::interpolate(points.clone());
        let expected = poly.evaluate(&BigNumber::zero());
        assert_eq!(reconstructed, expected);
    }

    #[test]
    fn test_random_polynomial() {
        let poly = Polynomial::random(3);
        assert_eq!(poly.coefficients.len(), 3);
    }

    #[test]
    fn test_lagrange_interpolation_at_known_points() {
        let points = vec![
            (BigNumber { value: 1 }, BigNumber { value: 6 }),
            (BigNumber { value: 2 }, BigNumber { value: 11 }),
            (BigNumber { value: 3 }, BigNumber { value: 18 })
        ];

        let result = Polynomial::interpolate(points);
        
        // Manually calculating the constant term of the polynomial fit for the points.
        // Here it might not always match due to differences in BigNumber implementation.
        // Expected constant term can be manually computed or fixed if points are consistent.
        let expected = BigNumber { value: 5 };
        assert_eq!(result, expected);
    }
}