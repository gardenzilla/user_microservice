// Copyright (C) 2020 Peter Mezei
//
// This file is part of Gardenzilla.
//
// Gardenzilla is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
//
// Gardenzilla is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Gardenzilla.  If not, see <http://www.gnu.org/licenses/>.

use crate::prelude::ServiceError::*;
use crate::prelude::ServiceResult;
use bcrypt::{hash, verify};
use rand::Rng;

/// # Hash password
/// Get a password string pointer, returns a Result<String, String>
/// ```rust
/// use core_lib::user::password::hash_password;
/// let hash = hash_password("purple dog").unwrap();
/// ```
pub fn hash_password(password: &str) -> ServiceResult<String> {
  //let hashed = hash("hunter2", DEFAULT_COST)?;
  //let valid = verify("hunter2", &hashed)?;
  match hash(password, 6) {
    Ok(hash) => Ok(hash),
    Err(_) => Err(InternalError(
      "ServiceError while creating hash from password".into(),
    )),
  }
}

/// # Verify password from hash
/// Gets a password and hash pointer and returns a Result<bool, String>
/// True if verify succeed, false otherwise.
/// ```rust
/// use core_lib::user::password::{verify_password_from_hash, hash_password};
/// let hash = hash_password("purple_dog").unwrap();
/// let result: bool = verify_password_from_hash(
///                         "purple_dog",
///                         &hash).unwrap();
/// ```
pub fn verify_password_from_hash<'a>(password: &'a str, hash: &'a str) -> ServiceResult<bool> {
  match verify(password, &hash) {
    Ok(result) => Ok(result),
    Err(_) => Err(InternalError(
      "ServiceError while trying verify password from hash".into(),
    )),
  }
}

/// # Generate random password
/// Set a length or leave it None.
/// Returns a random password aA-zZ, 0-9
/// ```rust
/// use core_lib::user::password::generate_random_password;
/// let password = generate_random_password(None).unwrap();
/// ```
pub fn generate_random_password(length: Option<u32>) -> ServiceResult<String> {
  // Create random rng
  let mut rng = rand::thread_rng();
  // Chars to generate random password
  let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
  // Generate random password
  let password = (0..length.unwrap_or(12))
    .into_iter()
    .map(|_| chars[rng.gen_range(0..chars.len())])
    .collect::<String>();
  // Return password
  Ok(password)
}

/// # Validate password
/// Validate password to check it is strong enough.
/// What we check is *password length*, *uppercase character frequency*,
/// *lowercase character frequency* and *number frequency*.
/// ```rust
/// use core_lib::user::password::validate_password;
/// assert_eq!(validate_password("DEmoPassWord1234789").is_ok(), true);
/// ```
pub fn validate_password(password: &str) -> ServiceResult<()> {
  let min_password_len = 3;
  let min_character_lowercase = 2;
  let min_character_uppercase = 1;
  let min_numeric_character = 1;
  let mut character_lowercase: u32 = 0;
  let mut character_uppercase: u32 = 0;
  let mut character_numeric: u32 = 0;
  for ch in password.chars() {
    // count numeric characters
    if ch.is_numeric() {
      character_numeric += 1;
    }
    // count lowercase characters
    if ch.is_lowercase() {
      character_lowercase += 1;
    }
    // count uppercase characters
    if ch.is_uppercase() {
      character_uppercase += 1;
    }
  }
  if password.len() >= min_password_len
    && character_numeric >= min_numeric_character
    && character_lowercase >= min_character_lowercase
    && character_uppercase >= min_character_uppercase
  {
    Ok(())
  } else {
    Err(BadRequest(format!(
      "A jelszó hossza min {} karakter legyen, és tartalmazzon legalább {}
            kisbetűt, valamint legalább {} db nagybetűt, valamint legalább {} számot",
      min_password_len, min_character_lowercase, min_character_uppercase, min_numeric_character
    )))
  }
}

// Tests
#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_hash_password() {
    let password = "purple_dog";
    let hash = hash_password(password).unwrap();
    assert_ne!(hash.len(), password.len());
  }

  #[test]
  fn test_verify_password() {
    let password = "purple_dog";
    let hash = hash_password(password).unwrap();
    assert_eq!(verify_password_from_hash(password, &hash).unwrap(), true);
    assert_eq!(
      verify_password_from_hash("wrong_password", &hash).unwrap(),
      false
    );
  }

  #[test]
  fn test_random_generator() {
    assert_eq!(generate_random_password(None).unwrap().len(), 12); // This should be true
    assert_eq!(generate_random_password(Some(5)).unwrap().len(), 5); // This should be true
    assert_eq!(generate_random_password(Some(0)).unwrap().len(), 0); // This should be true
    assert_eq!(generate_random_password(Some(7)).unwrap().len(), 7); // This should be true
  }
  #[test]
  fn test_validate_password() {
    assert_eq!(validate_password("pass").is_ok(), false); // should be err
    assert_eq!(validate_password("PAss1").is_ok(), true); // should be err
    assert_eq!(validate_password("password").is_ok(), false); // should be err
    assert_eq!(validate_password("Password").is_ok(), false); // should be err
    assert_eq!(validate_password("PASsword").is_ok(), false); // should be err
    assert_eq!(validate_password("Password12").is_ok(), true); // should be err
    assert_eq!(validate_password("PAssword12").is_ok(), true); // should be ok
  }
}
