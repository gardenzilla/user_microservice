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

use crate::password::*;
use crate::prelude::ServiceError::*;
use crate::prelude::*;
use chrono::prelude::*;
use packman::*;
use serde::{Deserialize, Serialize};

// Min ID length
const ID_MIN_CHARS: usize = 4;
// Max ID lenght
const ID_MAX_CHARS: usize = 20;
// Min email length
const EMAIL_MIN_CHARS: usize = 3;
// Max email length
const EMAIL_MAX_CHARS: usize = 50;
// Min name length
const NAME_MIN_CHARS: usize = 2;
// Max name length
const NAME_MAX_CHARS: usize = 40;

// English characters, numbers and _
const ALLOWED_USERNAME_CHARACTERS: &'static [char] = &[
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
  't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_',
];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
  // UserId; constant
  // cannot change in future
  pub uid: u32,
  // Username like UID but String; constant
  // cannot change in future
  pub username: String,
  // User name
  pub name: String,
  // User email
  pub email: String,
  // User phone
  pub phone: String,
  // User stored password hash
  pub password_hash: String,
  // Created by UID
  pub created_by: u32,
  // Created at
  pub created_at: DateTime<Utc>,
}

impl Default for User {
  fn default() -> Self {
    Self {
      uid: 0,
      username: String::default(),
      name: String::default(),
      email: String::default(),
      phone: String::default(),
      password_hash: String::default(),
      created_by: 0,
      created_at: Utc::now(),
    }
  }
}

impl TryFrom for User {
  type TryFrom = User;
}

impl User {
  pub fn new(
    uid: u32,
    username: String,
    name: String,
    email: String,
    phone: String,
    created_by: u32,
  ) -> ServiceResult<Self> {
    // Clean username
    let username = username.trim().to_lowercase();
    // Clean email address
    let email = email.trim().to_lowercase();
    // Max email length
    // Validate User ID length
    if username.len() > ID_MAX_CHARS || username.len() < ID_MIN_CHARS {
      return Err(BadRequest(format!(
        "A felhasználói azonosítónak minimum {} és maximum {} karakternek kell lennie",
        ID_MIN_CHARS, ID_MAX_CHARS
      )));
    }
    // Validate User ID characters
    if username
      .chars()
      .any(|c| !ALLOWED_USERNAME_CHARACTERS.contains(&c))
    {
      return Err(BadRequest(format!(
        "Rossz formátum. Engedélyezett karakterek: {}",
        ALLOWED_USERNAME_CHARACTERS.into_iter().collect::<String>()
      )));
    };
    // Validate Email length
    if email.len() > EMAIL_MAX_CHARS || email.len() < EMAIL_MIN_CHARS {
      return Err(BadRequest(format!(
        "Az email cím hosszúsága min {} max {}",
        EMAIL_MIN_CHARS, EMAIL_MAX_CHARS
      )));
    }
    // Validate Email content
    if !email.contains('@') || !email.contains('.') {
      return Err(BadRequest(
        "Nem megfelelő email cím. Legalább @ jelet és pontot kell tartalmaznia".to_string(),
      ));
    }
    // Validate Name length
    if name.len() > NAME_MAX_CHARS || name.len() < NAME_MIN_CHARS {
      return Err(BadRequest(format!(
        "A név hosszúságe legalább {} max {} karakter",
        NAME_MIN_CHARS, NAME_MAX_CHARS
      )));
    }
    Ok(User {
      uid,
      username: username,
      name,
      email: email,
      phone,
      password_hash: "".into(),
      created_by,
      created_at: Utc::now(),
    })
  }
}

impl User {
  // Try to update user data
  pub fn update(&mut self, name: String, email: String, phone: String) -> ServiceResult<&User> {
    if name.len() < 5 {
      return Err(BadRequest(
        "A user neve legalább 5 karakter kell, hogy legyen".into(),
      ));
    }
    if !email.contains('@') || !email.contains('.') {
      return Err(BadRequest(
        "Rossz email formátum. Tartalmazzon @ jelet és pontot".into(),
      ));
    }
    self.name = name;
    self.email = email;
    self.phone = phone;
    Ok(self)
  }
  // Try to set new password
  pub fn set_password(&mut self, password: String) -> ServiceResult<()> {
    validate_password(&password)?;
    self.password_hash = hash_password(&password)?;
    Ok(())
  }
  // Try to reset password
  pub fn reset_password(&mut self) -> ServiceResult<String> {
    let new_password = generate_random_password(None)?;
    self.password_hash = hash_password(&new_password)?;
    Ok(new_password)
  }
}

impl VecPackMember for User {
  type Out = u32;
  fn get_id(&self) -> &Self::Out {
    &self.uid
  }
}
