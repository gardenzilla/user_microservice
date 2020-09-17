use packman::*;
use prelude::*;
use protos::email::email_client::*;
use protos::email::*;
use protos::user::user_server::*;
use protos::user::*;
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use tokio::sync::{oneshot, Mutex};
use tonic::transport::Channel;
use tonic::{transport::Server, Request, Response, Status};

pub mod convert;
pub mod password;
pub mod prelude;
pub mod user;

pub struct UserService {
  next_id: Mutex<u32>,
  lookup_table: Mutex<HashMap<String, u32>>,
  users: Mutex<VecPack<user::User>>,
  email_client: Mutex<EmailClient<Channel>>,
}

impl UserService {
  fn init(
    users: VecPack<user::User>,         // User db
    email_client: EmailClient<Channel>, // Email service client
  ) -> UserService {
    // Define the next id
    // Iterate over the users
    // and fold till the biggest id
    let next_id: u32 = users.iter().fold(0u32, |prev_id, c| {
      let id = c.unpack().get_id();
      if *id > prev_id {
        // return the current id as
        // that bigger then the previous one
        *id
      } else {
        // return the previous id
        prev_id
      }
    }) + 1; // biggest found ID + 1 is the next ID

    // Lookup table to store
    // user aliases
    // Store user alias and user id
    //            =====          ==
    let mut lookup: HashMap<String, u32> = HashMap::new();

    // Build up lookup table
    // for aliases
    users
      .iter()
      .map(|c| {
        let c = c.unpack();
        (c.get_user_alias().to_string(), *c.get_id())
      })
      .for_each(|o| {
        let _ = lookup.insert(o.0, o.1);
      });

    UserService {
      next_id: Mutex::new(next_id),
      lookup_table: Mutex::new(lookup),
      users: Mutex::new(users),
      email_client: Mutex::new(email_client),
    }
  }

  async fn create_new_user(&self, u: CreateNewRequest) -> ServiceResult<UserObj> {
    if self.is_alias_available(&u.alias).await {
      return Err(ServiceError::already_exist(
        "A megadott felhasználói név már foglalt!",
      ));
    }
    let new_user = user::User::new(
      *self.next_id.lock().await,
      u.alias,
      u.name,
      u.email,
      u.phone,
      u.created_by,
    )?;
    let user_obj: UserObj = (&new_user).into();
    self.users.lock().await.insert(new_user)?;
    Ok(user_obj)
  }

  // Check wheter an alias is available
  // or already taken
  async fn is_alias_available(&self, alias: &str) -> bool {
    self.lookup_table.lock().await.get(alias).is_some()
  }
}

#[tonic::async_trait]
impl protos::user::user_server::User for UserService {
  type GetAllStream = tokio::sync::mpsc::Receiver<Result<UserObj, Status>>;
  async fn create_new(
    &self,
    request: Request<CreateNewRequest>,
  ) -> Result<Response<CreateNewResponse>, Status> {
    Ok(Response::new(CreateNewResponse {
      user: Some(self.create_new_user(request.into_inner()).await?),
    }))
  }
  async fn get_all(&self, _request: Request<()>) -> Result<Response<Self::GetAllStream>, Status> {
    let users = self
      .users
      .lock()
      .await
      .into_iter()
      .map(|i: &mut Pack<user::User>| i.unpack().into())
      .collect::<Vec<UserObj>>();

    let (mut tx, rx) = tokio::sync::mpsc::channel(4);

    for user in users {
      tx.send(Ok(user)).await.unwrap();
    }

    return Ok(Response::new(rx));
  }
  async fn get_by_id(
    &self,
    request: Request<GetByIdRequest>,
  ) -> Result<Response<GetByIdResponse>, Status> {
    let user: UserObj = self
      .users
      .lock()
      .await
      .find_id(&request.into_inner().userid)
      .map_err(|_| Status::not_found("User not found"))?
      .unpack()
      .into();
    let response = GetByIdResponse { user: Some(user) };
    return Ok(Response::new(response));
  }
  async fn update_by_id(
    &self,
    request: Request<UpdateByIdRequest>,
  ) -> Result<Response<UpdateByIdResponse>, Status> {
    let _user: UserObj = match request.into_inner().user {
      Some(u) => u,
      None => return Err(Status::internal("Request has an empty user object")),
    };
    let mut lock = self.users.lock().await;
    let user = match lock.find_id_mut(&_user.id) {
      Ok(u) => u,
      Err(err) => return Err(Status::not_found(format!("{}", err))),
    };
    let mut user_mut = user.as_mut();
    let mut _user_mut = user_mut.unpack();
    _user_mut.set_user_name(_user.name.to_string())?;
    _user_mut.set_user_email(_user.email.to_string())?;
    _user_mut.set_user_phone(_user.phone.to_string())?;

    let response = UpdateByIdResponse {
      user: Some(_user.into()),
    };
    return Ok(Response::new(response));
  }
  async fn is_user(
    &self,
    request: Request<IsUserRequest>,
  ) -> Result<Response<IsUserResponse>, Status> {
    let is_user = match self
      .users
      .lock()
      .await
      .find_id(&request.into_inner().userid)
    {
      Ok(_) => true,
      Err(_) => false,
    };
    let response = IsUserResponse {
      user_exist: is_user,
    };
    return Ok(Response::new(response));
  }
  async fn reset_password(
    &self,
    request: Request<ResetPasswordRequest>,
  ) -> Result<Response<ResetPasswordResponse>, Status> {
    let req = request.into_inner();

    for user in self.users.lock().await.as_vec_mut() {
      if user.unpack().get_user_email() == &req.email {
        let new_password = user.as_mut().reset_password()?;

        // Send email
        let mut email_service = self.email_client.lock().await;
        email_service.send_email(EmailRequest {
                    to: req.email,
                    subject: "Elfelejtett jelszó".into(),
                    body: format!("A Gardenzilla fiókodban töröltük a régi jelszavadat,\n és új jelszót állítottunk be.\n\n Az új jelszavad: {}", new_password),
                }).await?;

        return Ok(Response::new(ResetPasswordResponse {}));
      }
    }

    Err(Status::not_found("A megadott email cím nem található"))
  }
  async fn set_new_password(
    &self,
    request: Request<NewPasswordRequest>,
  ) -> Result<Response<NewPasswordResponse>, Status> {
    let req = request.into_inner();
    let mut lock = self.users.lock().await;
    let user = lock
      .find_id_mut(&req.userid)
      .map_err(|e| ServiceError::from(e))?;
    user.as_mut().unpack().set_password(req.new_password)?;
    let u = user.unpack();
    let mut email_service = self.email_client.lock().await;
    email_service
      .send_email(EmailRequest {
        to: u.get_user_email().into(),
        subject: "Új jelszó beállítva".into(),
        body: "Új jelszó lett beállítva a Gardenzilla fiókodban.".into(),
      })
      .await?;
    Ok(Response::new(NewPasswordResponse {}))
  }
  async fn validate_login(
    &self,
    request: Request<LoginRequest>,
  ) -> Result<Response<LoginResponse>, Status> {
    let req = request.into_inner();
    let userid = match self.lookup_table.lock().await.get(&req.username) {
      Some(userid) => *userid,
      None => {
        return Ok(Response::new(LoginResponse {
          is_valid: false,
          name: "".into(),
        }))
      }
    };
    match self.users.lock().await.find_id(&userid) {
      Ok(user) => {
        match password::verify_password_from_hash(&req.password, user.unpack().get_password_hash())
        {
          Ok(res) => {
            return Ok(Response::new(LoginResponse {
              is_valid: res,
              name: user.unpack().get_user_name().into(),
            }))
          }
          Err(_) => {
            return Ok(Response::new(LoginResponse {
              is_valid: false,
              name: "".into(),
            }))
          }
        }
      }
      Err(_) => {
        return Ok(Response::new(LoginResponse {
          is_valid: false,
          name: "".into(),
        }))
      }
    };
  }

  async fn lookup(
    &self,
    request: Request<LookupRequest>,
  ) -> Result<Response<LookupResponse>, Status> {
    let (id, name, alias) = match &self
      .users
      .lock()
      .await
      .find_id(&request.into_inner().user_id)
    {
      Ok(user) => {
        let u = user.unpack();
        (
          u.get_id().to_owned(),
          u.get_user_name().to_owned(),
          u.get_user_alias().to_owned(),
        )
      }
      Err(_) => {
        return Err(Status::not_found(
          "A megadott felhasználói ID nem található",
        ))
      }
    };
    Ok(Response::new(LookupResponse {
      uid: id,
      name: name,
      alias: alias,
    }))
  }

  async fn lookup_bulk(
    &self,
    request: Request<LookupBulkRequest>,
  ) -> Result<Response<LookupBulkResponse>, Status> {
    // Initial
    // result hashmap
    let mut res: Vec<LookupObj> = Vec::new();

    // User db
    let users = self.users.lock().await;

    // Iterate over all the users
    for uid in request.into_inner().user_ids {
      let found_user = match &users.find_id(&uid) {
        Ok(_user) => {
          let _u = _user.unpack();
          Some(LookupResult {
            name: _u.get_user_name().to_owned(),
            alias: _u.get_user_alias().to_owned(),
          })
        }
        Err(_) => None,
      };
      res.push(LookupObj {
        id: uid,
        user_obj: found_user,
      });
    }
    Ok(Response::new(LookupBulkResponse { users: res }))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let users: VecPack<user::User> = VecPack::try_load_or_init(PathBuf::from("data/users"))
    .expect("Error while loading users storage");

  let email_client = EmailClient::connect("http://[::1]:50053")
    .await
    .expect("Error while connecting to email service");

  let user_service = UserService::init(users, email_client);

  // If db is empty
  // create initial admin user
  let next_id = *user_service.next_id.lock().await;
  if next_id == 1 {
    use std::env;
    user_service
      .create_new_user(CreateNewRequest {
        alias: env::var("USER_INIT_ALIAS")?,
        name: env::var("USER_INIT_NAME")?,
        email: env::var("USER_INIT_EMAIL")?,
        phone: env::var("USER_INIT_PHONE")?,
        created_by: 1,
      })
      .await
      .expect("Error while creating the init admin user");
  }

  let addr = "[::1]:50051".parse().unwrap();

  // Create shutdown channel
  let (tx, rx) = oneshot::channel();

  // Spawn the server into a runtime
  tokio::task::spawn(async move {
    Server::builder()
      .add_service(UserServer::new(user_service))
      .serve_with_shutdown(addr, async {
        let _ = rx.await;
      })
      .await
      .unwrap()
  });

  tokio::signal::ctrl_c().await?;

  println!("SIGINT");

  // Send shutdown signal after SIGINT received
  let _ = tx.send(());

  Ok(())
}
