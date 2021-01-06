use gzlib::proto::email::{email_client::EmailClient, EmailRequest};
use gzlib::proto::user::user_server::*;
use gzlib::proto::user::*;
use packman::*;
use prelude::*;
use std::path::PathBuf;
use std::{env, error::Error};
use tokio::sync::{oneshot, Mutex};
use tonic::transport::Channel;
use tonic::{transport::Server, Request, Response, Status};

mod password;
mod prelude;
mod user;

struct UserService {
  users: Mutex<VecPack<user::User>>,
}

impl UserService {
  // Init UserService with the provided
  // db and service
  fn init(users: VecPack<user::User>, // User db
  ) -> UserService {
    UserService {
      users: Mutex::new(users),
    }
  }
  // Get next UID
  async fn next_uid(&self) -> u32 {
    let mut latest_id: u32 = 0;
    self.users.lock().await.iter().for_each(|user| {
      let uid: u32 = *user.unpack().get_id();
      if uid > latest_id {
        latest_id = uid;
      }
    });
    latest_id + 1
  }
  // Check if username available
  // username should be cleaned and in the form
  // as we send to to create new User object
  async fn is_username_ok(&self, username: &str) -> bool {
    !self
      .users
      .lock()
      .await
      .iter()
      .any(|u| u.unpack().username == username)
  }
  // Get stored user count
  async fn user_count(&self) -> usize {
    self.users.lock().await.len()
  }
  // Create new user
  async fn create_user(&self, r: NewUserObj) -> ServiceResult<UserObj> {
    // Get new UID
    let new_uid = self.next_uid().await;
    // Clean username
    let username = r.username.trim().to_lowercase();
    // Check if we can use this username
    if !self.is_username_ok(&username).await {
      return Err(ServiceError::already_exist(
        "A megadott felhasználói név már foglalt!",
      ));
    }
    // Create new user object
    let new_user = user::User::new(new_uid, username, r.name, r.email, r.phone, r.created_by)?;
    // Store new user
    self.users.lock().await.insert(new_user.clone())?;
    // Return new user as UserObj
    Ok(new_user.into())
  }
  // Get all users
  async fn get_all(&self) -> ServiceResult<Vec<UserObj>> {
    // Convert all users to Vec<UserObj>
    let res = self
      .users
      .lock()
      .await
      .iter()
      .map(|u| u.unpack().clone().into())
      .collect::<Vec<UserObj>>();
    // Return UserObj vector
    Ok(res)
  }
  // Get user by ID
  async fn get_by_id(&self, r: GetByIdRequest) -> ServiceResult<UserObj> {
    // Tries to find user
    let res = self.users.lock().await.find_id(&r.userid)?.unpack().clone();
    // Return it as UserObj
    Ok(res.into())
  }
  // Update by ID
  async fn update_by_id(&self, r: UserObj) -> ServiceResult<UserObj> {
    // Tries to find and update the User
    let res = self
      .users
      .lock()
      .await
      .find_id_mut(&r.uid)?
      .as_mut()
      .unpack()
      .update(r.name, r.email, r.phone)?
      .clone();
    // Returns it as UserObj
    Ok(res.into())
  }
  // Reset password
  async fn reset_password(&self, r: ResetPasswordRequest) -> ServiceResult<ResetPasswordResponse> {
    for user in self.users.lock().await.as_vec_mut() {
      if user.unpack().email == r.email {
        let new_password = user.as_mut().reset_password()?;
        let u = user.unpack();
        return Ok(ResetPasswordResponse {
          uid: u.uid,
          email: u.email.clone(),
          new_password: new_password,
        });
      }
    }

    Err(ServiceError::bad_request(
      "A megadott email cím nem található",
    ))
  }
  // Set new password
  async fn set_new_password(&self, r: NewPasswordRequest) -> ServiceResult<()> {
    let mut lock = self.users.lock().await;
    let user = lock
      .find_id_mut(&r.uid)
      .map_err(|e| ServiceError::from(e))?;
    user.as_mut().unpack().set_password(r.new_password)?;
    let u = user.unpack();
    Ok(())
  }
  // Tries to login
  async fn login(&self, r: LoginRequest) -> ServiceResult<UserObj> {
    if let Some(user) = self
      .users
      .lock()
      .await
      .iter()
      .find(|u| u.unpack().username == r.username)
    {
      if password::verify_password_from_hash(&r.password, &user.unpack().password_hash)? {
        return Ok(user.unpack().clone().into());
      }
    };
    Err(ServiceError::bad_request(
      "A megadott felhasználónév, vagy jelszó nem megfelelő!",
    ))
  }
}

#[tonic::async_trait]
impl gzlib::proto::user::user_server::User for UserService {
  async fn create_user(&self, request: Request<NewUserObj>) -> Result<Response<UserObj>, Status> {
    let res = self.create_user(request.into_inner()).await?;
    Ok(Response::new(res))
  }

  type GetAllStream = tokio::sync::mpsc::Receiver<Result<UserObj, Status>>;

  async fn get_all(&self, _: Request<()>) -> Result<Response<Self::GetAllStream>, Status> {
    // Create channels
    let (mut tx, rx) = tokio::sync::mpsc::channel(10);
    // Get found price objects
    let res = self.get_all().await?;
    // Send found objects through the channel
    for object in res.into_iter() {
      tx.send(Ok(object))
        .await
        .map_err(|_| Status::internal("Error while sending price bulk over channel"))?
    }
    return Ok(Response::new(rx));
  }

  async fn get_by_id(&self, request: Request<GetByIdRequest>) -> Result<Response<UserObj>, Status> {
    let res = self.get_by_id(request.into_inner()).await?;
    Ok(Response::new(res))
  }

  async fn update_by_id(&self, request: Request<UserObj>) -> Result<Response<UserObj>, Status> {
    let res = self.update_by_id(request.into_inner()).await?;
    Ok(Response::new(res))
  }

  async fn reset_password(
    &self,
    request: Request<ResetPasswordRequest>,
  ) -> Result<Response<ResetPasswordResponse>, Status> {
    let res = self.reset_password(request.into_inner()).await?;
    Ok(Response::new(res))
  }

  async fn set_new_password(
    &self,
    request: Request<NewPasswordRequest>,
  ) -> Result<Response<NewPasswordResponse>, Status> {
    let _ = self.set_new_password(request.into_inner()).await?;
    Ok(Response::new(NewPasswordResponse {}))
  }

  async fn login(&self, request: Request<LoginRequest>) -> Result<Response<UserObj>, Status> {
    let res = self.login(request.into_inner()).await?;
    Ok(Response::new(res))
  }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
  let users: VecPack<user::User> = VecPack::try_load_or_init(PathBuf::from("data/user"))
    .expect("Error while loading user storage");

  let user_service = UserService::init(users);

  let userlen = user_service.user_count().await;

  // If user db is empty
  // create init admin user
  if userlen == 0 {
    user_service
      .create_user(NewUserObj {
        username: env::var("USER_INIT_UNAME").unwrap_or("demouser".into()),
        name: env::var("USER_INIT_NAME").unwrap_or("demouser".into()),
        email: env::var("USER_INIT_EMAIL").unwrap_or("demouser@demouser.com".into()),
        phone: env::var("USER_INIT_PHONE").unwrap_or("...".into()),
        created_by: 1, // This user will have UID as 1
      })
      .await
      .expect("Error while creating the init admin user");
  }

  let addr = env::var("SERVICE_ADDR_USER")
    .unwrap_or("[::1]:50051".into())
    .parse()
    .unwrap();

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
