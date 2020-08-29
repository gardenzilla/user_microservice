use prelude::*;
use protos::email::email_client::*;
use protos::email::*;
use protos::user::user_server::*;
use protos::user::*;
use std::path::PathBuf;
use storaget::*;
use tokio::sync::{oneshot, Mutex};
use tonic::transport::Channel;
use tonic::{transport::Server, Request, Response, Status};

pub mod convert;
pub mod password;
pub mod prelude;
pub mod user;

pub struct UserService {
    users: Mutex<VecPack<user::User>>,
    email_client: Mutex<EmailClient<Channel>>,
}

impl UserService {
    fn new(users: Mutex<VecPack<user::User>>, email_client: EmailClient<Channel>) -> Self {
        Self {
            users,
            email_client: Mutex::new(email_client),
        }
    }
    async fn create_new_user(&self, u: CreateNewRequest) -> ServiceResult<UserObj> {
        if let Ok(_) = self.users.lock().await.find_id(&u.username) {
            return Err(ServiceError::already_exist("User exist!"));
        }
        let new_user = user::User::new(u.username, u.name, u.email, u.phone, u.created_by)?;
        let user_obj: UserObj = (&new_user).into();
        self.users.lock().await.insert(new_user)?;
        Ok(user_obj)
    }
}

#[tonic::async_trait]
impl User for UserService {
    async fn create_new(
        &self,
        request: Request<CreateNewRequest>,
    ) -> Result<Response<CreateNewResponse>, Status> {
        Ok(Response::new(CreateNewResponse {
            user: Some(self.create_new_user(request.into_inner()).await?),
        }))
    }
    async fn get_all(&self, _request: Request<()>) -> Result<Response<GetAllResponse>, Status> {
        let users = self
            .users
            .lock()
            .await
            .into_iter()
            .map(|i: &mut Pack<user::User>| i.unpack().into())
            .collect::<Vec<UserObj>>();
        let response = GetAllResponse { users: users };
        return Ok(Response::new(response));
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
            if user.get_user_email() == &req.userid {
                let new_password = user.as_mut().reset_password()?;

                // Send email
                let mut email_service = self.email_client.lock().await;
                email_service.send_email(EmailRequest {
                    to: req.userid,
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
        match self.users.lock().await.find_id(&req.username) {
            Ok(user) => match password::verify_password_from_hash(
                &req.password,
                user.unpack().get_password_hash(),
            ) {
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
            },
            Err(_) => {
                return Ok(Response::new(LoginResponse {
                    is_valid: false,
                    name: "".into(),
                }))
            }
        };
    }
}

#[tokio::main]
async fn main() -> prelude::ServiceResult<()> {
    let users: Mutex<VecPack<user::User>> = Mutex::new(
        VecPack::try_load_or_init(PathBuf::from("data/users"))
            .expect("Error while loading users storage"),
    );

    let email_client = EmailClient::connect("http://[::1]:50053")
        .await
        .expect("Error while connecting to email service");

    let user_service = UserService::new(users, email_client);

    let addr = "[::1]:50051".parse().unwrap();

    // Create shutdown channel
    let (tx, rx) = oneshot::channel();

    // Spawn the server into a runtime
    tokio::task::spawn(async move {
        Server::builder()
            .add_service(UserServer::new(user_service))
            .serve_with_shutdown(addr, async { rx.await.unwrap() })
            .await
    });

    tokio::signal::ctrl_c().await.unwrap();

    println!("SIGINT");

    // Send shutdown signal after SIGINT received
    let _ = tx.send(());

    Ok(())
}
