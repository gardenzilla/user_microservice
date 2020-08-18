use prelude::*;
use protos::user::user_server::*;
use protos::user::*;
use std::{path::PathBuf, sync::Mutex};
use storaget::*;
use tonic::{transport::Server, Request, Response, Status};

pub mod convert;
pub mod password;
pub mod prelude;
pub mod user;

pub struct UserService {
    users: Mutex<VecPack<user::User>>,
}

impl UserService {
    fn new(users: Mutex<VecPack<user::User>>) -> Self {
        Self { users }
    }
    fn create_new_user(&self, u: CreateNewRequest) -> ServiceResult<UserObj> {
        if let Ok(_) = self.users.lock().unwrap().find_id(&u.username) {
            return Err(ServiceError::already_exist("User exist!"));
        }
        let new_user = user::User::new(u.username, u.name, u.email, u.phone, u.created_by)?;
        let user_obj: UserObj = (&new_user).into();
        self.users.lock().unwrap().insert(new_user)?;
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
            user: Some(self.create_new_user(request.into_inner())?),
        }))
    }
    async fn get_all(&self, _request: Request<()>) -> Result<Response<GetAllResponse>, Status> {
        println!("New get all");
        let users = self
            .users
            .lock()
            .map_err(|_| Status::internal("Lock error"))?
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
            .map_err(|_| Status::internal("lock error"))?
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
        let mut lock = self
            .users
            .lock()
            .map_err(|_| Status::internal("Mutex lock error"))?;
        let user = match lock.find_id_mut(&_user.id) {
            Ok(u) => u,
            Err(err) => return Err(Status::not_found(format!("{}", err))),
        };
        user.update(|u| {
            u.set_user_name(_user.name.to_string()).unwrap();
            u.set_user_email(_user.email.to_string()).unwrap();
            u.set_user_phone(_user.phone.to_string()).unwrap();
        })
        .map_err(|_| Status::internal("Error while updating user object"))?;
        let response = UpdateByIdResponse {
            user: Some(user.unpack().into()),
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
            .map_err(|_| Status::internal("Error while locking"))?
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
        _request: Request<ReserPasswordRequest>,
    ) -> Result<Response<ReserPasswordResponse>, Status> {
        todo!()
    }
}

#[tokio::main]
async fn main() -> prelude::ServiceResult<()> {
    let users: Mutex<VecPack<user::User>> = Mutex::new(
        VecPack::try_load_or_init(PathBuf::from("data/users"))
            .expect("Error while loading users storage"),
    );

    let user_service = UserService::new(users);

    let addr = "[::1]:50051".parse().unwrap();

    Server::builder()
        .add_service(UserServer::new(user_service))
        .serve(addr)
        .await
        .expect("Error while staring server"); // Todo implement ? from<?>

    Ok(())
}
