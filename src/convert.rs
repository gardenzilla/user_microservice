use crate::user;
use crate::UserObj;

impl From<&user::User> for UserObj {
    fn from(user: &user::User) -> Self {
        UserObj {
            id: user.get_user_id().to_string(),
            name: user.get_user_name().to_string(),
            email: user.get_user_email().to_string(),
            phone: user.get_user_phone().to_string(),
            customers: user.get_customers().to_owned(),
            created_by: user.get_created_by().to_string(),
            created_at: user.get_date_created().to_string(),
        }
    }
}
