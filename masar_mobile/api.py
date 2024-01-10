import frappe 
from frappe import auth 
from frappe.exceptions import AuthenticationError
from frappe.auth import LoginManager




########### mahmoud code login user by user_email and password
@frappe.whitelist(allow_guest=True)
def user_login(usr, pwd):
    try:
        login_manager = frappe.auth.LoginManager()
        login_manager.authenticate(user=usr, pwd=pwd)
        login_manager.post_login()
    except frappe.AuthenticationError as e:
        raise frappe.AuthenticationError("Invalid email or verification code")
    except Exception as e:
        raise e
    user = frappe.get_doc('User', frappe.session.user)
    generated_key = generate_key(frappe.session.user)
    frappe.response["message"] = {
        "success_key": 1,
        "message": "Success Authenticate",
        "sid": frappe.session.sid,
        "api_key" :user.api_key,
        "api_secret": generated_key,
        "username": user.username,
        "email": user.email
    }

@frappe.whitelist()
def generate_key(user):
    user_details = frappe.get_doc('User', user)
    secret = frappe.generate_hash(length=10)
    if not user_details.api_key:
        api_key = frappe.generate_hash(length=10)
        user_details.api_key = api_key
    user_details.api_secret = secret
    user_details.save()
    return secret

############# mahmoud code for logout 
@frappe.whitelist(allow_guest=True)
def logout_user():
    frappe.local.login_manager.logout()
    # frappe.db.commit()
    return { 'message' : 'User Logout Successfully'}


#################### mahmoud check if email exist 
@frappe.whitelist(allow_guest=True)
def get_email(email = None):
    result = frappe.db.sql("""
        select tu.email
        from tabUser tu 
        where tu.email = %s AND tu.enabled =1
        ORDER BY tu.creation DESC;
        """, (email), as_dict=True)
    frappe.clear_cache()
    if not result:
        return f"This E-mail does not exist or deactivated. Plese Contact The Administrator"
    return result 

###################### mahmoud code to reset password 
@frappe.whitelist(allow_guest=True)
def reset_password(email , pwd ):
    user = frappe.get_value('User' , {'email':email} ,['full_name'])
    frappe.db.set_value('User' , email , 'new_password' , pwd)
    if not user:
        return f"The Password was Not Reset to {user}"
    return f"The Password has been Reset Successfully to {user}"

