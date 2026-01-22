"""Reset admin password to 'admin123'"""
import json
import bcrypt

# Generate hash for 'admin123'
password = b'admin123'
salt = bcrypt.gensalt()
password_hash = bcrypt.hashpw(password, salt).decode('utf-8')

print(f"New password hash: {password_hash}")

# Update users.json
users_file = 'data/users.json'
with open(users_file, 'r') as f:
    users = json.load(f)

for user in users:
    if user['username'] == 'admin':
        user['password_hash'] = password_hash
        user['must_change_password'] = False
        print(f"Updated admin user password")

with open(users_file, 'w') as f:
    json.dump(users, f, indent=2, default=str)

print("\nAdmin password reset to: admin123")
print("Please restart the server and try logging in.")
