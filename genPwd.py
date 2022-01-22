from passlib.hash import pbkdf2_sha512
import sys
print(pbkdf2_sha512.using(rounds=25000, salt_size=16).hash(sys.argv[1]))
sys.stdout.flush()
