from passlib.hash import pbkdf2_sha512
import sys
print(pbkdf2_sha512.verify(sys.argv[1], sys.argv[2]))
sys.stdout.flush()
