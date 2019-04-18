import pyDes
import base64
import argparse
from Crypto.Hash import SHA, HMAC
text= "wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE="
key = 'SnNGOTg3Ni0='
mac_length = 20

def viewstate_decrypt(mykey,mytext):
   print "###################Viewstate Decryption###########################\n" 
   d = pyDes.des(mykey,pyDes.ECB,padmode=pyDes.PAD_PKCS5)
   output = base64.decodestring(mytext)
   data = output[:len(output)-mac_length]
   mac  = output[len(output)-mac_length:]
   decrypted_data  = d.decrypt(data)
   new_mac = HMAC.new(mykey, data, SHA)
   verified_mac = new_mac.digest()

   print "\ndata decrypted: %r" % decrypted_data
   print "\nmac found: %r" % mac
   print "\nmac calculate: %r" % verified_mac
   if mac == verified_mac :
     print '\nMessage authentication code (mac) is the same '
     return 0
   return 1
  
def viewstate_encrypt(mykey,payload):
   d = pyDes.des(mykey,pyDes.ECB,padmode=pyDes.PAD_PKCS5)
   output  = d.encrypt(payload)
   mac = HMAC.new(mykey, output, SHA).digest()
   output+=mac 
   final = base64.b64encode(output)
   return final

parser = argparse.ArgumentParser(description='Viewstate encryption, decryption ')
parser.add_argument('-a','--action', help='Define the action to do (encrypt or decrypt)', default='decrypt')
args = vars(parser.parse_args())

# Decode the key from base64
key= base64.decodestring(key)
 
if args['action'] == 'decrypt':
  ## decrypt a viewstate data
  viewstate_decrypt(key,text)

## encrypt a payload
if args['action'] == 'encrypt':
  payload = open('payload','rb').read()
  final = viewstate_encrypt(key,payload)
  print final
