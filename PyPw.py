import string
import random
import binascii
import pickle
import hashlib as hasher
from math import *



class crypter:

	def __init__(self):
		print("#"*15)
		print("for help please type crypter.help() ...")
		print("#"*15)
		self.jumpM = 0
		self.jump = 0
		self.total = 0
		self.cntf = 0
		self.cnts = 0
		__encrypted_text = ""
		self.all_char_list = [x for x in string.ascii_letters] + [y for y in string.digits]
		self.spc_list = []

	# a clear function to clear all variables data
	def clear(self):
		self.jumpM = 0
		self.jump = 0
		self.total = 0
		self.cnts = 0
		self.cntf = 0
		self.__encrypted_text = ""
		self.spc_list = []
	@staticmethod
	def help():
		head = r"""
 		   _  _    _______________.___.__________ __      __      
__| || |__ \______   \__  |   |\______   |  \    /  \ __| || |__
\   __   /  |     ___//   |   | |     ___|   \/\/   / \   __   /
 |  ||  |   |    |    \____   | |    |    \        /   |  ||  | 
/_  ~~  _\  |____|    / ______| |____|     \__/\  /   /_  ~~  _\
  |_||_|              \/                        \/      |_||_|  

		"""
		commands = """
		# This library is for
		# Encrypting/decrypting
		# data
		##### commands #####
		############################################################################################################
   		# encrypt -- params : text to encrypt , password to use : encrypt the given text to unreadable form : example : encrypt("text","password")
   		# print_encrypted -- no params needed : show the encrypted message : example : print_encrypted()
   		# get_encrypted -- no params needed : return the encrypted message for further use : example : var = get_encrypted()
   		# save_in_file -- params : file_name : save the encrypted text in a file to use it later : example : save_in_file("res_decrypt")
   		# decrypt -- params : file_name , password : encrypt the decrypted text to human readable form : example : decrypt("res_decrypt","password")
   		######################################################################### Credits #############################################################
   		# Creators:
   		# Ahmed Hesham Salah
   		# Ahmed J. : AKA MT_Virus
   		# All rights reserved to ArDoSeR Team .
   		"""

		print(head)
		print(commands)


	# method to show the encrypted text
	def print_encrypted(self):
		print(self.__encrypted_text)

	# method to return the encrypted for further use
	def get_encrypted(self):
		return self.__encrypted_text

	# to save the encrypted in a file
	def save_in_file(self,file_name):
		self.file = open(file_name+".txt","wb")
		pickle.dump({"data":self.__encrypted_text},self.file)
		self.file.close()


	# method used to detect spaces in a string
	def space_detector(self,msg):
		self.spc_list = []
		if " " in msg:
			space_counter = 0
			for x in msg:
				if x == " ":
					self.spc_list.append(space_counter)
				space_counter += 1
			words_list = msg.split(" ")
			msg = "_".join(words_list)
			return msg
		else:
			return msg


	# method to get the encrypted letters to replace them in the original text (returns a list of letters)
	def get_encrypted_elements(self,password,msg):
		msg = self.space_detector(msg)
		if len(password) >= 3:
			self.OrdCnt = 0
			for c in range(len(password)):
				self.OrdCnt+= ord(password[c])
				self.OrdCnt = abs((self.OrdCnt//2)-388)
			self.start= ord(password[0])
			self.end=  ord(password[-1])
			self.jumpM = (self.start + self.end) % len(password)
			if self.jumpM == 0 :
				self.jumpM = (self.start + self.end) // len(password)
			self.jump = (self.jumpM * 2 + 8) // len(password)
			self.total = len(msg)+((len(msg)-1)*self.jump)
			self.chosen = ord(password[len(password)//2]) + self.OrdCnt
			self.CntDiv = 0
			while self.chosen > len(password):
				self.chosen=abs(self.chosen-1)
				self.chosen//=2
				self.CntDiv +=1
			self.Ecode= (ord(password[self.chosen-1])//2)-12
			self.Ecode1= (ord(password[-1])//2)-15
			self.Emsg=[]
			for self.E in msg:
				self.Emsg.append(chr(abs(ord(self.E)+self.Ecode1-self.Ecode+self.CntDiv-self.chosen)))
			return self.Emsg
		else:
			return False

	# the reverse of the encrypted letters used for debuging returns a list with original letters
	def get_reversed_encrypted_elements(self,password,msg):
		if len(password) >= 3:
			self.OrdCnt = 0
			for c in range(len(password)):
				self.OrdCnt+= ord(password[c])
				self.OrdCnt = abs((self.OrdCnt//2)-388)
			self.start= ord(password[0])
			self.end=  ord(password[-1])
			self.jumpM = (self.start + self.end) % len(password)
			if self.jumpM == 0 :
				self.jumpM = (self.start + self.end) // len(password)
			self.jump = (self.jumpM * 2 + 8) // len(password)
			self.chosen = ord(password[len(password)//2]) + self.OrdCnt
			self.CntDiv = 0
			while self.chosen > len(password):
				self.chosen=abs(self.chosen-1)
				self.chosen//=2
				self.CntDiv +=1
			self.Ecode= (ord(password[self.chosen-1])//2)-12
			self.Ecode1= (ord(password[-1])//2)-15
			self.Emsg=[]
			self.counter = 0
			for self.E in msg:
				if self.counter % self.jump == 0:
					self.Emsg.append(chr(abs(ord(self.E)-self.Ecode1+self.Ecode-self.CntDiv+self.chosen)))
				self.counter += 1
			return self.Emsg
		else:
			return False

	# 

	# this method used to XOR the password 
	def pass_reversed_additional(self,password,hashed):
		new_text = ""
		for x in password:
			new_text += chr(ord(x)^int((len(password)+len(hashed))/2))
		return new_text

	# the XOR layer
	def additional(self,final_text,jump,total):
		new_text = ""
		for x in final_text:
			new_text += chr(ord(x)^int((jump+total)/len(final_text)))
		return new_text

	# method used to reformat the password into a unique format (returns a new and unique password)
	def reformat_pass(self,password):
		old_pass = hasher.md5(password.encode())
		self.hashed = old_pass.hexdigest()
		new_pass = self.hashed.encode("ascii")
		new_pass = self.pass_reversed_additional(bytes.decode(new_pass),hasher.md5(new_pass).hexdigest())
		return new_pass


	# custom method to replace specifique letters
	def replacer(self,text,let_to_change,let_after_change):
		complete_text =""
		for x in text:
			if x ==  let_to_change:
				complete_text += let_after_change
			else:
				complete_text += x
		return complete_text


	# the hex part (encoding) with additional tweaks returns an str encoded with hex
	def second_additional(self,final_text,passw):
		passw = passw.replace("a","")
		passw = passw.replace("b","")
		passw = passw.replace("c","")
		OrdCnt = 0
		for c in range(len(passw)):
			OrdCnt+= ord(passw[c])
		OrdCnt = abs((OrdCnt//2)-388)
		DR = "m"
		ER = "s"
		FR = "r"
		CntHex = abs(ord("f")+ OrdCnt -self.cntf-self.cnts)
		alpha2 = "abc"
		while CntHex > 3:
			CntHex=abs(CntHex-1)
			CntHex//=2
		CntHex=CntHex-1
		final_text = self.replacer(final_text,"d",DR)
		final_text = self.replacer(final_text,"e",ER)
		final_text = self.replacer(final_text,"f",FR)
		final_text = self.replacer(final_text,"a","d")
		final_text = self.replacer(final_text,"b","e")
		final_text = self.replacer(final_text,"c","f")
		final_text=self.replacer(final_text,DR,alpha2[CntHex]) # m ~ a
		alpha2 = alpha2.replace(alpha2[CntHex] , "")
		final_text = self.replacer(final_text, ER ,alpha2[0]) # s ~ b
		final_text = self.replacer(final_text, FR ,alpha2[1] ) # r ~ c
		final_text = final_text.encode()
		final_text = binascii.unhexlify(final_text)
		final_text = bytes.decode(final_text)
		return final_text


	# return the sum of the ords of the password
	def get_ords(self,password):
		ords = 0
		for x in password:
			ords += ord(x)
		return str(ords)

	# returns all the numbers of the hashed password
	def get_nums(self,password):
		self.num_hash = hasher.md5(password.encode("ascii")).hexdigest()
		self.nums = ""
		for x in self.num_hash:
			try:
				int(x)
				self.nums += str(x)
			except:
				continue
		return self.nums



	# the encrypt function where all the magic happends (use the methods defined above)
	def shifter(self,password,text):
		self.param = (len(password)+(self.jump*len(password)%self.total)+self.total)%ord(password[2])
		self.__encrypted_text = ""
		for x in text:
			self.__encrypted_text += chr(ord(x)+self.param)

	def reverse_shifter(self,password):
		self.param = (len(password)+(self.jump*len(password)%self.total)+self.total)%ord(password[2])
		self.text_rev = ""
		for x in self.__encrypted_text:
			self.text_rev += chr(ord(x)-self.param)
		return self.text_rev

	def encrypt(self,text,password):
		password = self.reformat_pass(password)
		self.Emsg = self.get_encrypted_elements(password,text)
		if self.Emsg:
			self.EarlyTotal = ""
			for r in range(self.total):
				self.EarlyTotal= self.EarlyTotal + random.choice(self.all_char_list)
			self.cntf = 0
			self.cnts = 0
			while self.cntf <=self.total:
				self.cntf+=self.jump+1
				self.cnts+=1
			self.word_counter = 0
			self.final_text = ""
			for self.x in self.EarlyTotal:
				if len(self.Emsg) == 0:
					self.final_text += str(self.x)
				else:
					if (self.word_counter % self.jump)  == 0:
						self.final_text += self.Emsg[0]
						self.Emsg.pop(0)
						self.word_counter += 1
					else:
						self.final_text += str(self.x)
						self.word_counter += 1

			self.last_index = len(self.final_text)
			self.final_text += "."
			for ind in self.spc_list:
				self.final_text += str(ind)
				self.final_text += "."
			self.final_text += "."
			self.final_text += str(self.last_index)
			self.final_text = self.final_text.encode("ascii")
			self.final_text = bytes.decode(binascii.hexlify(self.final_text))
			self.final_text = self.second_additional(self.final_text,password)
			self.ords = self.get_ords(password)
			self.nums = self.get_nums(password)
			self.hexed = bytes.decode(binascii.hexlify(self.num_hash.encode("ascii")))
			self.__encrypted_text = self.additional(self.final_text,self.jump,self.total)
			self.hexed = self.additional(self.hexed,self.jump,self.total)
			self.first = self.additional(self.ords+self.nums,self.jump,self.total)
			self.__encrypted_text = self.first + self.__encrypted_text + self.hexed
			self.__encrypted_text += "."
			self.__encrypted_text += str(self.total)
			self.shifter(password,self.__encrypted_text)
			print("done encrypting ...")
		else:
			print("sorry your password should at least have 3 characters ...")


	########################

	# get all the spaces indexes
	def get_spaces_indexes(self,lst):
		lst_indexes = []
		index = ""
		for x in lst:
			if x == ".":
				if len(index) != 0:
					lst_indexes.append(int(index))
					index = ""
				else:
					break
			else:
				index += str(x)
		return lst_indexes


	# this to load the encrypted data from a file
	def load_data(self,file_name):
		try:
			self.file = open(file_name+".txt","rb")
			self.loaded_data = pickle.load(self.file)["data"]
			self.file.close()
			return self.loaded_data
		except Exception as e:
			print(str(e))
			return False

	# to get the backward index to get a specified type of data
	def get_backward_data(self):
		self.backward_counter = -1
		for _ in range(len(self.__encrypted_text)):
			if self.__encrypted_text[self.backward_counter] == ".":
				self.start_index = self.backward_counter
				break
			self.backward_counter -= 1
		return self.start_index

	# the reverse of the hex part return the original text without hex encoding
	def reversed_hex(self,passw):
		self.start = ord(passw[0])
		self.end=  ord(passw[-1])
		self.jumpM = (self.start + self.end) % len(passw)
		if self.jumpM == 0 :
			self.jumpM = (self.start + self.end) // len(passw)
		self.jump = (self.jumpM * 2 + 8)// len(passw)
		self.length_msg = int((self.total + self.jump)/(self.jump+1))
		self.cntf = 0
		self.cnts = 0
		while self.cntf <= self.total:
			self.cntf+=self.jump+1
			self.cnts+=1
		self.__encrypted_text = self.__encrypted_text.encode()
		self.__encrypted_text = self.__encrypted_text.hex()
		self.passwo = passw
		self.passwo = self.passwo.replace("a","")
		self.passwo = self.passwo.replace("b","")
		self.passwo = self.passwo.replace("c","")
		self.OrdCnt = 0
		for c in range(len(self.passwo)):
			self.OrdCnt+= ord(self.passwo[c])
		self.OrdCnt = abs((self.OrdCnt//2)-388)
		self.CntHex = abs(ord("f")+ self.OrdCnt -self.cntf-self.cnts)
		self.alpha2 = "abc"
		while self.CntHex > 3:
			self.CntHex=abs(self.CntHex-1)
			self.CntHex//=2
		self.CntHex=self.CntHex-1
		self.DR = "m"
		self.ER = "s"
		self.FR = "r"
		self.__encrypted_text=self.replacer(self.__encrypted_text, self.alpha2[self.CntHex],self.DR)
		self.alpha2 = self.alpha2.replace(self.alpha2[self.CntHex] , "")
		self.__encrypted_text = self.replacer(self.__encrypted_text, self.alpha2[0],self.ER )
		self.__encrypted_text = self.replacer(self.__encrypted_text, self.alpha2[1],self.FR )
		self.__encrypted_text = self.replacer(self.__encrypted_text,"d","a")
		self.__encrypted_text = self.replacer(self.__encrypted_text,"e","b")
		self.__encrypted_text = self.replacer(self.__encrypted_text,"f","c")
		self.__encrypted_text = self.replacer(self.__encrypted_text,self.DR,"d")
		self.__encrypted_text = self.replacer(self.__encrypted_text,self.ER,"e")
		self.__encrypted_text = self.replacer(self.__encrypted_text,self.FR,"f")
		self.__encrypted_text = self.__encrypted_text.encode()
		self.__encrypted_text = binascii.unhexlify(self.__encrypted_text)
		self.__encrypted_text = bytes.decode(self.__encrypted_text)

	# a simple method to calculate the jump
	def calculate_jmp(self,passw):
		self.start = ord(passw[0])
		self.end=  ord(passw[-1])
		self.jumpM = (self.start + self.end) % len(passw)
		if self.jumpM == 0 :
			self.jumpM = (self.start + self.end) // len(passw)
		self.jump = (self.jumpM * 2 + 8) // len(passw)

	# getting all the spaces indexes
	def retreive_spaces(self,start_index):
		if self.__encrypted_text[int(self.__encrypted_text[start_index+1:])] == ".":
			if len(self.__encrypted_text[int(self.__encrypted_text[start_index+1:]):start_index]) == 0:
				pass
			else:
				spaces_list = self.__encrypted_text[int(self.__encrypted_text[start_index+1:])+1:start_index]
				self.space_idexes = self.get_spaces_indexes(spaces_list)
				self.__encrypted_text = self.__encrypted_text[:int(self.__encrypted_text[start_index+1:])]

	# building our decrypted word
	def build(self,Emsg_msg , length_msg):
		final_word = ""
		counter = 1
		index = 0
		while True:
			if index in self.space_idexes:
				final_word += " "
				Emsg_msg.pop(0)
			else:
				final_word += Emsg_msg[0]
				Emsg_msg.pop(0)

			if counter == length_msg:
				break
			index += 1
			counter += 1
		return final_word[:length_msg]

	# the main decrypt function use functions defined above
	def decrypt(self,file_name,password):
		self.__encrypted_text = self.load_data(file_name)
		password = self.reformat_pass(password)
		self.__encrypted_text = self.reverse_shifter(password)
		if len(self.__encrypted_text) != 0:
			if not len(password) <= 3:
				self.calculate_jmp(password)
				self.start_index = self.get_backward_data()
				self.total = int(self.__encrypted_text[self.start_index+1:])
				self.__encrypted_text = self.__encrypted_text[:self.start_index]
				self.ords = self.get_ords(password)
				self.nums = self.get_nums(password)
				self.hexed = bytes.decode(binascii.hexlify(self.num_hash.encode("ascii")))
				self.hexed = self.additional(self.hexed,self.jump,self.total)
				self.first = self.additional(self.ords+self.nums,self.jump,self.total)
				self.__encrypted_text = self.__encrypted_text[len(self.first):]
				self.__encrypted_text = self.__encrypted_text[:-len(self.hexed)]
				self.__encrypted_text = self.additional(self.__encrypted_text,self.jump,self.total)
				self.reversed_hex(password)
				self.start_index = self.get_backward_data()
				self.retreive_spaces(self.start_index)
				self.Emsg_msg = self.get_reversed_encrypted_elements(password,self.__encrypted_text)
				if self.Emsg_msg:
					self.final_text = self.build(self.Emsg_msg,self.length_msg)
					print(self.final_text)
					self.clear()
						
				else:
					raise "some error occured ..."

			else:
				print("You have selected an invalid password it's can't less than 3 letters , You can try again")	
				
		else:
			print("sorry something went wrong ...")




			    


