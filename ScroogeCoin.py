from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa


class Coin():
    #static variable ID
    coinID = 0
    def __init__(self):
        self.ID = "c" + str(Coin.coinID)
        Coin.coinID +=1
        self.last_trans = None


class User():
    #Static variable ID
    userID = 0
    def __init__(self):
        self.ID = "u" + str(User.userID)
        User.userID +=1
        # generate private
        self._private_key = dsa.generate_private_key(key_size=1024, backend=default_backend())
        # get public key
        self.public_key = self._private_key.public_key()
        self.coins = []
    
    def add_coin(self, coin):
        self.coins.append(coin)

    def remove_coin(self, coin):
        self.coins.remove(coin)  

    def create_transaction(self, amount, coins, pbk_receiver, bFirstTrans):
        hash_ptrs = []
        if not bFirstTrans :
            for i in range(0, len(coins)):
                last_trans = coins[i].last_trans
                hash_last_trans = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hash_last_trans.update(last_trans.__str__())
                hash_last_trans.finalize()
                hash_ptr = HashPtr(last_trans, hash_last_trans)
                hash_ptrs.append(hash_ptr)
        else:
            hash_ptrs = None
        
        trans = Transaction(amount, coins, hash_ptrs, self.public_key, pbk_receiver, bFirstTrans)
        signed_trans = self._private_key.sign(trans.__str__(), hashes.SHA256())
        trans.signature = signed_trans

        #Send the transaction to Scrooge to verify it
        Scrooge.getInstance().verify_trans(trans, bFirstTrans)
    
    def sign(self, coin):
        return self._private_key.sign(coin, hashes.SHA256())
        
        


class Scrooge(User):
     
    __instance = None

    def getInstance():
      """ Static access method. """
      if Scrooge.__instance == None:
        Scrooge()
      return Scrooge.__instance

    def __init__(self):
        """ Virtually private constructor. """
        if Scrooge.__instance != None:
            raise Exception("Scrooge class is a singleton!")
        else:
            Scrooge.__instance = self
            super().__init__()
            self.buffer = []
            self.users = []
            self.first_block = True
            self.finalHashPtr = None
            
    def create_coin(self):
        coin = Coin()
        self.create_transaction(1, [coin], self.public_key, True)
        

    def verify_trans(self, trans, bFirstTrans):
        
        trans_valid = True

        if bFirstTrans:
            #verification of SCROOGE's Signature
            try:
                self.public_key.verify(trans.signature, trans.__str__(), hashes.SHA256())
            except:
                trans_valid = False
                print("ALERT!! Invalid Coin Creation Transaction!! Ya les! :o")

        else:
            #verification of SENDER's Signature
            try:
                trans.pbk_sender.verify(trans.signature, trans.__str__(), hashes.SHA256())
            except:
                trans_valid = False
                print("ALERT!! Invalid Transaction!! :o")

            #Verify coins belong to sender
            if self.public_key == trans.pbk_sender:
                sender = self
            else:
                sender = self.users[trans.pbk_sender]
            for coin in trans.coins:
                if coin not in sender.coins:
                    trans_valid = False
                    print("ALERT!! Invalid Transaction!! :o")

            #Check hash ptrs against buffer
            hash_ptrs = trans.hash_ptrs
            for hash_ptr in hash_ptrs:
                for buffer_trans in self.buffer:
                    if buffer_trans.hash_ptrs != None:
                        for buffer_trans_hash_ptr in buffer_trans.hash_ptrs:
                            if hash_ptr.hash == buffer_trans_hash_ptr.hash:
                                trans_valid = False
                                print("ALERT!! Invalid Transaction!! :o")
            
        if trans_valid:
            self.buffer.append(trans)
        
        if len(self.buffer) == 10:
            self.publish_block()

        
        

    def publish_block(self):
        #Perform the actual transactions (add and remove coins)
        block_trans = []
        for trans in self.buffer:
            if not trans.bFirstTrans:
                receiver = self.users[trans.pbk_receiver]
                if self.public_key == trans.pbk_sender:
                    sender = self
                else:
                    sender = self.users[trans.pbk_sender]

                for coin in trans.coins:
                    receiver.add_coin(coin)
                    sender.remove_coin(coin)
                    coin.last_trans = trans
            else: #scrooge pays to himself
                for coin in trans.coins:
                    self.add_coin(coin)
                    coin.last_trans = trans

            block_trans.append(trans)
        
        #empty the buffer
        self.buffer = []

        #Create a block of 10 transactions
        if self.first_block:
            hash_ptr_prev_block = None
            self.first_block = False
        else:
            #hash ptr of prev block
            hash_ptr_prev_block = HashPtr(self.finalHashPtr.trans, self.finalHashPtr.hash)

        block = Block(block_trans, hash_ptr_prev_block)
        #hash of the block
        hash_block = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_block.update(block.__str__())
        hash_block.finalize()
        #signature of the block
        signed_block = self._private_key.sign(block.__str__(), hashes.SHA256())

        #create new final hash ptr
        self.finalHashPtr = FinalHashPtr(block, hash_block, signed_block)
      

class Transaction():
    '''
    Each transaction should have a :
        transaction ID, 
        the amount of coins,
        transferred coin objects, 
        hash pointers to the coins' previous transactions, 
        and signed by the sender.
    '''
    #Static variable ID
    transID = 0

    def __init__(self, amount, coins, hash_ptrs, pbk_sender, pbk_receiver, bFirstTrans): 
        self.ID = "t" + str(Transaction.transID)
        Transaction.transID +=1
        self.amount = amount
        self.coins = coins
        self.hash_ptrs = hash_ptrs
        self.pbk_receiver = pbk_receiver
        self.pbk_sender = pbk_sender
        self.signature = ""
        self.bFirstTrans = bFirstTrans
    

    def __str__(self):
        coins_str = b""
        if self.coins != None:
            coins_str = b",".join(bytes(str(x), encoding='utf-8') for x in self.coins)
        hash_ptrs_str = b""
        if self.hash_ptrs != None:
            hash_ptrs_str = b",".join(x.__str__() for x in self.hash_ptrs)
        
        trans_str = b"" + bytes(self.ID, encoding='utf8') + b";" + bytes(str(self.amount), encoding='utf8') + b";" + coins_str  + b";" + hash_ptrs_str + b";" + bytes(str(self.pbk_sender), encoding='utf8') + b";" + bytes(str(self.pbk_receiver), encoding='utf8')
        return trans_str





class Block():
    '''
    Each block in the blockchain should have:
        a block ID, 
        10 valid transactions,
        a pointer to the previous block, 
        the hash of the entire previous block withOUT the signature.
    '''
    #Static variable ID
    blockID = 0
    def __init__(self, transactions, hash_ptr_prev_block):
        self.ID = "b" + str(Block.blockID)
        Block.blockID +=1
        #list of 10 transactions
        self.transactions = transactions 
        self.hash_ptr_prev_block = hash_ptr_prev_block
    
    def __str__(self):
        block_str = bytes()
        for trans in self.transactions:
            block_str += trans.__str__()
        if self.hash_ptr_prev_block != None:
            block_str += self.hash_ptr_prev_block.__str__()
        return block_str


class HashPtr():
    #hash pointer of a single transaction
    def __init__(self, trans, hash):
        self.trans = trans
        self.hash = hash
    
    def __str__(self):
        return self.trans.__str__() + bytes(self.hash.__str__(), encoding='utf-8')



class FinalHashPtr(HashPtr):
    #Hash pointer of the final block
    def __init__(self, block, hash, scrooge_sig):
        super().__init__(block, hash)
        self.scrooge_sig = scrooge_sig





def simulation():

    #INITIALIZATION:
    users = {}

    for i in range(0, 100):
        user = User()
        users[user.public_key] = user

    scrooge = Scrooge()
    scrooge.users = users 

    #Scrooge creates 1K coins, and pays 10 per user
    for i in range(0, 1000):
        scrooge.create_coin()
    print("Coins created successfully")

    j=0
    trans_counter = 0
    for user_pbk_key in scrooge.users:
        if trans_counter%10==0:
            j=0
        scrooge.create_transaction(10, scrooge.coins[j:j+10], user_pbk_key, 0)
        j+=10
        trans_counter+=1
    print("paid all users successfully")


    return scrooge
    




def main():

    scrooge = simulation()




if __name__ == "__main__":
    main()