from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import random
import msvcrt
import math


class Coin():
    #static variable ID
    coinID = 0
    def __init__(self):
        self.ID = "c" + str("{:03d}".format(Coin.coinID))
        Coin.coinID +=1
        self.last_trans = None



class User():
    #Static variable ID
    userID = 0
    def __init__(self):
        self.ID = "u" + str("{:02d}".format(User.userID))
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

    def create_transaction(self, amount, coins, pbk_receiver, bFirstTrans, log_file):
        hash_ptrs = []
        if not bFirstTrans :
            for i in range(0, len(coins)):
                last_trans = coins[i].last_trans
                hash_last_trans = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hash_last_trans.update(last_trans.__str__())
                hash_ptr = HashPtr(last_trans, hash_last_trans.finalize())
                hash_ptrs.append(hash_ptr)
        else:
            hash_ptrs = None
        
        trans = Transaction(amount, coins, hash_ptrs, self.public_key, pbk_receiver, bFirstTrans)
        signed_trans = self._private_key.sign(trans.__str__(), hashes.SHA256())
        trans.signature = signed_trans

        #Send the transaction to Scrooge to verify it
        Scrooge.getInstance().verify_trans(trans, bFirstTrans, log_file)
    
    def sign(self, coin):
        return self._private_key.sign(coin, hashes.SHA256())


        
class Scrooge(User):
     
    __instance = None
    @staticmethod
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
            
    def create_coin(self, log_file):
        coin = Coin()
        self.create_transaction(1, [coin], self.public_key, True, log_file)
        

    def verify_trans(self, trans, bFirstTrans, log_file):
        
        trans_valid = True

        double_spending_attack = False
        signature_verification_failed = False
        coin_doesnot_belong_sender = False
        coin_creation_attack = False

        if bFirstTrans:
            #verification of SCROOGE's Signature
            try:
                self.public_key.verify(trans.signature, trans.__str__(), hashes.SHA256())
            except:
                trans_valid = False
                coin_creation_attack = True
                

        else:
            #verification of SENDER's Signature
            try:
                trans.pbk_sender.verify(trans.signature, trans.__str__(), hashes.SHA256())
            except:
                trans_valid = False
                signature_verification_failed = True
                

            #Verify coins belong to sender
            if self.public_key == trans.pbk_sender:
                sender = self
            else:
                sender = self.users[trans.pbk_sender]
            for coin in trans.coins:
                if coin not in sender.coins:
                    trans_valid = False
                    coin_doesnot_belong_sender = True
                    

            #Check hash ptrs against buffer
            hash_ptrs = trans.hash_ptrs
            for hash_ptr in hash_ptrs:
                for buffer_trans in self.buffer:
                    if buffer_trans.hash_ptrs != None:
                        for buffer_trans_hash_ptr in buffer_trans.hash_ptrs:
                            if hash_ptr.hash == buffer_trans_hash_ptr.hash:
                                trans_valid = False
                                double_spending_attack = True
                                
            
        if trans_valid:
            self.buffer.append(trans)
            if log_file != None:
                print_block_under_construction(self.buffer, log_file)  
        else:
            print_invalid_transaction(double_spending_attack, signature_verification_failed, coin_creation_attack, coin_doesnot_belong_sender, trans, log_file)
            
        
        if len(self.buffer) == 10:
            self.publish_block(log_file)

        
        

    def publish_block(self, log_file):
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
        hash_block_bytes = hash_block.finalize()
        #signature of the block
        signed_block = self._private_key.sign(block.__str__(), hashes.SHA256())

        #create new final hash ptr
        self.finalHashPtr = FinalHashPtr(block, hash_block_bytes, signed_block)
        
        #block contains its own hash
        block.hash = hash_block_bytes

        # DONE: Print the blockchain after a new block is 
        if log_file != None:
            print_block_chain(self.finalHashPtr, log_file)



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
        #self.ID = "t" + str(Transaction.transID)
        self.ID = "t" + str("{:010d}".format(Transaction.transID))
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

    def get_trans_details(self):
        details = "TransactionID: " + str(self.ID) + "\nAmount: " + str(self.amount) + "\nCoins: ["
        c_str = ""
        if self.coins != None:
            c_str = ", ".join(str(x.ID) for x in self.coins)
        details += c_str + "]\n"
        details += "SenderPublicKey: "
        details += print_pbk_key(self.pbk_sender) + "\n"
        details += "ReceiverPublicKey: "
        details += print_pbk_key(self.pbk_receiver) + "\n"
        details += "HashPointers: ["
        h_str = ""
        if self.hash_ptrs != None:
            h_str = ", ".join(x.get_hash_ptr_details(block=False) for x in self.hash_ptrs)
        else:
            h_str = "None"
        details += h_str + "]\n"
        
        return details



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
        #self.ID = "b" + str(Block.blockID)
        self.ID = "b" + str("{:010d}".format(Block.blockID))
        Block.blockID +=1
        #list of 10 transactions
        self.transactions = transactions 
        self.hash = None
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
    
    #DONE: printing hash pointer
    def get_hash_ptr_details(self, block):
        if block:
            return "BlockID:" + self.trans.ID + "-Hash:" + self.hash.hex()
        else:
            return "TransID:" + self.trans.ID + "-Hash:" + self.hash.hex()



class FinalHashPtr(HashPtr):
    #Hash pointer of the final block
    def __init__(self, block, hash, scrooge_sig):
        super().__init__(block, hash)
        self.scrooge_sig = scrooge_sig
    


class MerkleTree():
    '''
    A merkle tree could either be a leaf node or a non-leaf node
    Each node (leaf/non-leaf) has:
        a left child
        a right child
        a parent node
        a hash of the left child
        a hash of the right child
        a hash (combination of the two children hashes)
    A leaf node's children are transactions, while a non-leaf node's children are merkle trees.
    A leaf node is linked to its children transactions (one-way link), 
    while in a non-leaf node the parent is linked to the children and the children to the parent (double-link).
    '''

    def __init__(self, left_tree, right_tree, left_sibling):
        if(left_tree == None and right_tree == None): # leaf node pointing to None transactions
            self.hashL = left_sibling.hashL # replicate left sibling's hash
            self.hashR = left_sibling.hashR
            self.hash = self.hashL + self.hashR
            self.left_tree = left_tree
            self.right_tree = right_tree
            self.parent = None

        elif isinstance(left_tree,Transaction) : # leaf node pointing to left transaction and right transaction?
            #hash left trans
            hashL = hashes.Hash(hashes.SHA256(), backend=default_backend())
            hashL.update(left_tree.__str__())
            hashL.finalize()

            #hash right trans
            if(right_tree is not None):
                hashR = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hashR.update(right_tree.__str__())
                hashR.finalize()
            else: # right transaction = None
                hashR = hashL # replicate left sibling-transaction hash

            self.hashL = hashL
            self.hashR = hashR
            self.hash = hashL + hashR
            self.left_tree = left_tree
            self.right_tree = right_tree
            self.parent = None
        else: # non-leaf node with left and right children trees
            self.hashL = left_tree.hash
            self.hashR = right_tree.hash
            self.hash = self.hashL + self.hashR
            self.left_tree = left_tree
            self.right_tree = right_tree
            self.parent = None
            left_tree.parent = self
            right_tree.parent = self

    def get_right_sibling(self):
        if self.parent.hashR == self.hash: # right most child
            return None
        return self.parent.right_tree

    def update_hashes(self,bleft_insert):
        if(isinstance(self.left_tree, Transaction)): # leaf node
            if(bleft_insert): # transaction has been inserted left => hash and replicate right
                hashL = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hashL.update(self.left_tree.__str__())
                hashL.finalize()
                self.hashL = hashL
                self.hashR = hashL
            else: # transaction has been inserted right => hash
                hashR = hashes.Hash(hashes.SHA256(), backend=default_backend())
                hashR.update(self.right_tree.__str__())
                hashR.finalize()
                self.hashR = hashR
        else: # non-leaf node
            self.hashL = self.left_tree.hash
            self.hashR = self.right_tree.hash
        
        self.hash = self.hashL + self.hashR
        
        if self.parent is None: # reached the root - recursion base case
            return

        rs = self.get_right_sibling()
        if rs is not None: # replicate right
            rs.hashL = self.hashL
            rs.hashR = self.hashR
            rs.hash = self.hash

        self.parent.update_hashes(False) # recursion step



class MerkleRoot(): # full merkle tree (singleton)
    __instance = None
    # merkleroot: MerkleTree # root of the tree
    # t: int # num of transactions
    # lvl: int # num of levels in the tree
    # lm_leaf: MerkleTree # left-most leaf with 1-2 empty children

    @staticmethod
    def getInstance():
      return MerkleRoot.__instance

    def __init__(self, trans):
        """ Virtually private constructor. """
        if MerkleRoot.__instance != None:
            raise Exception("Scrooge class is a singleton!")
        else:
            MerkleRoot.__instance = self
        self.merkleroot = MerkleTree(trans, None, None)
        self.t = 1
        self.lvl = 2
        self.lm_leaf = self.merkleroot

    def insert_transaction(self,trans):
        self.t += 1
        n = math.ceil(math.log2(self.t))
        l = math.pow(2,n)
        lvl = math.log2(l) + 1
        if(lvl == self.lvl):
            if(self.lm_leaf.left_tree is None):
                self.lm_leaf.left_tree = trans
                self.lm_leaf.update_hashes(True)
            elif(self.lm_leaf.right_tree is None):
                self.lm_leaf.right_tree = trans
                self.lm_leaf.update_hashes(False)
                if(l > self.t):
                    self.update_lm_leaf(self.lm_leaf)
        else: # expand tree
            self.expand_tree(l,lvl,trans)
            self.lvl = lvl
            self.lm_leaf.left_tree = trans
            self.lm_leaf.update_hashes(True)


    def update_lm_leaf(self, node):
        rs = node.get_right_sibling()
        if(rs is not None):
            new_lm_leaf = rs
            while(True):
                if(new_lm_leaf.left_tree is None):
                    break
                new_lm_leaf = new_lm_leaf.left_tree
            self.lm_leaf = new_lm_leaf
            return
        self.update_lm_leaf(node.parent)
    
    def expand_tree(self, leaves, lvls, trans):
        nodes = [trans]
        for i in range(1, leaves/2):
            nodes.append(None)
        tree = MerkleTree(nodes.pop(0),nodes.pop(0),None)
        self.lm_leaf = tree
        nodes.append(tree)
        root = self.expand_treeH(nodes, self.lm_leaf)
        self.merkleroot = MerkleTree(self.merkleroot, root, None)

    
    def expand_treeH(self, nodes, left_sibling):
        if(len(nodes) == 1):
            return nodes[0]
        tree = MerkleTree(nodes.pop(0), nodes.pop(0), left_sibling)
        nodes.append(tree)
        self.expand_treeH(nodes,left_sibling)



def print_pbk_key(key):

    key = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
    key = key.replace("\n", "")
    key = key.replace("-----BEGIN PUBLIC KEY-----", "")
    key = key.replace("-----END PUBLIC KEY-----", "")
    return key



def print_users_public_keys(users, log_file):
    print("###################### USERS' PUBLIC KEYS ######################")
    log_file.write("###################### USERS' PUBLIC KEYS ######################\n")
    
    for user_pbk_key in users:
        user = users[user_pbk_key]
        #DONE: print publick key
        log_file.write("User: " + str(user.ID) + "\nAmount: " + str(len(user.coins)) + "\nPublicKey: " +  print_pbk_key(user_pbk_key)+"\n")
        print("User: " + str(user.ID) + "\nAmount: " + str(len(user.coins)) + "\nPublickKey: " +  print_pbk_key(user_pbk_key))
        log_file.write("****************************************************************\n")
        log_file.flush()

    for i in range(0,3):
        log_file.write("################### END OF USERS PUBLIC KEYS ###################\n")
        print("################### END OF USERS PUBLIC KEYS ###################")
    log_file.write("################################################################\n")
    print("################################################################")  
    log_file.flush()



def print_block_under_construction(buffer, log_file):
    # DONE: Scoorge should print the block under construction for each new transaction added (include the transaction details).
    b_ID = "b" + str("{:010d}".format(Block.blockID))
    for i in range(0,3):
        print("######### BLOCK UNDER CONSTRUCTION: BLOCK " + b_ID + " ##########")
        log_file.write("######### BLOCK UNDER CONSTRUCTION: BLOCK " + b_ID + " ##########\n")
    log_file.flush()
    
    for trans in buffer:
        print(trans.get_trans_details())
        print("****************************************************************")
        log_file.write(trans.get_trans_details())
        log_file.write("****************************************************************\n")
        log_file.flush()
    
    log_file.write("################################################################\n")
    print("################################################################")
    log_file.flush()
    


def print_block_chain(final_hash_ptr, log_file):

    for i in range(0,3):
        print("########################## BLOCKCHAIN ##########################")
        log_file.write("########################## BLOCKCHAIN ##########################\n")
    log_file.flush()

    current_block = final_hash_ptr.trans
    
    while True:
        b_ID = current_block.ID
        b_transactions = current_block.transactions
        b_hash = current_block.hash.hex()
        if  current_block.hash_ptr_prev_block == None:
            b_hash_ptr = "None"
        else:
            b_hash_ptr = current_block.hash_ptr_prev_block.get_hash_ptr_details(block=True)

        print("####################### BLOCK " + b_ID + " #######################")
        log_file.write("####################### BLOCK " + b_ID + " #######################\n")
        print("BlockID: " + b_ID)
        log_file.write("BlockID: " + b_ID + '\n')
        print("BlockHash: " + b_hash)
        log_file.write("BlockHash: " + b_hash + '\n')
        print("BlockHashPointer: " + b_hash_ptr)
        log_file.write("BlockHashPointer: " + b_hash_ptr + '\n')
        print("BlockTransactions: *********************************************")
        log_file.write("BlockTransactions: *********************************************\n")
        print("****************************************************************")
        log_file.write("****************************************************************\n")
        log_file.flush()

        for trans in b_transactions:
            print(trans.get_trans_details())
            print("****************************************************************")
            log_file.write(trans.get_trans_details())
            log_file.write("****************************************************************\n")
            log_file.flush()
        try:
            current_block = current_block.hash_ptr_prev_block.trans
        except:
            break

    for i in range(0,3):
        print("####################### END OF BLOCKCHAIN ######################")
        log_file.write("####################### END OF BLOCKCHAIN ######################\n")
    log_file.write("################################################################\n")
    print("################################################################")
    log_file.flush()



def print_invalid_transaction(double_spending_attack, signature_verification_failed, coin_creation_attack, coin_doesnot_belong_sender, trans, log_file):

    if double_spending_attack:
        print("################# ALERT!! Invalid Transaction!! ################")
        print("################ ALERT!! Double Spending Attack!! ##############")
        log_file.write("################# ALERT!! Invalid Transaction!! ################\n")
        log_file.write("################ ALERT!! Double Spending Attack!! ##############\n")
        log_file.write(trans.get_trans_details())
        print(trans.get_trans_details())
        print("################################################################")
        log_file.write("################################################################\n")
        log_file.flush()
    elif signature_verification_failed:
        print("################## ALERT!! Invalid Transaction!! ################")
        print("############ ALERT!! Signature Verification Failed!! ############")
        log_file.write("################# ALERT!! Invalid Transaction!! #################\n")
        log_file.write("############ ALERT!! Signature Verification Failed!! ############\n")
        log_file.write(trans.get_trans_details())
        print(trans.get_trans_details())
        print("################################################################")
        log_file.write("################################################################\n")
        log_file.flush()
    elif coin_creation_attack:
        print("################# ALERT!! Invalid Transaction!! #################")
        print("########### Only Scrooge is Allowed to Create Coins!! ###########")
        log_file.write("################# ALERT!! Invalid Transaction!! #################\n")
        log_file.write("########### Only Scrooge is Allowed to Create Coins!! ###########\n")
        log_file.write(trans.get_trans_details())
        print(trans.get_trans_details())
        print("################################################################")
        log_file.write("################################################################\n")
        log_file.write(trans.get_trans_details())
    elif coin_doesnot_belong_sender:
        print("################# ALERT!! Invalid Transaction!! ################")
        print("############ ALERT!! Coin Does Not Belong to Sender!! ##########")
        log_file.write("################# ALERT!! Invalid Transaction!! ################\n")
        log_file.write("############ ALERT!! Coin Does Not Belong to Sender!! ##########\n")
        log_file.write(trans.get_trans_details())
        print(trans.get_trans_details())
        print("################################################################")
        log_file.write("################################################################\n")
        log_file.flush()



def initialize_system(log_file):

    #INITIALIZATION:
    users = {}

    #creating 100 users
    for i in range(0, 100):
        user = User()
        users[user.public_key] = user

    scrooge = Scrooge()
    scrooge.users = users 
    
    #Scrooge creates 1K coins, and pays 10 per user 
    print("Scrooge creating 1000 coins ...")   
    for i in range(0, 1000):
        scrooge.create_coin(None)
    
    print("Scrooge paying 10 coins per user ...")   
    j=0
    trans_counter = 0
    for user_pbk_key in scrooge.users:
        if trans_counter%10==0:
            j=0
        scrooge.create_transaction(10, scrooge.coins[j:j+10], user_pbk_key, 0, None)
        j+=10
        trans_counter+=1
    
    #print users' public keys and amounts     
    print_users_public_keys(scrooge.users, log_file)

    #print initial blockchain
    print_block_chain(scrooge.finalHashPtr, log_file)

    return scrooge



def simulation():

    #File Writer
    f = open('simulation_log.txt', 'w')

    scrooge = initialize_system(f)

    for i in range(0,3):
        print("###################### STARTING SIMULATION #####################")
        f.write("###################### STARTING SIMULATION #####################\n")
    print("################################################################")
    f.write("################################################################\n")
    f.flush()

    #simulation
    pbk_users = list(scrooge.users.keys())
    print("1. Press 't' to Generate a New RANDOM Transaction.")
    print("2. Press 'd' to Generate a Double Spending Attack.")
    print("3. Press Space to Exit")
    
    while(True):    
        # DONE: A simulation of the network, with multiple users and the randomized process of making a transaction
        in_char = msvcrt.getch()

        if in_char == b't':
            print("Generating a Random Transaction...")
            f.write("Generating a Random Transaction...\n")
            f.flush()

            a = random.randint(0, 99)
            b = random.randint(0, 99)
            user_a_pbk_key = pbk_users[a]
            user_b_pbk_key = pbk_users[b]
            user_a = scrooge.users[user_a_pbk_key]

            while len(user_a.coins) == 0:
                a = random.randint(0, 99)
                b = random.randint(0, 99)
                user_a_pbk_key = pbk_users[a]
                user_b_pbk_key = pbk_users[b]
                user_a = scrooge.users[user_a_pbk_key]
            
            amount = random.randint(1, len(user_a.coins))
            coins = user_a.coins[0:amount]
            user_a.create_transaction(amount, coins, user_b_pbk_key, 0, f)

            print("1. Press 't' to Generate a New RANDOM Transaction.")
            print("2. Press 'd' to Generate a Double Spending Attack.")
            print("3. Press Space to Exit")
        
        if in_char == b'd':
            print("Generating a Random Transaction...")
            f.write("Generating a Random Transaction...\n")
            f.flush()

            a = random.randint(0, 99)
            b = random.randint(0, 99)
            user_a_pbk_key = pbk_users[a]
            user_b_pbk_key = pbk_users[b]
            user_a = scrooge.users[user_a_pbk_key]

            while len(user_a.coins) == 0:
                a = random.randint(0, 99)
                b = random.randint(0, 99)
                user_a_pbk_key = pbk_users[a]
                user_b_pbk_key = pbk_users[b]
                user_a = scrooge.users[user_a_pbk_key]
            
            amount = random.randint(1, len(user_a.coins))
            coins = user_a.coins[0:amount]
            user_a.create_transaction(amount, coins, user_b_pbk_key, 0, f)
            print("Generating a Double Spending Attack...")
            f.write("Generating a Double Spending Attack...\n")
            f.flush()
            user_a.create_transaction(amount, coins, user_a_pbk_key, 0, f)

            print("1. Press 't' to Generate a New RANDOM Transaction.")
            print("2. Press 'd' to Generate a Double Spending Attack.")
            print("3. Press Space to Exit")
            
            
        #DONE: exit using space key
        if in_char == b' ':
            # DONE: Save all the printed data to a text file upon termination.
            f.close()
            print("Terminating...")
            break
    
    

def main():
    simulation()



if __name__ == "__main__":
    main()